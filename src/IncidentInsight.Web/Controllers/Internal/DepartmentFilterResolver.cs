// Incident エンティティ(部署一覧の唯一の真実の源)を使う
using IncidentInsight.Web.Models;
// 絞り込み入力の「空かどうか」の唯一の真実の源(SearchFilter)を使う
using IncidentInsight.Web.Models.Validation;
// EF Core 拡張(OrderBy / FirstOrDefaultAsync)
using Microsoft.EntityFrameworkCore;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// 発生部署の絞り込み値を「実際に絞り込みへ使う値」と「ドロップダウンに並べる選択肢」へ
/// 解決する共有処理。<c>/Incidents</c>(一覧)と <c>/Analytics</c>(集計 JSON)が使う。
/// </summary>
/// <remarks>
/// <para><b>なぜ 2 画面で共有するのか(issue #204 課題 4)。</b> 以前この処理は
/// <c>IncidentsController</c> の private メソッドで、<c>/Analytics</c> は
/// <c>SearchFilter.HasValue</c> を通した値をそのまま <c>Where</c> へ渡していた。
/// そのため<b>同じ URL パラメータで答えが食い違って</b>いた:
/// <c>/Incidents?department=旧ICU</c> は絞り込みを外して注意書きを出すのに、
/// <c>/Analytics/BySeverity?department=旧ICU</c> はそのまま絞り込んで<b>全 0 のグラフ</b>を
/// 注意書き無しで返す ——「この部署にはインシデントが 0 件だった」と読めてしまうが、
/// 実際は「そんな部署は無い」。医療インシデントの集計画面で 0 件と存在しないを
/// 区別できないのは誤読が重い。</para>
///
/// <para><b>判断の規則そのもの</b>(どの画面が「補完」でどれが「採用しない」か、その理由)は
/// <see cref="SearchFilter"/> の解説に集約してある。ここはそのうち
/// 「実データにあれば補完、無ければ採用しない」を実装する。</para>
///
/// <para><b>選択肢を使わない画面でも同じ関数を通す。</b> <c>/Analytics</c> には部署の
/// ドロップダウンが無いので <c>Options</c> は使われないが、値と選択肢を別々に決められる形に
/// すると、その画面が後からドロップダウンを持ったときに 2 つが別々に決まる余地が戻る
/// (issue #192 が塞いだ形そのもの)。許可リストの複製 1 回はその保険の対価として払う。</para>
///
/// <para><b>実在確認に使うクエリは呼び出し側が渡す。</b> 「どこまでを実データとみなすか」は
/// 画面の見せてよい範囲の話で、この関数からは決められない。呼び出し側は
/// <b>その画面が一覧で見せるのと同じスコープ</b>を掛けた <see cref="Incident"/> のクエリを渡すこと
/// ——現在はどちらの画面も <c>ScopedByUser</c> を通している(<c>/Analytics</c> は
/// Admin / RiskManager 限定なので実質は全件だが、ポリシーが広がったときに
/// 自動で安全側へ倒れるよう同じ形にしてある。§9 fail-safe)。</para>
/// </remarks>
internal static class DepartmentFilterResolver
{
    /// <summary>
    /// 発生部署の絞り込み入力について、<b>実際に絞り込みへ使う値</b>と
    /// <b>ドロップダウンに並べる選択肢</b>を同時に決める。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ 2 つを一緒に返すのか。</b> この 2 つは<b>必ず整合していなければならない</b>。
    /// 絞り込みに使った値が選択肢に無いと、ブラウザは <c>&lt;select&gt;</c> を「部署（全て）」の位置に置く。
    /// 絞り込みは効いたままなので画面と実状態が食い違い、利用者がそのフォームを再送信した瞬間に
    /// <c>department=""</c> が送られて<b>絞り込みが無言で解除される</b>(issue #192 の再現手順)。
    /// 別々の関数にすると片方だけ直したときにこの食い違いが戻るので、1 か所で決めて一緒に返す。</para>
    ///
    /// <para><b>判断の規則そのもの</b>(3 画面のどれが「補完」でどれが「採用しない」か、その理由)は
    /// <see cref="SearchFilter"/> の解説に集約してある。ここはそのうち
    /// 「実データにあれば補完、無ければ採用しない」を実装する
    /// (<c>/Incidents</c> の発生部署と <c>/Analytics</c> の <c>?department=</c> がこれを採る)。</para>
    ///
    /// <para><b>実在確認に部署スコープを掛ける理由。</b> 存在するかどうかの答えは
    /// 「その部署名の選択肢が出るか」「注意書きが出るか」という形で画面に現れる。
    /// スコープを外すと、Staff が <c>?department=...</c> を総当たりして
    /// <b>他部署にインシデントがあるかどうかを推測できる</b>(§9 最小公開)。
    /// 呼び出し側がその画面の一覧本体と同じ <c>ScopedByUser</c> を通したクエリを
    /// <paramref name="candidates"/> へ渡しておけば、見える範囲の外は
    /// 「存在しない」と等しく扱われる。</para>
    ///
    /// <para><b>綴り違いをアプリ側で畳まない(実測に基づく判断)。</b> 許可リストの判定を
    /// 大文字小文字や前後空白を無視する比較にすると、<b>既定プロバイダで絞り込みが壊れる</b>。
    /// Staff の部署クレームは自由記述で <c>EnforceKnownDepartment</c> の対象外なので、
    /// <c>Department</c> が <c>"icu"</c> の行は実在しうる。アプリ側で <c>"ICU"</c> へ畳むと、
    /// 大文字小文字を区別する SQLite(既定)/ PostgreSQL では
    /// <c>Where(Department == "ICU")</c> が<b>その行に一致せず 0 件になる</b>——
    /// 絞り込み無しなら見えている行が、絞り込むと消える。
    /// <b>どの行が一致するかを決めてよいのは DB だけ</b>なので、判定は DB へ委ね、
    /// アプリ側の比較は序数(完全一致)に統一する。</para>
    ///
    /// <para><b>この判断で「配備先による違い」は狭まらず、形が変わる(意図的)。</b>
    /// 許可リストと大文字小文字だけが違う値(<c>?department=icu</c>、実データは <c>"ICU"</c>)は、
    /// 大文字小文字を区別する SQLite / PostgreSQL では<b>絞り込みを適用せず全件</b>を返し、
    /// 区別しない SQL Server では<b>ICU の行だけ</b>を返す。この変更の前は前者が
    /// 「0 件」だったので、違いは「0 件 対 N 件」から「全件 対 N 件」へ<b>広がっている</b>。
    /// それでもこちらを採るのは、0 件は<b>絞り込みが効いた結果だと誤読される</b>のに対し、
    /// 全件は注意書き付きで「適用しなかった」と明示されるため
    /// (<c>/Incidents</c> は
    /// <see cref="Models.ViewModels.IncidentListViewModel.DepartmentFilterIgnored"/>、
    /// <c>/Analytics</c> は JSON の <c>departmentFilterIgnored</c>)。
    /// 返る行はどちらも部署スコープの中なので、見せてよい範囲は変わらない。
    /// <b>照合順序をまたいで同じ結果にすることはアプリ側からはできない</b>(§10 の限界)ので、
    /// 誤読しにくい側へ倒している。</para>
    ///
    /// <para><b>その代わりに残す不都合(意図的)。</b> 照合順序が大文字小文字を区別しない
    /// 配備先(SQL Server の <c>Japanese_CI_AS</c> 等)で、実データに <c>"icu"</c> と
    /// <c>"ICU"</c> の両方がある場合、選択肢に見た目のよく似た 2 項目が並ぶことがある。
    /// ただし<b>どちらを選んでも同じ行が出るだけ</b>で、絞り込みは正しく効き、
    /// 再送信しても解除されない(この関数が守る不変条件は保たれる)。
    /// 見た目の冗長さと「既定プロバイダで行に到達できない」を秤にかけて、前者を採っている。
    /// 綴りの揺れを本気で無くすなら、畳むべき場所はここではなく
    /// <b>保存する側</b>(Staff のクレームを許可リストへ正規化する)で、それは別の判断
    /// (issue #196 と同じ「保存される値」の話)。</para>
    ///
    /// <para><b>問い合わせは許可リストを外れたときだけ走る。</b> 通常の操作では値が
    /// <see cref="Incident.Departments"/> に載っているため、追加のクエリは発生しない。
    /// 走る場合も <c>Incident(Department, IncidentType)</c> インデックスに乗る問い合わせ 1 本で済む(§8)。
    /// 返すのは真偽値ではなく<b>保存されている綴りそのもの</b>(先頭 1 件の射影)である点が要で、
    /// 下の照合順序の項がその理由。<c>Any()</c> へ「戻す」と、コメントは残ったまま
    /// 照合順序のずれが黙って復活する。</para>
    /// </remarks>
    /// <param name="candidates">
    /// 実在確認に使うインシデントのクエリ。<b>その画面が一覧で見せるのと同じスコープ</b>を
    /// 掛けたものを渡すこと(理由は上の「実在確認に部署スコープを掛ける理由」)。
    /// </param>
    /// <param name="department">クエリ文字列から届いた発生部署の絞り込み値(未指定なら <c>null</c>)。</param>
    /// <returns>採用した絞り込み値(採用しないなら <c>null</c>)と、ドロップダウンの選択肢。</returns>
    public static async Task<DepartmentFilterSelection> ResolveAsync(
        IQueryable<Incident> candidates, string? department)
    {
        // 選択肢の土台は常に Incident.Departments(部署一覧の唯一の真実の源)。
        // 補完する場合に先頭へ差し込むので、書き換えられるリストとして複製しておく
        var options = Incident.Departments.ToList();

        // 空・空白のみは「絞り込み無し」。判定は SearchFilter.HasValue に集約してある
        if (!SearchFilter.HasValue(department))
            return new DepartmentFilterSelection(null, options, Ignored: false);

        // 現在の許可リストに載っている値は、そのまま採用してよい(選択肢にも既に並んでいる)。
        // 比較は序数(完全一致)で行う。ここを大文字小文字を無視する比較にしてはいけない
        // —— 下の「綴り違いをアプリ側で畳まない」の項を参照
        if (options.Contains(department))
            return new DepartmentFilterSelection(department, options, Ignored: false);

        // ここから先は「現在の許可リストに無い値」。過去の部署名なのか、打ち間違い・改ざんなのかを
        // 実データで見分ける。判定は見えている範囲(部署スコープ)の中だけで行う。
        //
        // 「あるか」ではなく「DB に入っている綴りそのもの」を取り出すのが要点。上の
        // options.Contains は C# の序数比較(大文字小文字・末尾空白を区別する)なのに、
        // ここの == は DB の照合順序に従うため、両者の判定が食い違う配備先がある。
        // SQL Server の既定(Japanese_CI_AS など)は大文字小文字を区別せず末尾空白も無視するので、
        // ?department=icu は「許可リストに無い(序数)」かつ「実データにある(照合順序)」となり、
        // 利用者の綴りをそのまま補完すると本物の "ICU" の上に偽の "icu" が並ぶ。
        // SQLite / PostgreSQL は区別するので同じ URL でも挙動が変わる —— テストの InMemory は
        // 序数比較なので、全件緑のまま SQL Server 配備でだけ壊れる形になる(§10)。
        // DB 側の綴りを持ち帰れば、どちらの経路を通っても選択肢に並ぶのは実在する値だけになる
        var storedDepartment = await candidates
            // その部署のインシデントに絞る(照合順序による一致は DB の判断に委ねる)
            .Where(i => i.Department == department)
            // 並びを固定してから先頭を取る。照合順序が大文字小文字を区別しない配備先では
            // "ICU" と "icu" が同時に一致しうる(Staff の部署クレームは自由記述で、
            // EnforceKnownDepartment は Staff を対象外にしているため綴り違いが実在しうる)。
            // 並びを決めずに先頭を取ると同じ URL でもリクエストごとに違う綴りが返り、
            // 選択肢の増減もページャの URL も揺れる。DB は同値行の並び順を保証しないので、
            // 一覧のページングが Id のタイブレーカーを付けているのと同じ理由で並びを固定する。
            // キーが Id だけなのは、上の Where を通った行は Department が(DB 自身の
            // 照合順序で)すべて同値だから —— Department を第 1 キーに足しても必ずタイになり、
            // 結果は変わらないまま SQL にソート列が増えるだけ。
            // なお Id だけにしても整列そのものは消えない: Incident(Department, IncidentType)
            // インデックスは Department の中を IncidentType 順に並べるので、Id 順に読むには
            // その部署の行を並べ替える必要がある。決定性のために整列 1 回を払う判断で、
            // 「seek だけで済む」わけではない(この問い合わせは許可リストを外れた値の
            //  ときだけ走るので、その頻度でこの費用は許容している)
            .OrderBy(i => i.Id)
            // 保存されている綴りを 1 件だけ取り出す
            .Select(i => i.Department)
            .FirstOrDefaultAsync();

        // 実データに無いなら採用しない。絞り込みも掛けず、画面へも値を返さない。
        // こうすると「絞り込み無し・バッジ非表示・select は全て」の三者が揃う(/AuditLogs と同じ扱い)。
        //
        // 判定を null だけでなく SearchFilter.HasValue にしてあるのは、下の補完が
        // 空値を足さない(EnsureAppliedValueIsSelectable の門番)ためで、空白のみの綴りを
        // ここで採用すると「絞り込みは効いているのに一致する <option> が無い」状態になる
        // ——この関数が守る不変条件(絞り込みに使った値は必ず選択肢にある)がそこだけ破れ、
        // 再送信で絞り込みが黙って解除される(issue #192 の症状)。あわせて
        // SearchFilter.HasValue(Model.Department) が false になるので、0 件のときに
        // 「絞り込み条件に一致しません」ではなく新規導入時向けの空状態が出る。
        // 姉妹メソッドの IncidentsController.ResolveDepartmentSaveSelection も同じ形の門番を持っており、
        // 2 つの解決メソッドが同じ形であること自体が規則(issue #202)。
        //
        // 到達するのは照合順序しだい。department は手前で HasValue を通っているので
        // 非空白が 1 文字はあり、序数比較なら空白のみの行には一致しない
        // (テストの InMemory も序数比較なのでこの枝には入らない)。一方 string.IsNullOrWhiteSpace は
        // 幅ゼロ空白(U+200B)等を「空白」と見なさないため、それを無視可能な文字として扱う
        // 照合順序では成立しうる。原理的に閉じていないので fail-closed 側へ倒す
        if (!SearchFilter.HasValue(storedDepartment))
            return new DepartmentFilterSelection(null, options, Ignored: true);

        // 実データにある＝許可リストから外れた過去の部署名。選択肢へ補完して絞り込みを維持する。
        // 「既にあれば足さない・無ければ先頭へ」の手順は /PreventiveMeasures と共通なので
        // 共有ヘルパに寄せてある(照合順序が大文字小文字を区別しない配備先では、DB が
        // 許可リストどおりの綴りを返してくることがある。その場合は足さないのが正しい)
        IncidentControllerHelpers.EnsureAppliedValueIsSelectable(options, storedDepartment);
        // 以降は利用者の入力ではなく DB 側の綴りを使う。これで
        // 「絞り込みに使った値は必ず選択肢にある」が照合順序によらず成り立つ
        return new DepartmentFilterSelection(storedDepartment, options, Ignored: false);
    }

    /// <summary>
    /// <see cref="ResolveAsync"/> の結果。
    /// 「実際に絞り込みへ使う値」と「ドロップダウンに並べる選択肢」を組にして運ぶ。
    /// </summary>
    /// <remarks>
    /// 2 つを 1 つの型にまとめてあるのは、片方だけを受け取って使う書き方をできなくするため。
    /// タプルではなく名前付きの型にしているのは、呼び出し側で <c>Item1</c> / <c>Item2</c> の
    /// 取り違えが起きないようにするのと、この解説の置き場所を作るため。
    /// </remarks>
    /// <param name="Effective">
    /// 絞り込みに使う発生部署名。採用しなかった場合(空入力・実データに無い値)は <c>null</c>。
    /// ViewModel へもこの値を載せる——採用しなかった値を画面へ返すと、絞り込みは効いていないのに
    /// 「絞り込み中」バッジが出る食い違いになるため。
    /// </param>
    /// <param name="Options">
    /// 発生部署ドロップダウンに並べる選択肢。通常は <see cref="Incident.Departments"/> そのままで、
    /// 許可リストから外れた過去の部署名で絞り込んでいるときだけ、その値が先頭に補完されている。
    /// </param>
    /// <param name="Ignored">
    /// <b>値を受け取ったのに採用しなかった</b>とき <c>true</c>。画面の注意書きの出し分けに使う。
    /// <para><see cref="Effective"/> が <c>null</c> になる理由は 2 つあり
    /// (「そもそも入力が無かった」と「入力はあったが実データに無かった」)、
    /// <b>注意書きを出してよいのは後者だけ</b>。前者でも出すと、絞り込みを使っていない
    /// 普通の一覧表示で警告が出続け、利用者は読まなくなる。
    /// この区別は <see cref="ResolveAsync"/> の中にしかないので、
    /// 呼び出し側で <c>SearchFilter.HasValue</c> を引き直さずここで受け取る
    /// ——引き直すと、解決側の「入力なし」の規則を変えたときに片方だけ古くなる。</para>
    /// </param>
    public readonly record struct DepartmentFilterSelection(string? Effective, List<string> Options, bool Ignored);
}
