// フレームワークと同じホスト名の正規化を通すために使う
using Microsoft.AspNetCore.Http;

// この判定が属する名前空間(他の入力検証の規則と同じ場所)
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// <c>AllowedHosts</c> の設定値が「どのホスト名でも受け付ける」状態かを判定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ純粋関数として切り出すのか。</b> 判定を <c>Program.cs</c> の
/// トップレベル文の中へ書くと、テストから呼べるのは「アプリを起動してログを覗く」形しか
/// 残らない。境界値（区切り方・空白・大文字小文字・複数指定）を固定したいので、
/// 判定だけを取り出してある。</para>
///
/// <para><b>判定は「フレームワークが任意の Host を受け付ける状態か」の 1 本</b>で、
/// <c>HostFilteringMiddleware</c> の挙動を<b>そのまま写した</b>ものにしてある
/// （既定設定の分割 → 0 件なら <c>["*"]</c> へフォールバック → ワイルドカード判定）。
/// <b>独自に丸めない</b>のが要点 ——前後の空白を落とす・空白だけを全許可扱いする といった
/// 「親切な」補正を入れると、フレームワークが実際には<b>一致させていない</b>設定
/// （<c>" ; "</c> ・ <c>"  *  "</c> ・ <c>"   "</c> は 1 件以上残るのでフォールバックせず、
/// 正規化しても綴りが一致しないため<b>すべて 400</b>＝実測）まで「全許可」と報告することになり、
/// 規則の説明とケースが食い違う。<b>この判定が拾うのは「黙って素通りする」形だけ</b>で、
/// 一致しない側は <see cref="NeverMatchingEntries"/> が別の警告として拾う ——
/// <b>「落ちるからすぐ気づける」は成り立たない</b>（下記）。
/// なお <c>HostFiltering</c> は許可リストにワイルドカード（<see cref="Wildcards"/>）が<b>1 つでも</b>含まれていれば
/// 「空でない Host はすべて受け付ける」に切り替わる。つまり
/// <c>"*;incident.example.com"</c> は「実ホスト名も足した」ように見えて
/// <b>実際には全ホスト許可のまま</b>で、これは実ホスト名を「追加」しようとしたときに
/// 自然に書いてしまう形。以前の判定は値全体が <c>"*"</c> と一致するかだけを見ていたため、
/// この綴りでは警告が出ず、運用者は「ログが出ていない＝絞れている」と読んでしまった
/// （docs/security.md がその確認手順を案内しているぶん、なお悪い）。</para>
/// </remarks>
public static class AllowedHostsPolicy
{
    /// <summary>設定値の区切り文字（ASP.NET Core が <c>AllowedHosts</c> に使うもの）。</summary>
    private const char Separator = ';';

    /// <summary>どのホスト名でも受け付ける状態を表す綴り（3 つとも同じ意味）。</summary>
    /// <remarks>
    /// <para><b><c>*</c> だけではない。</b> <c>HostFilteringMiddleware.IsTopLevelWildcard</c> は
    /// <c>*</c>（HTTP.sys）・<c>[::]</c>（Kestrel の IPv6 Any）・<c>0.0.0.0</c>（IPv4 Any）の
    /// いずれかが<b>1 つでも</b>含まれていれば、許可リスト全体を無効にして
    /// 「空でない Host はすべて受け付ける」へ切り替える。</para>
    ///
    /// <para><b>ここを <c>*</c> だけにすると、直したはずのバグがそのまま残る。</b>
    /// <c>"incident.example.test;0.0.0.0"</c> は <c>"*;incident.example.com"</c> と
    /// <b>構造がまったく同じ</b>（実ホスト名の隣にワイルドカードがある）で、
    /// <c>ASPNETCORE_URLS=http://0.0.0.0:8080</c> を写して書くと自然に生まれる。
    /// 実測でも、この綴りは別ホストを 200 で受けるのに警告が出なかった。</para>
    /// </remarks>
    private static readonly string[] Wildcards = ["*", "[::]", "0.0.0.0"];

    /// <summary>
    /// 設定値を、フレームワークとまったく同じ規則で項目へ分ける。
    /// </summary>
    /// <remarks>
    /// <b>2 つの判定が同じ分割を見ることを、構造で保証するために切り出してある。</b>
    /// 同じ式を 2 か所へ書き写すと、片方にだけトリムを足すような変更が通ってしまう
    /// （そのとき壊れ方は「全拒否が全許可に化ける」と「死んだ項目が 1 件も挙がらない」で、
    /// どちらも<b>警告が出なくなる</b>方向。CLAUDE.md §6 DRY）。
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値。</param>
    /// <returns>空の項目を落としたあとの項目（<b>トリムはしない</b>）。</returns>
    private static string[] SplitEntries(string allowedHosts) =>
        // 空の項目だけを落とし、前後の空白は<b>残す</b>（フレームワークと同じ規則）
        allowedHosts.Split(Separator, StringSplitOptions.RemoveEmptyEntries);

    /// <summary>
    /// 許可リストの 1 項目が、フレームワークから見てワイルドカードかを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>生の文字列で比べてはいけない。</b> <c>HostFilteringMiddleware</c> は各項目を
    /// <c>new HostString(entry).ToUriComponent()</c>（IDNA / NFKC の正規化）に通して<b>から</b>
    /// 3 綴りと突き合わせる。そのため全角数字の <c>０.０.０.０</c> や、日本語 IME の読点で
    /// 書いた <c>0。0。0。0</c> は正規化で <c>0.0.0.0</c> になり、
    /// <b>許可リスト全体が無効になる</b>（実測: この 2 つと、1 文字だけ全角の <c>０.0.0.0</c> も同じ）。
    /// 生の <c>Ordinal</c> 比較のままだと、そこがそのまま「警告の出ない全許可」になる ——
    /// この判定が直したはずの穴が、1 段深いところに残る形。</para>
    ///
    /// <para><b>正規化できない綴りは警告する側へ倒す（＝ belt and braces）。</b>
    /// <c>ToUriComponent()</c> は <c>"0.0.0.0\t"</c> のような値で例外を投げる。
    /// <b>実測では、いまのフレームワークは同じ正規化に失敗してリクエストごと例外になる</b>
    /// （200 でも 400 でもない。<c>HostFilteringShortCircuitTests</c> が固定）。
    /// つまり<b>今日の挙動は「素通り」ではない</b>ので、厳密にはこの判定の対象外 ——
    /// それでも <c>true</c> を返すのは、<b>この綴りをどう扱うかがフレームワーク側の
    /// 実装詳細に握られている</b>から。上流が例外をやめて「一致しない項目」として
    /// 読み飛ばすようになれば、そのときは素通りではなく静かな全拒否になるが、
    /// 逆にワイルドカードとして通す実装もありうる。判断材料が無い以上、
    /// 見逃す側ではなく鳴らす側へ倒す（§9 fail-closed）。
    /// <b>前後に空白がある綴り（<c>"0.0.0.0\t"</c> など）は <see cref="NeverMatchingEntries"/> にも
    /// 載る</b>ので、そのときは運用者が受け取る指示（空白を外せ）が両方の警告で一致する。
    /// <b>残っている境界: 途中に紛れた制御文字（<c>"0.0\t.0.0"</c>）はトリムしても変わらないので
    /// そちらには載らない。</b>この綴りでは警告 1 だけが出るが、その文面はワイルドカードの
    /// 話をするので、値とも症状（実測では毎リクエストが例外）とも噛み合わない。
    /// 綴りから「どの制御文字が IDNA を壊すか」を機械的に言い当てることはできないので、
    /// ここは<b>鳴らすことを優先し、文面の精度は捨てている</b>（黙るよりはよい）。</para>
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（<b>トリムしていない生の値</b>）。</param>
    /// <returns>フレームワークがワイルドカードとして扱うなら <c>true</c>。</returns>
    private static bool IsWildcardEntry(string entry) =>
        // 正規化できた綴りだけを 3 つのワイルドカードと突き合わせ、
        // 判断できない綴りは「絞れている」と言えないので警告する側へ倒す
        !TryNormalizeEntry(entry, out var normalized)
        || Wildcards.Contains(normalized, StringComparer.Ordinal);

    /// <summary>
    /// フレームワークと同じ正規化（IDNA / NFKC）を試み、成功したかを返す。
    /// </summary>
    /// <remarks>
    /// <b>正規化の失敗を、2 つの問いで別々に解釈するために切り出してある。</b>
    /// 「警告を出すべきか」（<see cref="IsPermissive"/>）は判断できない綴りを
    /// <b>ワイルドカード側へ倒す</b>のが正しい（鳴りすぎる＝安全側）。
    /// 一方「死んだ項目を消すと何が起きるか」
    /// （<see cref="ClassifyDeadEntryDeletion"/>）では倒してはいけない ——
    /// 実測するとフレームワークの結果は<b>項目の並び順で変わる</b>ので、
    /// ワイルドカード扱いに倒すと「消すな、消すと全許可になる」という
    /// <b>事実と逆の案内</b>になりうる。あちらは正規化できない項目が 1 つでもあれば
    /// <c>Unknown</c> を返し、断定そのものをやめる。
    /// 正規化の手順は同じなので、成否の解釈だけを呼び出し側へ持たせる。
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（トリムしていない生の値）。</param>
    /// <param name="normalized">成功したときの正規化後の綴り。</param>
    /// <returns>正規化できたなら <c>true</c>。</returns>
    private static bool TryNormalizeEntry(string entry, out string normalized)
    {
        // 正規化そのものが失敗しうるので捕まえる
        try
        {
            // HostFiltering と同じ手順でホスト名を正規化する
            normalized = new HostString(entry).ToUriComponent();
            // ここまで来たら正規化できている
            return true;
        }
        catch (ArgumentException)
        {
            // 呼び出し側が誤って使わないよう、空文字を入れておく
            normalized = string.Empty;
            // 正規化できなかったことだけを伝え、解釈は呼び出し側に任せる
            return false;
        }
    }

    /// <summary>
    /// その設定値が「実質すべてのホストを許可する」かを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>写しているのは汎用ホストの既定設定。</b> 実装はこの 2 行で、
    /// <b>この判定はこれを 1 行ずつ辿っただけ</b>のもの（他の場所へ書き写さず、ここを指すこと）:
    /// <code>
    /// var hosts = config["AllowedHosts"]?.Split(';', RemoveEmptyEntries);
    /// options.AllowedHosts = hosts?.Length > 0 ? hosts : new[] { "*" };
    /// </code>
    /// つまり<b>「空の項目は無害」なのは、空でない項目が 1 つでも残る場合だけ</b>。
    /// <c>";"</c> ・ <c>";;"</c> のように 1 件も残らない値は既定の <c>["*"]</c> へ落ちて全許可になる
    /// （手で書くより <c>AllowedHosts=${PRIMARY};${SECONDARY}</c> のテンプレート展開で生まれやすい）。
    /// <b>先にトリムしてはいけない</b> ——<c>" ; "</c> は項目が 2 件残るので既定へ落ちず、
    /// 許可リストが <c>[" ", " "]</c> になって<b>すべて拒否</b>される（実測で 400）。
    /// 丸めると、そこを「全許可」と読み違える。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>
    /// フレームワークが任意の <c>Host</c> を受け付ける状態なら <c>true</c>。
    /// 具体的には (a) 未設定、(b) 空の項目を落とすと<b>1 件も残らない</b>
    /// （<c>""</c> ・ <c>";"</c> ・ <c>";;"</c>。既定の <c>["*"]</c> へ落ちるため）、
    /// (c) ワイルドカードを 1 つでも含む、のいずれか。
    /// </returns>
    public static bool IsPermissive(string? allowedHosts)
    {
        // 未設定なら、フレームワークは分割すら行わず既定へ落ちる
        if (allowedHosts is null) return true;

        // <b>フレームワークとまったく同じ分割</b>で項目を取り出す（規則は SplitEntries が持つ）
        var entries = SplitEntries(allowedHosts);

        // 規則そのものは 1 か所（AcceptsEveryHost）に置き、ここは倒し方だけを選ぶ。
        // 警告を出すかの判定なので、判断できない綴りはワイルドカード側へ倒す
        return AcceptsEveryHost(entries);
    }

    /// <summary>
    /// その項目の並びが、どの <c>Host</c> でも受け付ける状態かを返す。
    /// </summary>
    /// <remarks>
    /// <b>フォールバックの規則を 1 か所に置くために切り出してある。</b>
    /// 「1 件も残らなければ既定の <c>["*"]</c> へ落ちる」「ワイルドカードが 1 つでもあれば
    /// 全許可へ切り替わる」という 2 つは、これを読む判定が 2 つあっても同じでなければならない。
    /// 書き写すと、フレームワーク側にもう 1 つ経路が増えたときに片方だけが直り、
    /// その差は<b>「消してよい」と案内する方向</b>（fail-open）へ倒れる。
    /// <b>1 項目の見方を差し替える引数は持たせない</b> ——
    /// <see cref="ClassifyDeadEntryDeletion"/> は正規化できない項目を先に
    /// <c>Unknown</c> で除くので、そこへ渡せる 2 つ目の判定はもう存在しない。
    /// 引数として口を開けておくと、使わない分岐が残るうえ、
    /// 次の書き手に「別の判定を渡してよい」と読ませてしまう（§6）。
    /// </remarks>
    /// <param name="entries">分割済みの項目（トリムしていない生の値）。</param>
    /// <returns>どの <c>Host</c> でも受け付ける状態なら <c>true</c>。</returns>
    private static bool AcceptsEveryHost(string[] entries) =>
        // 1 件も残らないなら既定の ["*"] へ落ちる／1 つでもワイルドカードがあれば全許可
        entries.Length == 0 || entries.Any(IsWildcardEntry);

    /// <summary>
    /// 書かれているのに<b>どの <c>Host</c> とも一致しえない</b>項目を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ <see cref="IsPermissive"/> と別に要るのか。</b> あちらが拾うのは
    /// 「絞ったつもりで全部通る」形だけで、その裏返しである
    /// <b>「並べたつもりで一部が通らない」形は素通りする</b>。
    /// いちばん踏みやすいのが<b>区切りのうしろに空白を入れた複数指定</b>で、
    /// これは一覧を書くときの自然な書き方:
    /// <code>AllowedHosts=incident.example.test; www.example.test</code>
    /// フレームワークは項目をトリムしないので、2 件目は <c>" www.example.test"</c> のまま残り
    /// <b>どの Host とも一致しない</b>。実測では 1 件目が 200、2 件目が<b>400</b>になる ——
    /// つまり<b>サイト全体は生きたまま、特定のホスト名だけが静かに落ちる</b>。</para>
    ///
    /// <para><b>「全拒否ならすぐ気づく」は、だから成り立たない。</b>
    /// 気づけるのは全ホストが一斉に落ちる場合（<c>"   "</c> 等）だけで、上の形は
    /// 主たるホスト名が生きているぶん<b>監視にもヘルスチェックにも出ない</b>。
    /// しかも <see cref="IsPermissive"/> は正しく <c>false</c> を返すので、
    /// <c>docs/security.md</c> が運用者に指示している「警告ログが出ていないことの確認」が
    /// <b>そのまま誤った安心</b>になる —— これは <c>"*;incident.example.test"</c> を
    /// 取りこぼしていた頃とまったく同じ形の穴で、向きだけが逆。</para>
    ///
    /// <para><b>判定は「トリムすると変わるか」だけ。</b> リクエストの <c>Host</c> ヘッダーは
    /// 解析された時点で前後に空白を持たないので、前後に空白のある項目は
    /// <b>綴りに関係なく</b>一致しえない（<c>" * "</c> のようにワイルドカードのつもりの綴りも
    /// ここに落ちる）。内側の空白（<c>"a b.test"</c>）は別の話なので見ない ——
    /// そもそもホスト名として不正で、ここで扱うと「何を保証しているか」がぼやける。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>一致しえない項目（無ければ空）。運用者へそのまま見せる想定。</returns>
    public static IReadOnlyList<string> NeverMatchingEntries(string? allowedHosts)
    {
        // 未設定なら項目そのものが無い
        if (allowedHosts is null) return [];

        // IsPermissive とまったく同じ分割を使う（同じ関数を呼ぶので、片方だけ規則が動かない）
        return SplitEntries(allowedHosts)
            // 一致しえない項目だけを残す（規則は IsNeverMatchingEntry が持つ）
            .Where(IsNeverMatchingEntry)
            // 警告へそのまま載せるので、書かれた順のまま配列にする
            .ToArray();
    }

    /// <summary>
    /// その項目 1 件が、どの <c>Host</c> とも一致しえないかを返す。
    /// </summary>
    /// <remarks>
    /// <b>規則を 1 か所へ置く。</b> 「死んでいる項目」と「生きている項目」を別々の式で
    /// 書くと、条件を広げたとき（<see cref="IsWildcardEntry"/> の docstring が
    /// 「残っている境界」として挙げている、項目の途中に紛れた制御文字への対応など）に
    /// 片方だけが取り残される。そのとき <see cref="ClassifyDeadEntryDeletion"/> は
    /// 「生きた項目が残る」と答えるのに実際には 0 件になり、
    /// <b>削除してよいと案内した結果が全ホスト許可</b>になる。
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（トリムしていない生の値）。</param>
    /// <returns>どの <c>Host</c> とも一致しえないなら <c>true</c>。</returns>
    private static bool IsNeverMatchingEntry(string entry) =>
        // 前後の空白を落とすと別物になる項目は、Host ヘッダーと綴りが一致しえない
        !string.Equals(entry, entry.Trim(), StringComparison.Ordinal);

    /// <summary>
    /// 一致しえない項目を<b>消すだけ</b>にしたら何が起きるかの分類。
    /// </summary>
    public enum DeadEntryDeletionOutcome
    {
        /// <summary>消す対象が無い（一致しえない項目が 1 件も無い）。</summary>
        NothingToDelete,

        /// <summary>消しても、残る一覧がどの <c>Host</c> でも受け付ける状態にはならない。</summary>
        Safe,

        /// <summary>消すと、残る一覧がどの <c>Host</c> でも受け付ける状態になる。</summary>
        WouldAllowEveryHost,

        /// <summary>判断できない（残る項目に正規化できない綴りがある）。</summary>
        Unknown,
    }

    /// <summary>
    /// 一致しえない項目を消したときに何が起きるかを分類する。
    /// </summary>
    /// <remarks>
    /// <para><b>直し方の案内を条件付きにするために要る。</b>
    /// <see cref="NeverMatchingEntries"/> が挙げた項目を消したあと、残る一覧が
    /// <b>どの <c>Host</c> でも受け付ける</b>状態になるなら、消すのは直し方ではない
    /// ——400 が止まるので直ったように見えて、実際には issue #64（Host ヘッダ偽装）へ移る。</para>
    ///
    /// <para><b>全許可へ化ける経路は 2 つあり、「生きた項目が残るか」では判別できない。</b>
    /// (a) 項目が 0 件になって既定の <c>["*"]</c> へ落ちる（<c>"   "</c> ・ <c>" ; "</c>）、
    /// (b) <b>残った項目自体がワイルドカード</b>（<c>"*; "</c> ・
    /// <c>"incident.example.com;0.0.0.0; "</c>。後者は <c>ASPNETCORE_URLS</c> を写すと自然に生まれる）。
    /// (b) はどちらも生きた項目が残るので、件数だけを見る判定では取りこぼす（実測）。</para>
    ///
    /// <para><b>bool ではなく 3 値にしてあるのは、答えられない場合があるから。</b>
    /// 残る項目に正規化できない綴りが混じっていると、フレームワークの結果は
    /// <b>並び順で変わる</b> ——<c>TryProcessHosts</c> は宣言順に正規化し、最初の
    /// ワイルドカードで打ち切るため、正規化できない項目が<b>前</b>にあれば例外
    /// （どの Host も受け付けない）、<b>後ろ</b>なら評価されず全許可になる。
    /// 実測: <c>"0.0\t.0.0;0.0.0.0"</c> は例外、<c>"0.0.0.0;0.0\t.0.0"</c> は 200。
    /// この並び順の意味づけを写し取ると、上流の実装詳細に判定が縛られる。
    /// どちらにせよ設定は壊れている（露出ではなく障害）ので、
    /// <b>断定せず「判断できない」と答え、案内も断定しない</b>のが正しい。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>消したときに何が起きるかの分類。</returns>
    public static DeadEntryDeletionOutcome ClassifyDeadEntryDeletion(string? allowedHosts)
    {
        // 未設定なら消す対象そのものが無い
        if (allowedHosts is null) return DeadEntryDeletionOutcome.NothingToDelete;

        // そもそも一致しえない項目が無ければ、消す話にならない
        if (NeverMatchingEntries(allowedHosts).Count == 0) return DeadEntryDeletionOutcome.NothingToDelete;

        // 死んだ項目を取り除いたあとに残る項目を取り出す
        var survivors = SplitEntries(allowedHosts)
            .Where(entry => !IsNeverMatchingEntry(entry))
            .ToArray();

        // 残る項目に正規化できない綴りがあれば、結果が並び順で変わるので断定しない
        if (survivors.Any(entry => !TryNormalizeEntry(entry, out _)))
        {
            // 判断できないことを、そのまま呼び出し側へ伝える
            return DeadEntryDeletionOutcome.Unknown;
        }

        // ここまで来れば全項目が正規化できる。IsWildcardEntry が「判断できない綴りを
        // ワイルドカード側へ倒す」のは正規化に失敗したときだけなので、上のガードを
        // 通ったあとは倒し方の違いが消え、そのまま使ってよい
        // （倒し方だけが違う 2 つ目の判定を別に持つと、使われない分岐が残る。§6）
        return AcceptsEveryHost(survivors)
            // 消すと全ホストを受け付ける状態になる
            ? DeadEntryDeletionOutcome.WouldAllowEveryHost
            // 消しても全許可にはならない＝消してよい
            : DeadEntryDeletionOutcome.Safe;
    }
}
