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
    private static bool IsWildcardEntry(string entry)
    {
        // フレームワークと同じ正規化を通した綴りを入れる
        string normalized;

        // 正規化そのものが失敗しうるので捕まえる
        try
        {
            // HostFiltering と同じ手順でホスト名を正規化する
            normalized = new HostString(entry).ToUriComponent();
        }
        catch (ArgumentException)
        {
            // 判断できない綴りは「絞れている」と言えないので、警告する側へ倒す
            return true;
        }

        // 正規化後の綴りが 3 つのワイルドカードのいずれかかを見る
        return Wildcards.Contains(normalized, StringComparer.Ordinal);
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

        // <b>1 件も残らないなら全許可。</b> 空文字や ";" ・ ";;" がここに落ちる
        if (entries.Length == 0) return true;

        // 1 つでもワイルドカードがあれば、その時点で全ホスト許可になる
        return entries.Any(IsWildcardEntry);
    }

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
    /// 片方だけが取り残される。そのとき <see cref="DeletingDeadEntriesWouldAllowEveryHost"/> は
    /// 「生きた項目が残る」と答えるのに実際には 0 件になり、
    /// <b>削除してよいと案内した結果が全ホスト許可</b>になる。
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（トリムしていない生の値）。</param>
    /// <returns>どの <c>Host</c> とも一致しえないなら <c>true</c>。</returns>
    private static bool IsNeverMatchingEntry(string entry) =>
        // 前後の空白を落とすと別物になる項目は、Host ヘッダーと綴りが一致しえない
        !string.Equals(entry, entry.Trim(), StringComparison.Ordinal);

    /// <summary>
    /// 一致しえない項目を<b>消すだけ</b>にすると、全ホスト許可へ化けるかを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>直し方の案内を条件付きにするために要る。</b>
    /// <see cref="NeverMatchingEntries"/> が挙げた項目を消すと項目数が減り、
    /// <b>0 件になった場合だけ</b>フレームワークが既定の <c>["*"]</c> を入れて全許可になる
    /// （規則は <see cref="IsPermissive"/> の docstring が正本）。
    /// 400 が止まるので直ったように見えるが、実際には issue #64（Host ヘッダ偽装）へ移る。</para>
    ///
    /// <para><b>逆に、生きた項目が 1 つでも残るなら「消す」が正しい直し方。</b>
    /// たとえば <c>AllowedHosts=incident.example.com; ${SECONDARY}</c> で
    /// <c>SECONDARY</c> が未定義だと値は <c>"incident.example.com; "</c> になり、
    /// 死んだ項目 <c>" "</c> には<b>書き換える先の実ホスト名が存在しない</b> ——
    /// 末尾の <c>"; "</c> を消すのが唯一の直し方で、生きた項目が残るので全許可にはならない。
    /// 案内を無条件に「消すな」とすると、この形で運用者が直しようを失う。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>消すと 1 件も残らない（＝全許可へ化ける）なら <c>true</c>。</returns>
    public static bool DeletingDeadEntriesWouldAllowEveryHost(string? allowedHosts)
    {
        // 未設定なら消す対象そのものが無い
        if (allowedHosts is null) return false;

        // そもそも一致しえない項目が無ければ、消す話にならない
        if (NeverMatchingEntries(allowedHosts).Count == 0) return false;

        // 死んだ項目を取り除いた「消したあとの設定値」を組み立てる
        var afterDeletion = string.Join(
            Separator,
            SplitEntries(allowedHosts).Where(entry => !IsNeverMatchingEntry(entry)));

        // <b>その結果を同じ判定へ通す。</b> 「生きた項目が 1 件でも残るか」で見てはいけない
        // ——残った 1 件がワイルドカードなら、0 件にならなくても全許可のままだから。
        // 実測: "*; " と "incident.example.test;0.0.0.0; " は死んだ項目を消しても
        // どの Host も受け付ける（後者は ASPNETCORE_URLS を写して書くと自然に生まれる形）。
        // IsPermissive を通せば、空になる経路もワイルドカードが残る経路も 1 本で覆える
        return IsPermissive(afterDeletion);
    }
}
