// フレームワークと同じホスト名の正規化を通すために使う
using Microsoft.AspNetCore.Http;
// ログ用に制御文字を可視化するとき、文字列を 1 文字ずつ組み立てるために使う
using System.Text;

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
    /// その項目の並びが、どの <c>Host</c> でも受け付ける状態か、
    /// そうなら<b>何が原因か</b>を返す。
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
    /// <para><b>フォールバックの規則もここに置く。</b>
    /// 「1 件も残らなければ既定の <c>["*"]</c> へ落ちる」「ワイルドカードが 1 つでもあれば
    /// 全許可へ切り替わる」という 2 つは、これを読む判定が 2 つあっても同じでなければならない。
    /// 書き写すと、フレームワーク側にもう 1 つ経路が増えたときに片方だけが直り、
    /// その差は<b>「消してよい」と案内する方向</b>（fail-open）へ倒れる。</para>
    ///
    /// <para><b>bool ではなく理由を返すのが要点。</b> 以前はここが
    /// 「ワイルドカードか」を返す <c>bool</c> で、正規化に失敗した項目も
    /// <c>true</c>（＝ワイルドカード）へ畳んでいた。倒す向きは正しい（§9 fail-closed）が、
    /// <b>畳んだ時点で「どちらだったか」が失われる</b>ため、警告の文面は
    /// ワイルドカードの話しかできなくなる ——
    /// <c>"0.0\t.0.0"</c>（途中に制御文字が紛れた綴り）で運用者が受け取るのは
    /// 「'*' か '[::]' か '0.0.0.0' を消せ」という、<b>自分の設定に存在しないものを
    /// 指す案内</b>で、実際の症状（実測では毎リクエストが例外）とも噛み合わない。
    /// <b>「どの制御文字が IDNA を壊すか」を言い当てる必要は無い</b> ——
    /// <see cref="TryNormalizeEntry"/> が<b>同じ正規化を実際に通して</b>答えを既に持っており、
    /// 畳まずに運べば済む。以前この境界を「機械的には言い当てられない」と書いていたのは誤りで、
    /// 予測ではなく観測の問題だった。</para>
    ///
    /// <para><b>並び順のとおりに前から見る。</b> フレームワークは項目を宣言順に
    /// 正規化しながら走査し、<b>最初のワイルドカードで打ち切る</b>。
    /// だから正規化できない項目とワイルドカードが同居するとき、結果は並び順で変わる ——
    /// 実測では <c>"0.0\t.0.0;0.0.0.0"</c> は例外、<c>"0.0.0.0;0.0\t.0.0"</c> は 200
    /// （<c>HostFilteringShortCircuitTests</c> が固定）。
    /// <c>Any</c> で畳まず前から 1 件ずつ見るのは、この順序をそのまま写すため。</para>
    /// </remarks>
    /// <param name="entries">分割済みの項目（トリムしていない生の値でよい）。</param>
    /// <returns>
    /// どの <c>Host</c> でも受け付ける状態でなければ
    /// <see cref="PermissiveReason.NotPermissive"/>、そうでなければその原因。
    /// </returns>
    private static PermissiveReason ClassifyEntries(string[] entries)
    {
        // 1 件も残らないなら、フレームワークは既定の ["*"] へ落ちる
        if (entries.Length == 0) return PermissiveReason.NoEntriesLeft;

        // フレームワークと同じく、宣言順に 1 件ずつ見て最初に当たったところで打ち切る
        foreach (var entry in entries)
        {
            // 正規化できない綴りは、フレームワークが先に例外を投げる位置でもある
            if (!TryNormalizeEntry(entry, out var normalized))
            {
                // 判断できない綴りは「絞れている」と言えないので、警告する側へ倒す
                return PermissiveReason.UnparsableEntry;
            }

            // 正規化後の綴りが 3 つのワイルドカードのいずれかなら、その時点で全許可
            if (Wildcards.Contains(normalized, StringComparer.Ordinal))
            {
                // どれが当たったかまでは要らない（運用者への案内は 3 綴りを並べる）
                return PermissiveReason.WildcardEntry;
            }
        }

        // 最後まで当たらなければ、実ホスト名だけの一覧
        return PermissiveReason.NotPermissive;
    }

    /// <summary>
    /// フレームワークと同じ正規化（IDNA / NFKC）を試み、成功したかを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>正規化の失敗を、3 つの問いで別々に解釈するために切り出してある。</b>
    /// 「警告を出すべきか」（<see cref="IsPermissive"/>）は判断できない綴りを
    /// <b>ワイルドカード側へ倒す</b>のが正しい（鳴りすぎる＝安全側）。
    /// 「死んだ項目を消すと何が起きるか」（<see cref="ClassifyDeadEntryDeletion"/>）は
    /// <b>宣言順に見て実際にその綴りへ到達したときだけ</b>断定をやめる ——
    /// 実測するとフレームワークの結果は<b>項目の並び順で変わる</b>ため、
    /// 到達しない壊れた項目まで「判断できない」に倒すと、確定している答えを取り落とす。
    /// 「その項目は一致しえないか」（<see cref="IsNeverMatchingEntry"/>）は
    /// <b>どちらにも倒さず対象から外す</b> ——突き合わせる値そのものが作れない以上、
    /// 「空白のせいで一致しない」とは言えないため。</para>
    ///
    /// <para><b>成功したときの値も返すのが要点。</b> フレームワークが <c>Host</c> と
    /// 突き合わせるのは正規化<b>後</b>の綴りなので、呼び出し側が生の綴りを見て判断すると
    /// 正規化で落ちる文字（角括弧 IPv6 の <c>]</c> 以降）を見落とす。
    /// 正規化の手順は同じなので、成否と結果の解釈だけを呼び出し側へ持たせる。</para>
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
    /// (c) ワイルドカードを 1 つでも含む、(d) 正規化できない綴りを含む
    /// （素通りではないが「絞れている」とも言えないので鳴らす側へ倒す）、のいずれか。
    /// <b>どれに当たったかは <see cref="ClassifyPermissive"/> が返す</b> ——
    /// 警告の文面はそれに合わせる（値に無いワイルドカードを探させないため）。
    /// </returns>
    public static bool IsPermissive(string? allowedHosts) =>
        // 理由まで求めたうえで、警告に値するかを共通の規則で決める。
        // <b>bool をここで組み立て直さない</b> ——同じ規則が 2 か所に現れると、
        // 片方にだけ分岐が足されたとき「警告は出るのに文面は古い」形で食い違う
        WarrantsWarning(ClassifyPermissive(allowedHosts));

    /// <summary>
    /// その原因が、運用者へ警告を出すべきものかを返す。
    /// </summary>
    /// <remarks>
    /// <b>「どの原因が警告に値するか」を 1 か所へ置くために要る。</b>
    /// <see cref="IsPermissive"/> と <c>Program.cs</c> の起動時チェックは
    /// どちらもこの判断を必要とするが、どちらかが
    /// <c>reason != PermissiveReason.NotPermissive</c> を自分で書くと、
    /// 規則の写しが増える（実際に <c>Program.cs</c> がそう書いていた）。
    /// そのとき「警告に値しない原因」を 1 つ足すと、
    /// 片方だけが黙って古い判断のまま残る ——
    /// <see cref="IsPermissive"/> の docstring が禁じているのと同じ形。
    /// </remarks>
    /// <param name="reason">全許可になっている原因（<see cref="ClassifyPermissive"/> の戻り値）。</param>
    /// <returns>警告を出すべきなら <c>true</c>。</returns>
    public static bool WarrantsWarning(PermissiveReason reason) =>
        // 「絞れている」以外はすべて、運用者に知らせるべき状態
        reason != PermissiveReason.NotPermissive;

    /// <summary>
    /// その設定値が全許可なら、<b>その原因</b>を返す。
    /// </summary>
    /// <remarks>
    /// <para><b><see cref="IsPermissive"/> の中身をそのまま公開したもの。</b>
    /// 警告ログは「絞れていない」ことだけでなく<b>なぜそうなのか</b>を運用者へ伝える必要があり、
    /// 原因ごとに書くべきことが違う（値に無いワイルドカードを探させない・
    /// 空の一覧なら既定へ落ちることを言う・正規化できない綴りなら症状が
    /// 全拒否ではなく例外であることを言う）。
    /// <b>原因の判定を Program.cs 側へ書いてはいけない</b> ——
    /// あちらは <c>if (!IsDevelopment())</c> の中なのでテストから 1 行も走らない
    /// （同じ理由で <see cref="DeadEntryFixAdvice"/> もここに置いてある）。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>
    /// 実ホスト名だけに絞れているなら <see cref="PermissiveReason.NotPermissive"/>、
    /// そうでなければ全許可になっている原因。
    /// </returns>
    public static PermissiveReason ClassifyPermissive(string? allowedHosts)
    {
        // 未設定なら、フレームワークは分割すら行わず既定の ["*"] へ落ちる
        if (allowedHosts is null) return PermissiveReason.NoEntriesLeft;

        // <b>フレームワークとまったく同じ分割</b>で項目を取り出す（規則は SplitEntries が持つ）
        var entries = SplitEntries(allowedHosts);

        // 規則そのものは 1 か所（ClassifyEntries）に置く
        return ClassifyEntries(entries);
    }

    /// <summary>
    /// 設定値が全許可になっている原因。
    /// </summary>
    public enum PermissiveReason
    {
        /// <summary>全許可ではない（実ホスト名だけの一覧）。</summary>
        NotPermissive,

        /// <summary>
        /// 空の項目を落とすと 1 件も残らない（未設定・<c>""</c> ・ <c>";"</c> など）。
        /// フレームワークは既定の <c>["*"]</c> へ落ちる。
        /// </summary>
        NoEntriesLeft,

        /// <summary>ワイルドカード（<c>*</c> ・ <c>[::]</c> ・ <c>0.0.0.0</c>）を含む。</summary>
        WildcardEntry,

        /// <summary>
        /// 正規化できない綴りを含む（<c>"0.0\t.0.0"</c> など）。
        /// 実測ではフレームワーク自身が例外を投げる ——
        /// 素通りではないが「絞れている」とも言えないので警告する側へ数える。
        /// </summary>
        UnparsableEntry,
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
    ///
    ///
    /// <para><b>起動時のチェックはここを直接は呼ばない</b>（<see cref="InspectNeverMatchingEntries"/>
    /// を 1 本だけ呼ぶ）。それでも公開のまま残しているのは、<b>2 つの出力を別々に観測する入口</b>
    /// が要るため —— <c>ResponseCacheHeaderIntegrationTests</c> は「一致しえない項目が 1 件だけか」
    /// を、<c>AllowedHostsPolicyTests</c> は分類と切り離した値を、それぞれここから見る。
    /// まとめた入口だけにすると、どちらが崩れたのかを失敗文言から切り分けられない。
    /// <b>本番の経路は <see cref="InspectNeverMatchingEntries"/> 1 本だけ</b>と読むこと。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>一致しえない項目（無ければ空）。運用者へそのまま見せる想定。</returns>
    public static IReadOnlyList<string> NeverMatchingEntries(string? allowedHosts) =>
        // 振り分けは 1 か所（PartitionEntries）だけが行う。ここで自前に振り分け直すと、
        // 分類側（ClassifyDeadEntryDeletion）と「同じ項目を見ている」保証が構造から外れる
        PartitionEntries(allowedHosts).Dead;

    /// <summary>
    /// その項目 1 件が、どの <c>Host</c> とも一致しえないかを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>規則を 1 か所へ置く。</b> 「死んでいる項目」と「生きている項目」を別々の式で
    /// 書くと、条件を広げたとき（項目の途中に紛れた制御文字まで
    /// 「一致しえない」と数えるようにする、など）に片方だけが取り残される。そのとき <see cref="ClassifyDeadEntryDeletion"/> は
    /// 「生きた項目が残る」と答えるのに実際には 0 件になり、
    /// <b>削除してよいと案内した結果が全ホスト許可</b>になる。</para>
    ///
    /// <para><b>生の綴りではなく<see cref="TryNormalizeEntry">正規化後</see>を見る。</b>
    /// フレームワークが <c>Host</c> ヘッダーと突き合わせるのは<b>正規化を通したあとの値</b>で、
    /// この正規化は空白を落とすとは限らない代わりに<b>落とす綴りがある</b> ——
    /// <c>HostString.ToUriComponent()</c> は角括弧の IPv6 リテラルで
    /// <c>]</c> より<b>うしろを丸ごと捨てる</b>（実測:
    /// <c>"[::1] "</c> → <c>"[::1]"</c> ・ <c>"[::] "</c> → <c>"[::]"</c>。
    /// 素のホスト名は <c>" a.test"</c> → <c>" a.test"</c> で空白が残るので、
    /// <b>この違いは括弧付きの綴りだけに出る</b>）。
    /// 生の綴りを <c>Trim()</c> と比べていた頃は、この 2 つを「死んでいる」と誤って名指ししていた:
    /// <c>"a.test;[::1] "</c> は実測で <c>Host: [::1]</c> を<b>200 で受ける</b>のに
    /// 「消してよい」と案内し（消すと IPv6 のクライアントが一斉に 400 になる＝こちらが障害を作る）、
    /// <c>"[::] "</c> に至っては実測で<b>全ホスト許可</b>なのに
    /// 「どのホスト名も受け付けない」と説明していた
    /// （<see cref="IsPermissive"/> は正規化を通すので正しく全許可と答えており、
    /// <b>2 本の警告が同じ項目について逆のことを言う</b>状態だった）。</para>
    ///
    /// <para><b>正規化できない綴りは、ここでは死んだ項目に数えない。</b>
    /// 突き合わせる値そのものが作れない以上「空白のせいで一致しない」とは言えず、
    /// その綴りは <see cref="IsPermissive"/> 側が
    /// <see cref="PermissiveReason.UnparsableEntry"/> として専用の文面で拾う。
    /// ここで拾うと、同じ項目に対して<b>原因の違う 2 本の警告</b>が出て取り違えのもとになる。</para>
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（トリムしていない生の値）。</param>
    /// <returns>どの <c>Host</c> とも一致しえないなら <c>true</c>。</returns>
    private static bool IsNeverMatchingEntry(string entry) =>
        // 正規化できない綴りは別の警告の担当なので、ここでは死んだ項目に数えない
        TryNormalizeEntry(entry, out var normalized)
        // 正規化後にまだ前後の空白が残る項目は、Host ヘッダーと綴りが一致しえない
        && !string.Equals(normalized, normalized.Trim(), StringComparison.Ordinal);

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
    /// どちらにせよ設定は壊れている（露出ではなく障害）ので、
    /// <b>断定せず「判断できない」と答え、案内も断定しない</b>のが正しい。</para>
    ///
    /// <para><b>ただし「壊れた項目があるか」を <c>Any</c> で見てはいけない。</b>
    /// 上のとおり結果を左右するのは<b>並び順</b>なので、判定も
    /// <see cref="ClassifyEntries"/> に任せて<b>宣言順に見て最初に当たったところで打ち切る</b>。
    /// <c>Any</c> で畳むと、前にワイルドカードがあって<b>実際には評価されない</b>壊れた項目まで
    /// <see cref="DeadEntryDeletionOutcome.Unknown"/> に倒してしまう ——
    /// <c>"0.0.0.0;0.0\t.0.0; "</c> は 1 件目で打ち切られて 200（全許可）で確定しているのに
    /// 「消した結果は予測できない」と答え、運用者は
    /// <b>本当に必要な「ワイルドカードの項目も消せ」という案内を受け取れない</b>。</para>
    ///
    ///
    /// <para><b>起動時のチェックはここを直接は呼ばない</b>（<see cref="InspectNeverMatchingEntries"/>
    /// を 1 本だけ呼ぶ）。公開のまま残す理由は <see cref="NeverMatchingEntries"/> と同じで、
    /// 分類だけを切り離して観測する入口として使う。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>消したときに何が起きるかの分類。</returns>
    public static DeadEntryDeletionOutcome ClassifyDeadEntryDeletion(string? allowedHosts) =>
        // 分割と振り分けは共有のパスへ任せる（分類と名指しが同じ集合を見ることを構造に載せる）
        ClassifyDeletionOf(PartitionEntries(allowedHosts));

    /// <summary>
    /// 一致しえない項目と、それを<b>消すだけ</b>にしたら何が起きるかを<b>ひと続きで</b>返す。
    /// </summary>
    /// <remarks>
    /// <b>名指しする項目と、案内の根拠になった項目が同じ集合であることを、構造で保証する。</b>
    /// 呼び出し側が <see cref="NeverMatchingEntries"/> と
    /// <see cref="ClassifyDeadEntryDeletion"/> を別々に呼ぶと、同じ値を 2 度割って
    /// 同じ正規化を 2 周するうえ、<b>両者が同じ項目を見ていることを保証するものが何も無い</b>
    /// （判定の条件を片方にだけ足す変更が通ってしまう）。
    /// 起動時のチェックはこの 1 本だけを呼ぶ（CLAUDE.md §6 DRY）。
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>一致しえない項目（無ければ空）と、それを消したときに何が起きるかの分類。</returns>
    public static (IReadOnlyList<string> Entries, DeadEntryDeletionOutcome Outcome)
        InspectNeverMatchingEntries(string? allowedHosts)
    {
        // 設定値を 1 度だけ分割し、1 度だけ「死んだ項目」と「残る項目」へ振り分ける
        var partition = PartitionEntries(allowedHosts);

        // 名指しする項目と分類を、その 1 つの振り分けから作る
        // （ここが「同じ集合を見ている」ことの根拠。2 つの公開 API を別々に呼ぶ形に戻すと、
        //  片方の判定にだけ条件や副作用を足す変更が通ってしまう）
        return (partition.Dead, ClassifyDeletionOf(partition));
    }

    /// <summary>
    /// 設定値を<b>1 度だけ</b>分割し、「一致しえない項目」と「残る項目」へ振り分けた結果。
    /// </summary>
    /// <param name="Dead">どの <c>Host</c> とも一致しえない項目（書かれた順）。</param>
    /// <param name="Survivors">それらを消したあとに残る項目（書かれた順）。</param>
    private readonly record struct EntryPartition(string[] Dead, string[] Survivors);

    /// <summary>
    /// 設定値を分割し、<see cref="IsNeverMatchingEntry"/> で 1 度だけ振り分ける。
    /// </summary>
    /// <remarks>
    /// <para><b>名指しと分類の唯一の入口にする。</b> 「一致しえない項目を挙げる」
    /// （<see cref="NeverMatchingEntries"/>）と「それを消すと何が起きるか」
    /// （<see cref="ClassifyDeadEntryDeletion"/>）は、<b>同じ振り分けの表と裏</b>でしかない。
    /// それぞれが自前で分割・振り分けをすると、判定の条件を片方にだけ足す変更が通り、
    /// <b>名指しした項目と案内の根拠になった項目が食い違う</b>
    /// （挙げていない項目を前提にした案内、あるいはその逆）。両方をここから導けば、
    /// その食い違いは<b>書こうとしても書けない</b>。</para>
    ///
    /// <para><b>正規化を項目ごとに 1 回で済ませる。</b> <see cref="IsNeverMatchingEntry"/> は
    /// 内部で <c>HostString.ToUriComponent()</c>（IDN の往復）を通す。2 つの公開 API を
    /// 別々に呼んでいた頃は分割が 2 回・正規化が項目ごとに 2 回走っていた。
    /// 実害の中心は速度ではなく<b>契約</b>で、「1 度に導く」と読んだ人がこの判定へ
    /// 副作用（メモ化・計測・1 回だけのログ）を足すと、静かに 2 回実行される。</para>
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>振り分けた結果（未設定ならどちらも空）。</returns>
    private static EntryPartition PartitionEntries(string? allowedHosts)
    {
        // 未設定なら項目そのものが無い（分割も正規化も走らせない）
        if (allowedHosts is null) return new EntryPartition([], []);

        // IsPermissive とまったく同じ分割を使う（同じ関数を呼ぶので、片方だけ規則が動かない）
        var entries = SplitEntries(allowedHosts);

        // 死んだ項目と残る項目を作る。ここが振り分けの唯一の場所
        var dead = new List<string>();
        var survivors = new List<string>();

        // 書かれた順のまま 1 件ずつ振り分ける（並び順は分類の判定に効くので崩さない）
        foreach (var entry in entries)
        {
            // 判定は 1 項目につき 1 回だけ呼ぶ（規則は IsNeverMatchingEntry が持つ）
            if (IsNeverMatchingEntry(entry)) dead.Add(entry);
            // 一致しうる項目は「消したあとに残る側」へ入れる
            else survivors.Add(entry);
        }

        // 振り分けた結果を、警告へそのまま載せられる配列の形で返す
        return new EntryPartition(dead.ToArray(), survivors.ToArray());
    }

    /// <summary>
    /// 振り分け済みの結果から、「死んだ項目を消すと何が起きるか」を分類する。
    /// </summary>
    /// <remarks>
    /// 判定の理由は <see cref="ClassifyDeadEntryDeletion"/> の docstring が正本。
    /// ここは<b>振り分けをやり直さない</b>ことだけを担う（やり直すと、上の
    /// <see cref="PartitionEntries"/> が構造に載せた保証がその場で外れる）。
    /// </remarks>
    /// <param name="partition">1 度だけ振り分けた結果。</param>
    /// <returns>消したときに何が起きるかの分類。</returns>
    private static DeadEntryDeletionOutcome ClassifyDeletionOf(EntryPartition partition)
    {
        // 死んだ項目が 1 件も無いなら、そもそも消す話にならない
        if (partition.Dead.Length == 0) return DeadEntryDeletionOutcome.NothingToDelete;

        // 残る項目を、フレームワークと同じ「宣言順に見て最初に当たったら打ち切る」規則で分類する。
        // <b>Any で「正規化できない項目があるか」を先に見てはいけない。</b> あの形は並び順を
        // 無視するので、前にワイルドカードがあって<b>実際には評価されない</b>壊れた項目まで
        // 「判断できない」に倒してしまう ——たとえば "0.0.0.0;0.0\t.0.0; " は、フレームワークが
        // 1 件目で打ち切るため結果が 200（全許可）で確定しているのに Unknown と答え、
        // 運用者は「ワイルドカードの項目も消せ」という本当に必要な案内を受け取れなかった
        // （並び順の実測は UnparsableEntry_ChangesTheOutcomeDependingOnItsPositionInTheList が固定）
        var survivorReason = ClassifyEntries(partition.Survivors);

        // 順に見た結果、実際に正規化できない綴りへ到達したときだけ断定をやめる
        return survivorReason switch
        {
            // 壊れた項目が先に評価される並びなので、消した結果は並び順しだいで変わる
            PermissiveReason.UnparsableEntry => DeadEntryDeletionOutcome.Unknown,

            // 消しても全許可にはならない＝消してよい
            PermissiveReason.NotPermissive => DeadEntryDeletionOutcome.Safe,

            // 残りが 0 件（既定の ["*"] へ落ちる）か、残った項目自体がワイルドカード
            _ => DeadEntryDeletionOutcome.WouldAllowEveryHost,
        };
    }

    /// <summary>
    /// 一覧をどう書くかの共通の一言（どの案内にも同じものを添える）。
    /// </summary>
    private const string ListFormatHint =
        " Write the list as 'a.example;b.example', with no spaces.";

    /// <summary>
    /// 一覧全体を作り直すよう促す一言（断定できない場合に共通で使う）。
    /// </summary>
    /// <remarks>
    /// <b>2 か所へ書き写さない。</b> 「判断できない」と「分類が増えたのに案内を足し忘れた」は
    /// 別の入口だが、運用者にしてほしいことは同じ。文面が割れると、同じ操作を
    /// 別の出来事として受け取らせることになる（CLAUDE.md: 同じ理由の文面は一字一句そろえる）。
    /// </remarks>
    private const string ReviewWholeListHint =
        "keep only real hostnames, with no wildcards and no stray characters.";

    /// <summary>
    /// 分類に応じた、運用者向けの直し方の案内を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ <c>Program.cs</c> に置かないのか。</b> あちらのトップレベル文は
    /// <c>if (!IsDevelopment())</c> の中にあり、統合テストのフィクスチャはすべて
    /// Development で起動するので、<b>この対応表は 1 行もテストから走らない</b>。
    /// 実測でも、いちばん危ない分岐の文面を "Just delete them, it is fine" へ
    /// 差し替えても<b>全件緑のまま通り、テスト件数すら変わらなかった</b>。
    /// 判定を切り出したのと同じ理由（このクラスの docstring 冒頭）で、対応表も切り出す。</para>
    ///
    /// <para><b>既定は断定しない側へ倒す。</b> 分類に値が増えたとき、
    /// <c>switch</c> の <c>_</c> は何も言わずに既定の文面を返す
    /// （実測: 5 つ目の値を足してもビルドは 0 Warning / 0 Error。
    ///  <c>CS8509</c> は <c>_</c> があるぶん出ず、この repo は警告をエラーにもしていない）。
    /// だから既定を「消してよい」側へ倒してはいけない ——
    /// 足し忘れた分類で削除を勧め、その結果が全許可になりうる。
    /// <b>足し忘れ自体は <c>AllowedHostsPolicyTests</c> が enum から導いて落とす。</b></para>
    /// </remarks>
    /// <param name="outcome">消したときに何が起きるかの分類。</param>
    /// <returns>ログにそのまま載せる案内（英語。ログの他の文面とそろえる）。</returns>
    public static string DeadEntryFixAdvice(DeadEntryDeletionOutcome outcome) =>
        // 分類ごとに、運用者がすべきことを 1 つだけ示す
        outcome switch
        {
            // 消すと全ホストを受け付ける状態になる ——直すべきは名指しの項目だけではない
            DeadEntryDeletionOutcome.WouldAllowEveryHost =>
                "Do NOT simply delete them: with these entries gone the remaining list would "
                + "accept every Host header — either it becomes empty and falls back to '*', "
                + "or a wildcard entry ('*', '[::]' or '0.0.0.0') is left behind. "
                + "Rewrite each listed entry to the real hostname AND remove any wildcard entry, "
                + "so that real hostnames are all that is left." + ListFormatHint,

            // 残る項目に正規化できない綴りがあるので、消した結果を断定しない
            DeadEntryDeletionOutcome.Unknown =>
                "Another entry cannot be parsed as a hostname, so this list is already broken in "
                + "a way that makes the effect of deleting unpredictable. Fix the whole list at "
                + "once: " + ReviewWholeListHint + ListFormatHint,

            // 消しても全許可にはならないが、<b>削除を同列に並べない</b>。
            // 名指しされる典型は "incident.example.com; www.example.com" の 2 件目＝
            // その配備先が実際に使うホスト名なので、消すと「静かに 400」が
            // 「意図して 400」へ変わるだけで、警告が暴いたはずの障害が固定される。
            // Safe が保証するのは「絞り込みが開かないこと」だけで、
            // その項目が要らないことまでは言っていない
            DeadEntryDeletionOutcome.Safe =>
                "Fix each listed entry by removing the surrounding whitespace, so the hostname "
                + "is matched again. Only delete an entry if it contains no hostname you actually "
                + "serve (an unset ${VARIABLE} leaves a blank entry like this) — deleting these "
                + "entries does not leave a list that accepts every Host, but it does mean the "
                + "hostname stays rejected." + ListFormatHint,

            // 名指しする項目が無いときと、分類が増えたのに足し忘れたとき。
            // どちらも断定せず、一覧全体を見直してもらう（上記のとおり fail-closed）
            _ => FallbackFixAdvice,
        };

    /// <summary>
    /// 専用の案内を持たない分類へ返す既定の文面。
    /// </summary>
    /// <remarks>
    /// <b>テストが「関数を呼ばずに」参照できるよう、名前を付けて公開してある。</b>
    /// 既定の文面を <c>DeadEntryFixAdvice(NothingToDelete)</c> で求めると、
    /// 比較が<b>自分自身との照合</b>になり、<c>NothingToDelete</c> に専用の arm を
    /// 足した瞬間に「足し忘れ」を 1 件も検出しなくなる
    /// （実測: 5 つ目の値を arm 無しで足し、同時に <c>NothingToDelete</c> の arm を
    ///  足すと<b>全件緑のまま通り、テスト件数も変わらなかった</b>）。
    /// CLAUDE.md が繰り返し禁じている「同じ判定でガードを書く」形なので、
    /// 照合の相手は<b>関数の外にある定数</b>にする。
    /// </remarks>
    public const string FallbackFixAdvice =
        "Review the whole list by hand: " + ReviewWholeListHint + ListFormatHint;
    /// <summary>
    /// 全許可になっている原因を、そのまま警告ログに載せられる文に直す。
    /// </summary>
    /// <remarks>
    /// <para><b>対応表を <c>Program.cs</c> に置かない理由は
    /// <see cref="DeadEntryFixAdvice"/> と同じ。</b> あちらは
    /// <c>if (!IsDevelopment())</c> の中なので、書くとテストから 1 行も走らない。</para>
    ///
    /// <para><b>直し方（実ホスト名に絞る）は原因によらず同じなので、ここでは原因だけを言う。</b>
    /// 直し方まで分岐させると、同じ 1 文が 4 通りに増えて食い違う口が増える。
    /// 変えるべきなのは<b>運用者が自分の設定のどこを見ればよいか</b>だけ ——
    /// 以前は 4 通りすべてに「'*' か '[::]' か '0.0.0.0' を消せ」と出していたため、
    /// 空の一覧や制御文字の混入では<b>存在しないものを探させていた</b>。</para>
    ///
    /// <para><b>既定は断定しない側へ倒す。</b> 分類に値が増えたとき
    /// <c>switch</c> の <c>_</c> は何も言わずに既定の文面を返す（<c>CS8509</c> は出ない）。
    /// だから既定は原因を名指ししない汎用文にし、
    /// <b>足し忘れ自体は <c>AllowedHostsPolicyTests</c> が enum から導いて落とす。</b></para>
    /// </remarks>
    /// <param name="reason">全許可になっている原因。</param>
    /// <returns>ログにそのまま載せる原因の説明（英語。ログの他の文面とそろえる）。</returns>
    public static string PermissiveCauseMessage(PermissiveReason reason) =>
        // 原因ごとに、運用者が自分の設定のどこを見ればよいかを示す
        reason switch
        {
            // 一覧そのものが空 ——値の中にワイルドカードは無いので、探させてはいけない
            PermissiveReason.NoEntriesLeft =>
                "The list has no non-empty entries, so the framework falls back to '*' "
                + "and host filtering is disabled entirely.",

            // ワイルドカードが混ざっている ——3 綴りを並べて、どれを消せばよいか示す
            PermissiveReason.WildcardEntry =>
                "The list contains a wildcard entry ('*', '[::]' or '0.0.0.0'), which "
                + "disables host filtering entirely — even when real hostnames are listed too.",

            // 正規化できない綴り ——症状が全許可ではなく例外なので、そう書く
            PermissiveReason.UnparsableEntry =>
                "One entry cannot be parsed as a hostname (a stray control or full-width "
                + "character, for example). There may be no wildcard in the list at all: "
                + "the framework currently fails to normalise that entry and errors on every "
                + "request instead, so this is reported as 'not narrowed down' either way.",

            // 「絞れている」ときと、分類が増えたのに足し忘れたとき。
            // どちらも原因を名指しせず、値そのものを見てもらう（上記のとおり fail-closed）
            _ => FallbackPermissiveCauseMessage,
        };

    /// <summary>
    /// 専用の説明を持たない原因へ返す既定の文面。
    /// </summary>
    /// <remarks>
    /// <para><b>テストが「関数を呼ばずに」参照できるよう、名前を付けて公開してある。</b>
    /// 理由は <see cref="FallbackFixAdvice"/> と同じで、
    /// 既定の文面を <c>PermissiveCauseMessage(NotPermissive)</c> で求めると
    /// 比較が<b>自分自身との照合</b>になり、足し忘れを 1 件も検出しなくなる。</para>
    ///
    /// <para><b>原因を名乗らない文面にしてある。</b> この関数は <c>public</c> なので、
    /// <see cref="PermissiveReason.NotPermissive"/>（＝正しく絞れている設定）を
    /// そのまま渡す呼び出し側が将来現れうる。以前の文面は
    /// 「絞れていない」と断定していたため、そのとき<b>正しい設定に対して
    /// 事実と逆の説明</b>を出すことになっていた（しかもテストがその対応を固定していた）。
    /// 分類が増えたときの既定としても、断定しないほうが安全側（fail-closed）。
    /// <b>この 2 段落を別々の <c>&lt;remarks&gt;</c> に分けない</b> ——XML ドキュメントの
    /// 利用側（IDE のクイック情報・doc 生成）は最初の 1 つしか描画しないので、
    /// 2 つ目は読み手に届かない。届かなくなるのは「この文面を断定的な向きへ
    /// 書き換えてはいけない」という唯一の歯止めで、<c>AllowedHostsPolicyTests</c> は
    /// enum からの網羅しか見ていないため<b>文面の向きが逆でも緑のまま</b>通る
    /// （issue #259）。</para>
    /// </remarks>
    public const string FallbackPermissiveCauseMessage =
        "No specific cause is available for this value; inspect the value itself.";

    /// <summary>設定値が未設定だったときにログへ出す代わりの綴り。</summary>
    /// <remarks>
    /// 構造化ログの既定は <c>null</c> を <c>(null)</c> と描くが、運用者にとっては
    /// 「設定していない」と「空文字を設定した」は別の出来事なので、前者だけを名乗る。
    /// </remarks>
    public const string UnsetValueForLog = "(not set)";

    /// <summary>
    /// 設定値を、ログの 1 レコードへそのまま載せられる形に直す。
    /// </summary>
    /// <remarks>
    /// <para><b>生の値をログへ埋め込まない。</b> <see cref="PermissiveReason.UnparsableEntry"/>
    /// という分類が存在すること自体が、この値に制御文字が入りうることを前提にしている
    /// （<c>"0.0\t.0.0"</c> のような綴りのためにある）。CR / LF が混ざっていると
    /// <b>1 本の警告がログ上は複数のレコードに見え</b>、(a) <c>docs/security.md</c> が案内する
    /// 「この警告が出ていないことを確認する」という運用手順が偽の継続行で破れ、
    /// (b) ログの収集・解析が<b>まさにその警告が指している設定ミスのときに</b>壊れる
    /// （issue #258）。</para>
    ///
    /// <para><b>置き換えの規則はこの 1 か所だけに置く。</b> 2 本の警告（全許可・一致しえない項目）で
    /// 書き写すと、片方だけ直る形になる。</para>
    /// </remarks>
    /// <param name="value"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>目に見えない文字を可視化した綴り（未設定なら <see cref="UnsetValueForLog"/>）。</returns>
    public static string DescribeValueForLog(string? value) =>
        // 未設定は「空文字を設定した」と区別して名乗る
        value is null ? UnsetValueForLog : MakeInvisibleCharactersVisible(value);

    /// <summary>
    /// 一致しえない項目の一覧を、ログの 1 レコードへそのまま載せられる形に直す。
    /// </summary>
    /// <remarks>
    /// <para><b>囲みと可視化を <c>Program.cs</c> から引き取っている。</b> あちらは
    /// <c>if (!IsDevelopment())</c> の中なのでテストから 1 行も走らず、整形を置いたままだと
    /// 「項目ごとに可視化を通す」という保証が<b>誰にも見られない場所</b>に残る。</para>
    ///
    /// <para><b><c>[ ]</c> で囲むのは、前後の空白が目で見えないから。</b> 囲まないと
    /// 「なぜこれが一致しないのか」が運用者に伝わらない。</para>
    ///
    /// <para><b>囲みの内側にも <see cref="DescribeValueForLog"/> と同じ規則を通す。</b>
    /// <b>いまの規則では、ここへ制御文字を含む項目は来ない</b> ——実測でも、制御文字を
    /// 含む項目は正規化そのものに失敗して <see cref="PermissiveReason.UnparsableEntry"/> 側
    /// （1 本目の警告）へ回るので、「一致しえない項目」として名指しされる綴りに
    /// 制御文字が残る組み合わせは 1 つも無い。それでも同じ規則を通すのは、
    /// <b>「一致しえない」の定義が広がるのはこれからも起きる</b>から
    /// （実際 issue #256 がその 1 つ）。規則を片方だけに掛けておくと、
    /// 定義を広げた人が<b>ログの分断まで一緒に持ち込む</b>ことになる ——
    /// 綴りがそのままなら <see cref="DescribeValueForLog"/> は元の文字列を返すので、
    /// 通しておく代償は無い。</para>
    /// </remarks>
    /// <param name="entries">一致しえない項目（<see cref="NeverMatchingEntries"/> の結果）。</param>
    /// <returns>ログへそのまま載せられる 1 本の文字列。</returns>
    public static string DescribeEntriesForLog(IReadOnlyList<string> entries) =>
        // 1 件ずつ可視化して "[ ]" で囲み、読みやすいよう ", " でつなぐ
        string.Join(", ", entries.Select(entry => $"[{MakeInvisibleCharactersVisible(entry)}]"));

    /// <summary>
    /// 目に見えない文字（制御文字）を、ログで読める綴りへ置き換える。
    /// </summary>
    /// <remarks>
    /// <para><b>制御文字ごとの対応表を持たない。</b> <c>\t</c> / <c>\r</c> / <c>\n</c> だけを
    /// 名前付きにして残りを別扱いにすると、表と実際の文字集合が少しずつずれていく。
    /// <c>\uXXXX</c> の 1 規則なら、どの制御文字でも同じ読み方で済む。</para>
    ///
    /// <para><b>逆斜線そのものも置き換える。</b> そうしないと、値に文字どおり
    /// <c>\u0009</c> と書いた場合と、タブが 1 文字入っている場合が<b>同じ見た目</b>になり、
    /// 運用者は自分の設定のどちらなのかを判別できない。ホスト名に逆斜線が
    /// 正当に現れることは無いので、読みにくくなる実害も無い。</para>
    /// </remarks>
    /// <param name="value">可視化したい文字列。</param>
    /// <returns>制御文字を <c>\uXXXX</c> へ、逆斜線を <c>\\</c> へ置き換えた文字列。</returns>
    private static string MakeInvisibleCharactersVisible(string value)
    {
        // 置き換えるものが 1 つも無い値（ほとんどの設定値）では、元の文字列をそのまま返す
        if (!value.Any(ch => char.IsControl(ch) || ch == '\\')) return value;

        // 置き換えが要るときだけ組み立てる
        var builder = new StringBuilder(value.Length);

        // 1 文字ずつ見て、読めない文字だけを置き換える
        foreach (var ch in value)
        {
            // 逆斜線は、下の \uXXXX と取り違えられないよう二重にする
            if (ch == '\\') builder.Append("\\\\");
            // 制御文字は、コードポイントが読める形へ直す（大文字 4 桁の 16 進）
            else if (char.IsControl(ch)) builder.Append("\\u").Append(((int)ch).ToString("X4"));
            // それ以外はそのまま（ホスト名として読める文字）
            else builder.Append(ch);
        }

        // 可視化した綴りを返す
        return builder.ToString();
    }
}
