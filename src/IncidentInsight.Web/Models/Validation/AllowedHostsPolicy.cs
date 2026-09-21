// フレームワークと同じホスト名の正規化を通すために使う
using Microsoft.AspNetCore.Http;
// ログ用に読めない文字を可視化するとき、文字列を 1 文字ずつ組み立てるために使う
using System.Text;
// 文字が「字として現れるか」をカテゴリで判定するために使う
using System.Globalization;
// 項目が本当に IPv6 リテラルかを、自前の近似ではなく標準の解析で見るために使う
using System.Net;
// 読めたアドレスが IPv4 か IPv6 かを見分けるために使う
using System.Net.Sockets;

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
    /// <para><b>判定は 2 つ。</b> (1) 正規化後の綴りが、突き合わせに使われるホスト部と
    /// 食い違うこと（前後の空白・ポートがこれ）。(2) <c>Host</c> ヘッダーが運べない文字を
    /// 含むこと（空白・<c>%</c>）。リクエストの <c>Host</c> ヘッダーは解析された時点で
    /// 前後に空白を持たないので、前後に空白のある項目は<b>綴りに関係なく</b>一致しえない
    /// （<c>" * "</c> のようにワイルドカードのつもりの綴りもここに落ちる）。
    /// <b>内側の空白（<c>"a b.test"</c> ・ <c>"0.0.0 .0"</c>）も (2) で拾う（issue #269）</b> ——
    /// 以前は「別の話」として見ていなかったが、そのせいで <c>"0.0.0 .0"</c> が無警告のまま残り、
    /// 運用者がその空白を外すと <c>0.0.0.0</c> ＝全許可になる経路が開いていた。
    /// どこまで拾うかの線引きは
    /// <see cref="ContainsSpellingAHostHeaderCannotCarry"/> の remarks が正本。</para>
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
        // 分類側（ClassifyDeadEntryDeletion）と「同じ項目を見ている」保証が構造から外れる。
        // 理由まで要る呼び出し側は InspectNeverMatchingEntries を使う（こちらは綴りだけ）
        [.. PartitionEntries(allowedHosts).Dead.Select(dead => dead.Value)];

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
        // 規則そのものは ClassifyDeadEntry が 1 つだけ持つ（ここは「理由があるか」だけを見る）
        ClassifyDeadEntry(entry) is not null;

    /// <summary>
    /// その項目 1 件が、どの <c>Host</c> とも一致しえないか、そうなら<b>なぜか</b>を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>ここが「一致しえない」の唯一の定義。</b> 「一致しえないか」（<c>bool</c>）と
    /// 「なぜ一致しえないか」（運用者へ出す文面）を別々の式で書くと、条件を広げたときに
    /// 片方だけが取り残され、<b>名指しした項目に付く理由が事実と違う</b>状態になる。
    /// <see cref="IsNeverMatchingEntry"/> も <see cref="DeadEntryCauseMessage"/> も
    /// ここから導く。</para>
    ///
    /// <para><b>空白とポートが理由になるのは、突き合わせ方が 2 段階だから</b>
    /// （<b>理由の一覧は <see cref="DeadEntryReason"/> が正本</b>。ここで数えて書くと、
    /// 理由を足したときにこの数字だけが古くなる）。
    /// <c>HostString.MatchesAny</c> は (1) リクエスト側の値から<b>ポートを落とし</b>、
    /// (2) 残ったホスト名を<b>許可リストの項目とそのまま</b>比べる。つまり項目の側は
    /// トリムもされずポートも落とされないので、<b>前後に空白が残る項目</b>も
    /// <b>ポートを含む項目</b>も、どの <c>Host</c> とも等しくなりえない。
    /// 実測でも <c>incident.example.test:8080</c> は
    /// <c>Host: incident.example.test:8080</c> を送っても一致せず毎リクエスト 400 になる
    /// のに、<see cref="IsPermissive"/> は <c>false</c>・ここも空を返していたため
    /// <b>警告が 1 本も出なかった</b>（issue #256）。
    /// <c>ASPNETCORE_URLS</c> からホスト名を写すときポートごと持ってくるのは
    /// <c>0.0.0.0</c> を写してしまうのと同じくらい自然な形で、しかも
    /// <c>a.example.test;b.example.test:8080</c> のように混ざると
    /// <b>サイトは生きたまま特定のホスト名だけが静かに 400 になる</b> ——
    /// 2 本目の警告を足した理由そのものの形。</para>
    ///
    /// <para><b>ポートの判定は「コロンがあるか」では書かない。</b>
    /// 角括弧の IPv6 リテラル（<c>[::1]</c> ・ <c>[::]</c>）はコロンを含むが
    /// ポートは持たず、実測でも <c>Host: [::1]</c> と正しく一致する。
    /// フレームワーク自身の分け方（<c>HostString</c> のホスト部とポート部）へ委ね、
    /// <b>正規化後の綴りがホスト部と一致しないこと</b>でその項目が死んでいることを見る。
    /// <b>ただし「死んでいる」から先の理由は、そこからは決まらない（issue #269）。</b>
    /// ポートと名乗るのは<b>ホスト部の直後がコロン</b>のときだけ、IPv6 と名乗るのは
    /// <b>実際に <see cref="IPAddress"/> で読める</b>ときだけにし、
    /// どちらにも当たらない綴りは <see cref="DeadEntryReason.NotABareHostname"/> へ倒す
    /// （理由を 2 択の当て推量で決めていた頃の壊れ方は
    /// <see cref="IsIpv6Literal"/> の docstring が正本）。
    /// <c>HostString.Port</c> を見る形では足りない ——実測で <c>a.test:abc</c> ・
    /// <c>a.test:</c> はポート部が数値として読めないため <c>Port</c> が <c>null</c> になるが、
    /// 項目としては依然としてどの <c>Host</c> とも一致しない。</para>
    ///
    /// <para><b>生の綴りではなく<see cref="TryNormalizeEntry">正規化後</see>を見る。</b>
    /// 理由は <see cref="IsNeverMatchingEntry"/> の docstring が正本。
    /// 正規化できない綴りはここでは死んだ項目に数えず、
    /// <see cref="PermissiveReason.UnparsableEntry"/> 側（1 本目の警告）へ任せる。</para>
    ///
    /// <para><b>両方に当たる項目（<c>" a.test:8080"</c>）は空白側を名乗る。</b>
    /// どちらの理由でも運用者がすることは同じ（その項目を実ホスト名だけに書き直す）で、
    /// 1 項目に 2 つの理由を並べても読み手の判断は変わらないため。</para>
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（トリムしていない生の値）。</param>
    /// <returns>一致しえないならその理由、一致しうるなら <c>null</c>。</returns>
    private static DeadEntryReason? ClassifyDeadEntry(string entry)
    {
        // 正規化できない綴りは別の警告の担当なので、ここでは死んだ項目に数えない
        if (!TryNormalizeEntry(entry, out var normalized)) return null;

        // フレームワークが Host と突き合わせるときに使う綴り（ホスト部だけ）を取り出す
        var comparable = ComparableSpelling(normalized);

        // 前後に空白が残っておらず、突き合わせ相手の綴りとも一致し、
        // さらに<b>角括弧の中身がそのまま Host ヘッダーに載りうる</b>なら、その項目は一致しうる
        if (string.Equals(normalized, normalized.Trim(), StringComparison.Ordinal)
            && string.Equals(normalized, comparable, StringComparison.Ordinal)
            && !ContainsSpellingAHostHeaderCannotCarry(normalized))
        {
            // 生きている項目なので理由は無い
            return null;
        }

        // <b>いちばん危ない形を先に名乗る。</b> 案内どおりに直すとワイルドカードになる項目は、
        // 「直せば一致する」と読ませてはいけない（直した瞬間にホスト名の絞り込みが丸ごと消える）
        if (Wildcards.Contains(RepairedSpelling(normalized), StringComparer.Ordinal))
        {
            // 直し方が「書き直す」ではなく「実ホスト名に置き換える／消す」になる唯一の形
            return DeadEntryReason.WildcardOnceRepaired;
        }

        // 正規化後にまだ前後の空白が残る項目は、Host ヘッダーと綴りが一致しえない
        if (!string.Equals(normalized, normalized.Trim(), StringComparison.Ordinal))
        {
            // 空白が原因であることを、そのまま運用者への文面へ運ぶ
            return DeadEntryReason.SurroundingWhitespace;
        }

        // <b>前後以外に空白が残っている項目は、空白専用の理由で名乗る（レビュー指摘）。</b>
        // 正規化は角括弧を補うので空白は内側へ移りうる（" ::1" → "[ ::1]"）。
        // ここを下の NotABareHostname へ落とすと、文面が
        // 「素の IPv6 リテラルではない・角括弧で囲んでも直らない」と<b>事実と逆</b>のことを
        // 言い出す —— " ::1" の正しい直し方は、まさに空白を外して "[::1]" と書くこと。
        // しかも「余分なコロンを書くな」に従うと IPv6 のコロンを消すことになる
        if (normalized.Any(char.IsWhiteSpace))
        {
            // 空白が原因であることを、そのまま運用者への文面へ運ぶ
            return DeadEntryReason.WhitespaceInsideEntry;
        }

        // <b>パーセント記号も専用の理由で名乗る（レビュー指摘）。</b>
        // 下の NotABareHostname の文面は「ポートも余分なコロンも書くな」と案内するが、
        // "www.example%2Ecom" にはどちらも無い ——名指しした項目について事実と違うことを
        // 言う形（issue #256 が名指しした誤り）になるので、ここで分ける
        if (normalized.Contains(PercentSign))
        {
            // パーセント記号が原因であることを、そのまま運用者への文面へ運ぶ
            return DeadEntryReason.PercentSignInEntry;
        }

        // ホスト部の直後がコロンなら、落とされたのは<b>実際にポート部</b>
        // （"a.test:8080" ・ "a.test:" ・ "a.test:abc" がこの形）
        if (normalized.StartsWith(comparable + PortSeparator, StringComparison.Ordinal))
        {
            // ポートが原因であることを、そのまま運用者への文面へ運ぶ
            return DeadEntryReason.PortSuffix;
        }

        // 突き合わせ相手が「角括弧を足したもの」で、<b>中身が実際に IPv6 として読める</b>なら、
        // 原因は括弧の無い IPv6 リテラル（＝角括弧で囲めば本当に一致するようになる）
        if (string.Equals(comparable, $"[{normalized}]", StringComparison.Ordinal)
            && IsIpv6Literal(normalized))
        {
            // 「角括弧で囲め」という案内が、この項目については事実として正しい
            return DeadEntryReason.UnbracketedIpv6Literal;
        }

        // どちらとも断定できない綴り（素のホスト名になっていない）
        return DeadEntryReason.NotABareHostname;
    }

    /// <summary>ホスト名とポートを分ける区切り。</summary>
    /// <remarks>
    /// 名前を付けているのは、<see cref="ClassifyDeadEntry"/> の判定と
    /// <see cref="ComparableSpelling"/> が委ねている <see cref="HostString"/> の分け方が
    /// <b>同じ区切り</b>の話をしていることを読み手に示すため（§6）。
    /// </remarks>
    private const string PortSeparator = ":";

    /// <summary>
    /// その綴りが、<b>実際に IPv6 アドレスとして読める</b>かを見る。
    /// </summary>
    /// <remarks>
    /// <para><b>「角括弧を補われた」＝ IPv6 ではない（issue #269）。</b>
    /// <see cref="HostString"/> のホスト部の切り出しは、<c>]</c> を含まず
    /// <b>コロンが 2 つ以上ある</b>値を、IPv6 かどうかに関係なく角括弧で包む。
    /// つまり <c>www.example.com:8080:</c>（末尾コロンのタイプミス、あるいは
    /// <c>host:port:path</c> の写し）も「角括弧を足したもの」に一致してしまう。</para>
    ///
    /// <para><b>取り違えると、警告が自分で自分を黙らせる。</b> この綴りを
    /// <see cref="DeadEntryReason.UnbracketedIpv6Literal"/> と名乗ると、文面は
    /// 「角括弧で囲め」と案内する。実測では、そのとおり
    /// <c>[www.example.test:8080:]</c> へ直すと<b>2 本目の警告が消える</b>一方
    /// （その綴りは <c>Host: [www.example.test:8080:]</c> なら実際に一致するので、
    /// 判定としては「生きている」で正しい）、運用者が並べたかった
    /// <c>www.example.test</c> は<b>400 のまま</b>だった。
    /// つまり案内に従うほど「警告が出ていない＝絞れている」という
    /// <c>docs/security.md</c> の確認手順が誤った安心になる ——
    /// このクラスが繰り返し避けている<b>警告が障害を作る側に回る</b>形そのもの。</para>
    ///
    /// <para><b>判定は自前で書かず <see cref="IPAddress"/> に委ねる。</b>
    /// 「コロンが 2 つ以上」「16 進とコロンだけ」といった近似は、
    /// 埋め込み IPv4（<c>::ffff:192.168.0.1</c>）やスコープ付き（<c>fe80::1%eth0</c>）で
    /// 取りこぼすか、逆に上の <c>www.example.com:8080:</c> を拾う。</para>
    /// </remarks>
    /// <param name="value">正規化済みの項目。</param>
    /// <returns>素の（スコープの付かない）IPv6 アドレスとして読めるなら <c>true</c>。</returns>
    private static bool IsIpv6Literal(string value) =>
        // アドレスとして読めて、かつそれが IPv6 であること（IPv4 は角括弧を取らない）
        IPAddress.TryParse(value, out var address)
        && address.AddressFamily == AddressFamily.InterNetworkV6
        // <b>スコープ付き（fe80::1%eth0）は除く（レビュー指摘）。</b>
        // 案内どおり角括弧で囲んでも Kestrel が Host ヘッダーごと弾くので、
        // 「囲めば一致する」は事実にならない。
        // <b>除き方は ScopeId ではなく綴りで見る（レビュー指摘）。</b>
        // IPAddress.TryParse はスコープ名が解決できないと ScopeId を 0 にして成功するため、
        // ScopeId を見る形は<b>実行機のインターフェース表に依存</b>し、
        // fe80::1%eth0 の分類が配備先ごとに変わる（"%25" を使う綴りも 0 になる）
        && !ContainsSpellingAHostHeaderCannotCarry(value);

    /// <summary>
    /// その綴りが、<c>Host</c> ヘッダーでは運べないと<b>実測した</b>文字を含むかを見る。
    /// </summary>
    /// <remarks>
    /// <para><b>Kestrel の検証規則を書き写さない（レビュー指摘）。</b> 角括弧の中身について
    /// 実測すると、Kestrel が受け付ける範囲は「IPv6 として正しいか」とは無関係だった ——
    /// <c>[a:b]</c> ・ <c>[...]</c> ・ <c>[::1::2]</c> ・ <c>[0.0.0.0]</c> は
    /// <b>どれも 200</b>（IPv6 としては 1 つも正しくない）で、
    /// <c>[foo]</c> ・ <c>[]</c> ・ <c>[:]</c> は 400。つまり実際の規則は
    /// 「16 進の数字・<c>:</c> ・ <c>.</c> だけからなり、ある程度の形を満たすこと」に近い。</para>
    ///
    /// <para><b>だから「素の IPv6 でなければ死んでいる」とは書けない。</b>
    /// そう書いた版は <c>[a:b]</c> のような<b>実際には一致する項目</b>を
    /// 「消してよい」と案内することになり、このクラスが繰り返し避けている
    /// <b>警告が障害を作る側</b>（見逃しより重い誤り）へ倒れる。
    /// かといって Kestrel の文字集合を推測で書き写すのは、この repo が
    /// 何度も踏んだ「近似を育てる」道そのもの。</para>
    ///
    /// <para><b>そこで、実測で 400 になった原因の文字だけに絞る</b> ——
    /// 空白（<c>[::1 ]</c> ・ <c>[:: ]</c>）と <c>%</c>（<c>[fe80::1%eth0]</c> ・
    /// <c>[::1%25eth0]</c>）。どちらも Host ヘッダーの構文として運べないので
    /// <b>誤検知の側へ倒れる余地が無く</b>、推測も要らない。</para>
    ///
    /// <para><b>どちらも角括弧の有無を問わない（レビュー指摘）。</b> 空白が
    /// <c>0.0.0 .0</c> のような途中の形でも運べないのは分かりやすいが、
    /// <c>%</c> も同じだった —— 一時は「普通のホスト名では percent-encoding として
    /// 合法だから角括弧の中だけ」としていたが、<b>実測はその逆</b>で、
    /// <c>a%2Db.test</c> ・ <c>www.example%2Ecom</c> ・ <c>a%b.test</c> ・ <c>a%25b.test</c> は
    /// <b>どれも 400</b>（比較のため: <c>a_b.test</c> ・ <c>a~b.test</c> ・
    /// <c>xn--bcher-kva.test</c> は 200）。角括弧の中だけを見ていた版では
    /// <c>AllowedHosts=…;www.example%2Ecom</c> が<b>警告 2 本とも出ないまま 400</b> になっていた
    /// （issue #256 と同じ形の見逃し）。<b>推測ではなく実測で決めること</b>
    /// ——この 1 行は「合法そうだから」という理屈だけで穴になっていた。</para>
    ///
    /// <para><b>残っている境界（意図した見逃し）:</b> <c>[foo]</c> や
    /// <c>[www.example.com:8080:]</c> は Kestrel が 400 で弾くのに、ここでは拾えない
    /// （中身の文字だけでは Kestrel の規則と区別できないため）。
    /// 見逃す側なので許容する ——そのかわり、
    /// <see cref="DeadEntryReason.NotABareHostname"/> の文面が
    /// <b>「角括弧で囲むな」</b>と明示して、運用者をここへ誘導しないようにしてある。</para>
    /// </remarks>
    /// <param name="spelling">角括弧の中身（または項目そのもの）。</param>
    /// <returns>運べない文字を含むなら <c>true</c>。</returns>
    private static bool ContainsSpellingAHostHeaderCannotCarry(string spelling) =>
        // 空白（ヘッダー値の解析で切れる）か、スコープの区切り（実測で 400）を含むか
        spelling.Any(ch => char.IsWhiteSpace(ch) || ch == PercentSign);

    /// <summary>
    /// パーセント記号（IPv6 のスコープ区切り <c>fe80::1%eth0</c> と percent-encoding の両方）。
    /// </summary>
    /// <remarks>
    /// <b>どちらの用途でも <c>Host</c> ヘッダーには載らない</b>（実測は
    /// <see cref="ContainsSpellingAHostHeaderCannotCarry"/> の remarks が正本）。
    /// </remarks>
    private const char PercentSign = '%';

    /// <summary>
    /// フレームワークが <c>Host</c> と突き合わせるときに使う綴り（ホスト部）を返す。
    /// </summary>
    /// <remarks>
    /// <b>自前でコロンを数えない。</b> 角括弧の IPv6 リテラルはコロンを含むがポートを持たず、
    /// 逆に括弧の無い IPv6 リテラルは括弧を補われる。どちらも
    /// <c>HostString</c> のホスト部の切り出しが正しく分けてくれるので、そこへ委ねる。
    /// </remarks>
    /// <param name="normalized">正規化済みの項目。</param>
    /// <returns>ホスト部の綴り。</returns>
    private static string ComparableSpelling(string normalized) => new HostString(normalized).Host;

    /// <summary>
    /// その項目を案内どおりに直したときに残る綴り（＝実際に突き合わされることになる綴り）を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>「消したら何が起きるか」だけでは足りない。</b>
    /// <see cref="ClassifyDeadEntryDeletion"/> は<b>消す</b>操作しか見ていないが、
    /// 2 本目の警告が実際に勧めるのは<b>書き直す</b>操作のほう。
    /// <c>"incident.example.com;0.0.0.0:8080"</c>（<c>ASPNETCORE_URLS</c> を写すと自然に生まれる形）は
    /// 消せば実ホスト名だけが残るので「消してよい」＝<c>Safe</c> と分類されるが、
    /// 案内どおり<b>ポートを外して書き直す</b>と <c>0.0.0.0</c> になり、
    /// <b>ホスト名の絞り込みが丸ごと無効になる</b>（issue #64 へ移る）。
    /// 前後の空白でも同じで、<c>"incident.example.com; 0.0.0.0"</c> ・
    /// <c>"incident.example.com; *"</c> は<b>以前から</b>この形だった。</para>
    ///
    /// <para><b>だから直した結果も見る。</b> 直すとは「空白を落とし、
    /// 突き合わせに使われるホスト部だけにする」こと。その結果がワイルドカードなら、
    /// その項目は <see cref="DeadEntryReason.WildcardOnceRepaired"/> として
    /// 専用の文面で名指しする。</para>
    ///
    /// <para><b>落とすのは前後の空白だけでは足りない（レビュー指摘）。</b>
    /// 正規化は角括弧を<b>補う</b>ので、空白は<b>括弧の内側へ移りうる</b> ——
    /// <c>" ::"</c>（区切りのうしろに空白を入れた一覧で、<c>ASPNETCORE_URLS</c> から
    /// 写す <c>0.0.0.0</c> の IPv6 版）は <c>"[ ::]"</c> になる。
    /// <c>Trim()</c> だけだと内側の空白が残って <c>[::]</c> と一致せず、
    /// <b>この項目だけがワイルドカードの警告から外れる</b>。
    /// そのとき付くのは「この項目を実ホスト名へ直せ」という<b>ごく普通の案内</b>で、
    /// 従って空白を外すと <c>::</c> ＝全ホスト許可（issue #64）——
    /// 空白 1 つで、いちばん危ない形の専用警告が<b>有害な案内</b>に入れ替わる。
    /// 空白をすべて落としてから見れば、この抜け道は綴りに依存せず閉じる
    /// （落として初めてワイルドカードになる項目だけが影響を受けるので、
    /// 実ホスト名を誤って名指しすることは無い）。</para>
    /// </remarks>
    /// <param name="normalized">正規化済みの項目。</param>
    /// <returns>案内どおりに直したあとの綴り。</returns>
    private static string RepairedSpelling(string normalized) =>
        // 運べない文字（空白・"%" 以降）を落としてからホスト部を取る
        // （空白・パーセント・ポートをまとめて外した形）
        ComparableSpelling(TruncateAtPercentSign(RemoveWhitespace(normalized)));

    /// <summary>最初のパーセント記号より後ろを落とす。</summary>
    /// <remarks>
    /// <para><b>空白と同じ穴が <c>%</c> 側にも残っていた（レビュー指摘）。</b>
    /// <c>"0.0.0.0%20"</c> は、運用者が末尾の読めない部分を削れば <c>0.0.0.0</c> ＝
    /// 全ホスト許可（issue #64）になるのに、<see cref="RemoveWhitespace"/> だけでは
    /// <c>"0.0.0.0%20"</c> のままで <see cref="DeadEntryReason.WildcardOnceRepaired"/> に
    /// 当たらず、<b>ごく普通の「実ホスト名へ直せ」</b>の案内が付いていた
    /// （<c>"[::]%20"</c> のほうは括弧のおかげで当たっていたので、<b>非対称</b>でもあった）。</para>
    ///
    /// <para><b>落とすのは「<c>%</c> 以降」で、<c>%</c> だけを抜かない。</b>
    /// 抜くと <c>"0.0.0.0%20"</c> は <c>"0.0.0.020"</c> になり、運用者が実際に行う直し方
    /// （読めない末尾ごと削る）と食い違う ——この関数が答えるのは
    /// 「直したら何になるか」なので、実際の直し方に寄せる。</para>
    ///
    /// <para><b>誤検知の側へは倒れない。</b> 影響を受けるのは「<c>%</c> の手前が
    /// ちょうどワイルドカードの綴り」の項目だけで、その項目に
    /// 「そのまま直すな」と言うのは正しい。<c>"a.test%20"</c> ・ <c>"%0.0.0.0"</c> は
    /// 落とした結果がワイルドカードではないので、これまでどおりの理由で名乗る。</para>
    /// </remarks>
    /// <param name="value">空白を落とした後の綴り。</param>
    /// <returns>最初の <c>%</c> より前の部分（<c>%</c> が無ければ元の綴り）。</returns>
    private static string TruncateAtPercentSign(string value)
    {
        // 最初のパーセント記号の位置を探す
        var at = value.IndexOf(PercentSign);

        // 見つからなければそのまま、見つかればその手前までを返す
        return at < 0 ? value : value[..at];
    }

    /// <summary>綴りから空白をすべて取り除く。</summary>
    /// <remarks>
    /// 前後だけでなく途中の空白も落とすのは、正規化が角括弧を補うと
    /// 空白が内側へ移るため（理由は <see cref="RepairedSpelling"/> の remarks が正本）。
    /// </remarks>
    /// <param name="value">元の綴り。</param>
    /// <returns>空白を 1 つも含まない綴り。</returns>
    private static string RemoveWhitespace(string value) =>
        // 空白でない文字だけを連結して返す
        string.Concat(value.Where(ch => !char.IsWhiteSpace(ch)));

    /// <summary>
    /// その項目が、どの <c>Host</c> とも一致しえない理由。
    /// </summary>
    /// <remarks>
    /// 理由ごとに文面を分けるのは <see cref="PermissiveReason"/> と同じ趣旨 ——
    /// 混在した一覧（<c>"a.example.test; b.example.test;c.example.test:8080"</c>）で
    /// 1 つの文面しか出せないと、<b>どの項目がなぜ落ちているか</b>を運用者が追えない。
    /// </remarks>
    public enum DeadEntryReason
    {
        /// <summary>正規化後も前後に空白が残っている（項目はトリムされない）。</summary>
        SurroundingWhitespace,

        /// <summary>ポートを含んでいる（<c>Host</c> 側はポートを落としてから比べられる）。</summary>
        PortSuffix,

        /// <summary>角括弧の無い IPv6 リテラル（<c>Host</c> 側は必ず角括弧付きで届く）。</summary>
        UnbracketedIpv6Literal,

        /// <summary>
        /// 前後以外の場所に空白が残っている（<c>Host</c> ヘッダーは空白を運べない）。
        /// </summary>
        /// <remarks>
        /// <see cref="SurroundingWhitespace"/> と分けてあるのは、<b>直し方の案内が違う</b>から。
        /// あちらは「前後を落とせ」で済むが、こちらは正規化が角括弧を補った結果
        /// 空白が<b>内側へ移った</b>形（<c>" ::1"</c> → <c>"[ ::1]"</c>）や、
        /// 途中に空白のある形（<c>"www.example .test"</c>）を含むため、
        /// 「どこにある空白も落とせ」と言う必要がある。
        /// <see cref="NotABareHostname"/> へ落とすと、その文面が
        /// 「角括弧で囲んでも直らない」と<b>事実と逆</b>のことを案内してしまう。
        /// </remarks>
        WhitespaceInsideEntry,

        /// <summary>
        /// パーセント記号を含む（<c>Host</c> ヘッダーはこの文字を運べない）。
        /// </summary>
        /// <remarks>
        /// IPv6 のスコープ区切り（<c>[fe80::1%eth0]</c>）でも percent-encoding
        /// （<c>www.example%2Ecom</c>）でも、実測では <c>Host</c> ヘッダーが 400 になる。
        /// <see cref="NotABareHostname"/> へ落とすと、その文面が「ポートも余分なコロンも
        /// 書くな」と<b>その項目には当てはまらないこと</b>を案内してしまう。
        /// </remarks>
        PercentSignInEntry,

        /// <summary>
        /// 素のホスト名になっていない（ポートでも IPv6 リテラルでもない綴り）。
        /// </summary>
        /// <remarks>
        /// <b>断定しないための値（issue #269）。</b> 以前は最後の 2 つを
        /// 「角括弧を足されたか否か」の 2 択で決めており、どちらの側でも
        /// 事実と違う理由が付いた: <c>www.example.com:8080:</c> は
        /// <see cref="UnbracketedIpv6Literal"/> と名乗って<b>角括弧で囲め</b>と案内し
        /// （従うと 2 本目の警告だけが消え、並べたかったホスト名は 400 のまま）、
        /// <c>a]b.test</c> は <see cref="PortSuffix"/> と名乗って<b>ポートを外せ</b>と
        /// 案内していた（その項目にポートは 1 つも無い）。
        /// 原因を言い当てられない綴りでは、<b>言い当てないほうが安全</b>。
        /// </remarks>
        NotABareHostname,

        /// <summary>直すとワイルドカードになる（＝書き直すと全ホスト許可になる）。</summary>
        WildcardOnceRepaired,
    }

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
    public static (IReadOnlyList<DeadEntry> Entries, DeadEntryDeletionOutcome Outcome)
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
    /// <param name="Dead">どの <c>Host</c> とも一致しえない項目（書かれた順・理由つき）。</param>
    /// <param name="Survivors">それらを消したあとに残る項目（書かれた順）。</param>
    private readonly record struct EntryPartition(DeadEntry[] Dead, string[] Survivors);

    /// <summary>
    /// どの <c>Host</c> とも一致しえない項目 1 件と、その理由。
    /// </summary>
    /// <remarks>
    /// <b>理由を項目と一緒に運ぶ。</b> 名指しする側（警告の文面）が理由を
    /// <see cref="ClassifyDeadEntry"/> から導き直すと、<see cref="PartitionEntries"/> が
    /// docstring で約束している「項目ごとに正規化を 1 回で済ませる」が崩れる ——
    /// あの約束は速度の話ではなく<b>契約</b>で、あとから判定へ副作用（メモ化・計測・
    /// 1 回だけのログ）を足した人がそれを静かに 2 回走らせることになる。
    /// 振り分けの時点で分かっている値なので、そのまま持たせる。
    /// </remarks>
    /// <param name="Value">項目の綴り（生の値）。</param>
    /// <param name="Reason">その項目が一致しえない理由。</param>
    public readonly record struct DeadEntry(string Value, DeadEntryReason Reason);

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
        var dead = new List<DeadEntry>();
        var survivors = new List<string>();

        // 書かれた順のまま 1 件ずつ振り分ける（並び順は分類の判定に効くので崩さない）
        foreach (var entry in entries)
        {
            // 判定は 1 項目につき 1 回だけ呼ぶ（規則は ClassifyDeadEntry が持つ）
            var reason = ClassifyDeadEntry(entry);

            // 理由が付いた項目は、理由ごと「死んだ側」へ入れる（あとで導き直さない）
            if (reason is not null) dead.Add(new DeadEntry(entry, reason.Value));
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
        " Write the list as 'a.example;b.example', with no spaces and no port numbers.";

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
                "Fix each listed entry so that it is exactly the hostname you serve (the reason "
                + "is given next to each entry above), so the hostname is matched again. Only "
                + "delete an entry if it contains no hostname you actually serve (an unset "
                + "${VARIABLE} leaves a blank entry like this) — deleting these entries does not "
                + "leave a list that accepts every Host, but it does mean the hostname stays "
                + "rejected." + ListFormatHint,

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
    /// <param name="entries">一致しえない項目（<see cref="InspectNeverMatchingEntries"/> の結果）。</param>
    /// <returns>ログへそのまま載せられる 1 本の文字列。</returns>
    public static string DescribeEntriesForLog(IReadOnlyList<DeadEntry> entries) =>
        // 1 件ずつ「可視化して "[ ]" で囲み、その項目の理由を添える」形にして ", " でつなぐ
        string.Join(", ", entries.Select(DescribeEntryForLog));

    /// <summary>
    /// 一致しえない項目 1 件を、囲み・可視化・理由の 3 点セットにする。
    /// </summary>
    /// <remarks>
    /// <b>理由は振り分けの時点で決まっているものを使い、ここで導き直さない。</b>
    /// 導き直すと <see cref="PartitionEntries"/> が docstring で約束している
    /// 「項目ごとに正規化を 1 回で済ませる」が崩れる。名指しした項目と添えた理由が
    /// 食い違わないことは、<see cref="DeadEntry"/> が 1 つの値として運ぶことで担保する。
    /// </remarks>
    /// <param name="entry">一致しえない項目 1 件（理由つき）。</param>
    /// <returns>ログへ載せる 1 件分の綴り。</returns>
    private static string DescribeEntryForLog(DeadEntry entry) =>
        // 空白が目で見えるよう "[ ]" で囲み、そのうしろへその項目自身の理由を添える
        $"[{MakeInvisibleCharactersVisible(entry.Value)}] ({DeadEntryCauseMessage(entry.Reason)})";

    /// <summary>
    /// 項目が一致しえない理由を、そのままログに載せられる文に直す。
    /// </summary>
    /// <remarks>
    /// <para><b>対応表を <c>Program.cs</c> に置かない理由は
    /// <see cref="DeadEntryFixAdvice"/> と同じ。</b> あちらは
    /// <c>if (!IsDevelopment())</c> の中なので、書くとテストから 1 行も走らない。</para>
    ///
    /// <para><b>直し方ではなく理由だけを言う。</b> 直し方は「消してよいかどうか」で変わるので
    /// <see cref="DeadEntryFixAdvice"/> が 1 本だけ出す。ここで直し方まで分岐させると、
    /// 同じ 1 文が理由 × 分類の通り数に増えて食い違う口が増える。</para>
    ///
    /// <para><b>既定は断定しない側へ倒す。</b> 理由に値が増えたとき <c>switch</c> の
    /// <c>_</c> は何も言わずに既定の文面を返す（<c>CS8509</c> は出ない）。
    /// <b>足し忘れ自体は <c>AllowedHostsPolicyTests</c> が enum から導いて落とす。</b></para>
    /// </remarks>
    /// <param name="reason">その項目が一致しえない理由。</param>
    /// <returns>ログにそのまま載せる理由の説明（英語。ログの他の文面とそろえる）。</returns>
    public static string DeadEntryCauseMessage(DeadEntryReason reason) =>
        // 理由ごとに、運用者がその項目のどこを見ればよいかを示す
        reason switch
        {
            // 項目はトリムされないので、前後の空白がそのまま綴りの一部になっている
            DeadEntryReason.SurroundingWhitespace =>
                "host filtering does not trim entries, so the surrounding whitespace is part of "
                + "the entry and no Host header can ever equal it",

            // Host ヘッダー側はポートを落としてから比べられるので、ポート付きは一致しえない
            DeadEntryReason.PortSuffix =>
                "host filtering strips the port from the Host header before comparing, so an "
                + "entry that carries a port can never be equal — list the hostname on its own",

            // Host ヘッダーの IPv6 リテラルは必ず角括弧付きで届くので、括弧なしは一致しえない
            DeadEntryReason.UnbracketedIpv6Literal =>
                "this is an IPv6 literal without brackets, but a Host header always carries one "
                + "in brackets, so the two can never be equal — write it as '[::1]'",

            // 空白はどこにあっても運べないので、「1 つ残らず落とせ」とだけ言う
            DeadEntryReason.WhitespaceInsideEntry =>
                "a Host header cannot carry whitespace, and host filtering compares it against "
                + "the entry exactly as written, so the two can never be equal — remove every "
                + "space from this entry (note that host filtering rewrites a bare IPv6 literal "
                + "into brackets, so a leading space ends up inside them: ' ::1' becomes "
                + "'[ ::1]'; write it as '[::1]')",

            // パーセント記号は用途を問わず運べないので、「書かない」とだけ言う
            DeadEntryReason.PercentSignInEntry =>
                "a Host header cannot carry a percent sign — neither as an IPv6 scope id "
                + "('[fe80::1%eth0]') nor as percent-encoding ('www.example%2Ecom') — and host "
                + "filtering compares it against the entry exactly as written, so the two can "
                + "never be equal. Write the hostname literally, without any '%'",

            // 原因を言い当てられない綴り ——<b>断定せず、直し方だけを案内する</b>
            DeadEntryReason.NotABareHostname =>
                "this entry is neither a bare hostname nor a plain IPv6 literal in brackets, "
                + "and host filtering compares the Host header's host part against the entry "
                + "exactly as written, so the two can never be equal — write one plain hostname "
                + "with no port and no stray colons (brackets are only for a plain IPv6 literal "
                + "such as '[::1]'; wrapping anything else in brackets does not make the "
                + "hostname you meant to allow reachable)",

            // <b>いちばん危ない形。</b> 「直せば一致する」と読ませると、直した瞬間に絞り込みが消える
            DeadEntryReason.WildcardOnceRepaired =>
                "this entry does not match as written, and the hostname inside it is a wildcard "
                + "('*', '[::]' or '0.0.0.0') — do NOT just strip the whitespace or the port, "
                + "because the repaired entry would disable host filtering entirely (issue #64). "
                + "Replace it with a real hostname, or delete it",

            // 理由が増えたのに文面を足し忘れたとき（上記のとおり fail-closed）
            _ => FallbackDeadEntryCauseMessage,
        };

    /// <summary>
    /// 専用の説明を持たない理由へ返す既定の文面。
    /// </summary>
    /// <remarks>
    /// <b>テストが「関数を呼ばずに」参照できるよう、名前を付けて公開してある。</b>
    /// 理由は <see cref="FallbackFixAdvice"/> と同じで、既定の文面を
    /// <c>DeadEntryCauseMessage(...)</c> で求めると比較が<b>自分自身との照合</b>になり、
    /// 足し忘れを 1 件も検出しなくなる。
    /// </remarks>
    public const string FallbackDeadEntryCauseMessage =
        "no Host header can ever equal this entry; inspect the entry itself";

    /// <summary>
    /// 目に見えない文字（制御文字と、行区切りとして扱われうる文字）を、ログで読める綴りへ置き換える。
    /// </summary>
    /// <remarks>
    /// <para><b>文字ごとの対応表を持たない。</b> <c>\t</c> / <c>\r</c> / <c>\n</c> だけを
    /// 名前付きにして残りを別扱いにすると、表と実際の文字集合が少しずつずれていく。
    /// コードポイントをそのまま書く形なら、どの文字でも同じ読み方で済む。</para>
    ///
    /// <para><b>綴りは 2 つある（レビュー指摘）。</b> BMP の中は <c>\uXXXX</c>（4 桁）、
    /// BMP の外は <c>\UXXXXXXXX</c>（大文字 U ＋ 8 桁）で、C# / .NET の書き方にそろえてある。
    /// <b>4 桁だけだと思って読み書きしないこと</b> ——たとえば <c>\U000E0001</c> を
    /// 4 桁として解くと <c>\U000E</c> ＋ 文字列 <c>0001</c> になり、
    /// 運用者が読む値を静かに壊す（この仕組み自体が防ごうとしていることと同じ）。</para>
    ///
    /// <para><b>逆斜線そのものも置き換える。</b> そうしないと、値に文字どおり
    /// <c>\u0009</c> と書いた場合と、タブが 1 文字入っている場合が<b>同じ見た目</b>になり、
    /// 運用者は自分の設定のどちらなのかを判別できない。ホスト名に逆斜線が
    /// 正当に現れることは無いので、読みにくくなる実害も無い。</para>
    ///
    /// <para><b>条件は <c>char.IsControl</c> では足りない。</b> 守りたいのは
    /// 「1 本の警告がログ上は複数のレコードに見える」ことを防ぐ点（issue #258）で、
    /// そこで効くのは<b>行区切りとして扱われうるか</b>であって
    /// 「制御文字か」ではない。<c>U+2028</c>（LINE SEPARATOR）と
    /// <c>U+2029</c>（PARAGRAPH SEPARATOR）は<b><c>char.IsControl</c> が <c>false</c></b> なのに、
    /// これらを行の区切りとして扱う処理系が実在する（このリポジトリ自身の
    /// <c>CSharpCommentScanner.SplitLines</c> の docstring が、解析器は
    /// <c>\r\n</c> ・ <c>\r</c> ・ <c>\n</c> に加えて <c>U+0085</c> ・ <c>U+2028</c> ・ <c>U+2029</c> でも
    /// 行を分けると明記している。JSON / JS ベースのログビューアも同じ）。
    /// <b>非対称なのが要点</b>で、同じ役割の <c>U+0085</c>（NEL）は
    /// <c>char.IsControl</c> が <c>true</c> なので以前から置き換えられており、
    /// <c>U+2028</c> / <c>U+2029</c> だけが生のまま載っていた（issue #263）。</para>
    /// </remarks>
    /// <param name="value">可視化したい文字列。</param>
    /// <returns>
    /// 読めない文字を <c>\uXXXX</c>（BMP）または <c>\UXXXXXXXX</c>（それ以外の面）へ、
    /// 逆斜線を <c>\\</c> へ置き換えた文字列。<b>幅は 2 通りある</b> ——
    /// 4 桁固定と読むと、運用者が読む値を静かに壊す（詳しくは remarks）。
    /// </returns>
    private static string MakeInvisibleCharactersVisible(string value)
    {
        // 組み立て先（走り終えて何も置き換えていなければ捨てる）
        var builder = new StringBuilder(value.Length);

        // 1 文字でも置き換えたか（置き換えていなければ元の文字列をそのまま返す）
        var rewritten = false;

        // <b>符号単位ではなくコードポイント単位で見る（レビュー指摘）。</b>
        // 1 文字（char）ずつ見ると、BMP の外にある文字は<b>サロゲートの片割れ</b>として
        // 現れ、カテゴリは必ず Surrogate になる ——Format かどうかを見ても常に外れるので、
        // <c>U+E0001</c>（Unicode Tags。見えない文字を紛れ込ませる代表的な綴り）が
        // 生のまま載っていた。BMP の <c>U+200B</c> だけを直した形のまま、
        // 同じ危険が「char と コードポイントの境目」へ移っていたことになる。
        for (var index = 0; index < value.Length; index++)
        {
            // いま見ている符号単位
            var unit = value[index];

            // 逆斜線は、下の \uXXXX と取り違えられないよう二重にする
            if (unit == Backslash)
            {
                // 二重化する
                builder.Append("\\\\");
                // 置き換えたことを控えて次へ
                rewritten = true;
                continue;
            }

            // 対になったサロゲート（BMP の外の 1 文字）なら、2 符号単位をまとめて見る
            if (char.IsHighSurrogate(unit)
                && index + 1 < value.Length
                && char.IsLowSurrogate(value[index + 1]))
            {
                // 2 つの符号単位から本来の 1 文字を組み立てる
                var rune = new Rune(unit, value[index + 1]);

                // 字として現れないなら 8 桁で、そうでなければそのまま出す
                if (NeedsEscaping(rune))
                {
                    // 8 桁の綴りへ置き換える
                    builder.Append("\\U").Append(rune.Value.ToString("X8"));
                    // 置き換えたことを控える
                    rewritten = true;
                }
                // 読める文字なので 2 符号単位をそのまま出す
                else builder.Append(unit).Append(value[index + 1]);

                // 2 符号単位を消費したので 1 つ余分に進める
                index++;
                continue;
            }

            // <b>対になっていないサロゲートは必ず可視化する。</b> それ自体が不正な綴りで、
            // 描画は環境任せ（多くは空白か置換文字）なので、生で出すと読み手が値を誤解する
            if (char.IsSurrogate(unit))
            {
                // 片割れをそのままコードポイントとして出す
                builder.Append("\\u").Append(((int)unit).ToString("X4"));
                // 置き換えたことを控えて次へ
                rewritten = true;
                continue;
            }

            // ここへ来るのは BMP の普通の 1 文字（サロゲートでないので Rune にできる）
            var single = new Rune(unit);

            // 字として現れないなら 4 桁で、そうでなければそのまま出す
            if (NeedsEscaping(single))
            {
                // 4 桁の綴りへ置き換える
                builder.Append("\\u").Append(((int)unit).ToString("X4"));
                // 置き換えたことを控える
                rewritten = true;
            }
            // 読める文字なのでそのまま出す
            else builder.Append(unit);
        }

        // 1 つも置き換えていないなら、組み立てた綴りは元と同じなので元をそのまま返す
        // （<b>ここが唯一の判定</b>。以前は「置き換えるものがあるか」を先に 1 度見てから
        // 組み立てていたが、条件が 2 か所に分かれるため、片方だけを広げた変更が
        // 「広げたはずの文字が早期 return に拾われて素通りする」向きに壊れうる形だった。
        // しかも 1 文字ずつ見る述語では<b>対になったサロゲートを判断できない</b>ため、
        // 読めるだけの絵文字 1 つで早期 return が必ず外れていた＝レビュー指摘）
        return rewritten ? builder.ToString() : value;
    }

    /// <summary>二重化して出す文字（逆斜線）。</summary>
    /// <remarks>
    /// 名前を付けているのは、組み立てと<b>この docstring の説明</b>が
    /// <b>同じ文字</b>を指していることを読み手に示すため。
    /// </remarks>
    private const char Backslash = '\\';

    /// <summary>
    /// その 1 文字を、生のままログへ載せてはいけないか（＝可視化が要るか）を判定する。
    /// </summary>
    /// <remarks>
    /// <para><b>呼び口は組み立ての 1 か所だけにしてある。</b> 以前は
    /// <see cref="MakeInvisibleCharactersVisible"/> が「置き換えが 1 つでもあるか」を
    /// 先に 1 度見てから組み立てていたため、同じ条件が 2 か所に分かれていた。
    /// 書き写した条件は<b>片方だけを広げた変更</b>で崩れ、そのとき壊れ方は
    /// 「広げたはずの文字が、早期 return に拾われて素通りする」＝
    /// <b>黙って元の挙動へ戻る</b>方向になる（CLAUDE.md §6 DRY）。
    /// いまは組み立てながら「1 つでも置き換えたか」を控えるので、条件はここだけにある。</para>
    ///
    /// <para><b>綴りの表ではなく Unicode のカテゴリで見る。</b> 以前は
    /// <c>char.IsControl</c> ＋ 手で並べた 2 文字（<c>U+2028</c> / <c>U+2029</c>）だったが、
    /// それは「今まで踏んだ分だけの表」で、<b>同じ危険を持つ文字がまだ残っていた</b>
    /// （レビュー指摘。実測で <c>U+200B</c>（幅ゼロ空白）と <c>U+202E</c>（書字方向の上書き）が
    /// 生のまま出ていた）。前者は<b>一致しえない項目を健全な項目と見分けられなくし</b>
    /// （<c>[ ]</c> で囲む意味が消える）、後者は<b>警告の行の残りを逆順に描かせる</b>ので、
    /// 運用者が読む 1 行を別の内容に見せられる ——どちらも issue #263 と同じ種類の危険。
    /// カテゴリで見れば「字として現れないもの」をまとめて捉えられ、
    /// docstring が掲げてきた「文字ごとの対応表を持たない」にも沿う。</para>
    ///
    /// <para><b>私用領域（<c>Co</c>）と未割り当て（<c>Cn</c>）も含める（レビュー指摘）。</b>
    /// どちらも表示がフォント任せで、多くの環境では空白か豆腐になる ——
    /// <c>U+200B</c> を可視化する理由（一致しえない項目を健全な項目と見分けられなくする）が
    /// そのまま当てはまる。ホスト名にこれらが正当に現れることは無いので、代償も無い。</para>
    ///
    /// <para><b>残っている境界: 幅のある空白（<c>U+00A0</c> など <c>Zs</c>）は素通しにしてある。</b>
    /// <c>Zs</c> には普通の空白（<c>U+0020</c>）も含まれるので、カテゴリごと可視化すると
    /// <b>ごく普通の値が読めなくなる</b>。幅のある空白は<b>空白として見える</b>ぶん、
    /// 幅ゼロの文字より危険が小さいと判断している（前後の空白は <c>[ ]</c> の囲みが見せる）。</para>
    /// </remarks>
    /// <param name="ch">判定する 1 文字（符号単位ではなくコードポイント）。</param>
    /// <returns>可視化が要るなら <c>true</c>。</returns>
    private static bool NeedsEscaping(Rune ch) =>
        // 画面・ログに<b>字として現れない</b>カテゴリなら可視化する
        Rune.GetUnicodeCategory(ch)
            is UnicodeCategory.Control        // タブ・CR / LF・NEL など
            or UnicodeCategory.Format         // 幅ゼロの文字（U+200B）や書字方向の上書き（U+202E）
            or UnicodeCategory.LineSeparator  // U+2028
            or UnicodeCategory.ParagraphSeparator  // U+2029
            or UnicodeCategory.PrivateUse          // 私用領域（表示はフォント任せ＝多くは空白か豆腐）
            or UnicodeCategory.OtherNotAssigned;   // 未割り当て（同上）

}
