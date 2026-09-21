// ログ出力(ILogger / LogWarning)に使う
using Microsoft.Extensions.Logging;

// この配線が属する名前空間(AllowedHosts の規則と同じ場所)
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// <c>AllowedHosts</c> の設定値を検査し、運用者向けの警告 2 本を出す。
/// </summary>
/// <remarks>
/// <para><b>なぜ <c>Program.cs</c> から出したのか。</b> この組み立ては
/// <c>if (!IsDevelopment())</c> の中にあり、書いたままだとテストから 1 行も走らない
/// （実測で、いちばん危ない分岐の文面を反対の意味へ差し替えても全件緑のまま通った）。
/// 加えて<b>呼び出し口が 2 つになった</b> ——起動時と、設定の再読み込み時（issue #264）。
/// 2 か所へ書き写すと、片方にだけ理由や文面を足す変更が通ってしまう（CLAUDE.md §6 DRY）。</para>
///
/// <para><b>置き場所は判定と同じフォルダ。</b> 文面の対応表（<c>PermissiveCauseMessage</c> /
/// <c>DeadEntryCauseMessage</c> / <c>DeadEntryFixAdvice</c>）も
/// <see cref="AllowedHostsPolicy"/> にあるので、「規則」と「その伝え方」を離さない。
/// 1 ファイルのために新しいフォルダを作らないのも同じ理由（§6「将来を見越した過度な抽象化を避ける」）。</para>
///
/// <para><b>同じ値で 2 度目以降は黙る。</b> 再読み込みの通知は
/// <c>AllowedHosts</c> が変わっていなくても届く（設定ファイルのどこを直しても鳴り、
/// ファイル監視は 1 度の書き込みで複数回鳴ることがある）。毎回出すと、
/// <b>本当に緩めた瞬間の 1 本</b>が同じ文面の山に埋もれる ——
/// <c>docs/security.md</c> が案内している「この警告が出ていないことを確認する」手順は
/// 件数ではなく有無を見るので、埋もれること自体は誤った安心にはならないが、
/// 「いつ緩んだか」を追えなくする。</para>
/// </remarks>
/// <param name="logger">警告の出力先。</param>
/// <param name="environmentName">
/// 起動している環境の名前。
/// <b>"in Production" と決め打たない</b> ——この警告は <c>!IsDevelopment()</c> で出るので
/// <c>Staging</c> でも鳴り、決め打つと Staging の設定ミスを本番の話と取り違える。
/// </param>
public sealed class AllowedHostsWarningReporter(ILogger logger, string environmentName)
{
    // 複数のスレッドから同時に呼ばれても、判定と記録が食い違わないようにする錠
    // (再読み込みの通知はアプリのスレッドプールから届き、起動時の呼び出しと重なりうる)
    private readonly object _gate = new();

    // 1 度でも評価したか。
    //
    // <b>この旗を外すと、いちばん警告が要る場合だけ黙る。</b> 未設定のまま起動すると
    // allowedHosts は null で、比較対象の初期値も null なので、旗が無いと
    // <b>初回の呼び出しがそのまま「前回と同じ」に当たり 1 本も出ない</b> ——
    // そのとき HostFiltering は ["*"] へ落ちて全許可（issue #64）なので、
    // 「警告が出ていない＝絞れている」という確認手順がそのまま誤った安心になる。
    // 旗を落とす変異は AllowedHostsStartupWarningTests の
    // UnsetValue_StillEmitsThePermissiveWarning が落とす（レビュー指摘。
    // 以前はどのケースも文字列を渡していたので、この不変条件に検出網が無かった）。
    private bool _hasEvaluated;

    // 直近に評価した値(同じ値で鳴り続けないための比較対象)
    private string? _lastEvaluatedValue;

    /// <summary>
    /// 前回と違う値のときだけ、<c>AllowedHosts</c> を検査して警告を出す。
    /// </summary>
    /// <remarks>
    /// <b>初回は必ず評価する。</b> 「前回の値」が無い状態を「同じ」と扱うと、
    /// 未設定（<c>null</c>）のまま起動したときに 1 本も出なくなる ——
    /// それはまさに全許可の状態で、いちばん警告が要る場合。
    /// </remarks>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    public void ReportIfValueChanged(string? allowedHosts)
    {
        // <b>判定・記録・出力をまとめて 1 つの錠の中で行う。</b>
        // 判定と記録だけを守って出力を外へ出すと、値の違う 2 回の評価が<b>出た順と逆に</b>
        // ログへ並びうる（A が "*" を記録した直後に横取りされ、B が実ホスト名を評価して
        // 何も出さず、そのあと A が "*" の警告を書く ——運用者のログでは「もう直した設定」に
        // 対して全許可の警告が最新として残る）。この仕組みの目的は「いつ緩んだか」を
        // 追えることなので、順序が狂うのはそのまま目的を損なう。
        // 出力を錠の中へ入れる代償は、呼ばれるのが起動時と設定の再読み込みだけで、
        // どちらも待たされて困る経路ではないので受け入れられる（レビュー指摘）。
        lock (_gate)
        {
            // 2 回目以降で値が前回と同じなら、何も出さずに戻る
            if (_hasEvaluated && string.Equals(_lastEvaluatedValue, allowedHosts, StringComparison.Ordinal))
            {
                // 前回と同じ値なので、何も出さずに戻る
                return;
            }

            // 次回の比較のために、いま評価する値を覚えておく
            _lastEvaluatedValue = allowedHosts;
            // 以降は「前回の値がある」状態になる
            _hasEvaluated = true;

            // 「絞ったつもりで全部通る」形を拾う(1 本目)
            ReportPermissiveValue(allowedHosts);
            // 「並べたつもりで一部が通らない」形を拾う(2 本目)
            ReportNeverMatchingEntries(allowedHosts);
        }
    }

    /// <summary>
    /// 値が「どの <c>Host</c> でも受け付ける」状態なら、原因を添えて警告する（1 本目）。
    /// </summary>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値。</param>
    private void ReportPermissiveValue(string? allowedHosts)
    {
        // <b>「絞れていない」だけでなく、その原因まで運用者へ渡す。</b>
        // 全許可になる経路は複数あり(1 件も残らない / ワイルドカード / 正規化できない綴り。
        // 正本は PermissiveReason の値そのもので、ここで数えて書くと原因を足したとき
        // この数字だけが古くなる)、以前はどれでも「'*' か '[::]' か '0.0.0.0' を消せ」と
        // 出していた ——値にワイルドカードが 1 つも無い綴り("0.0\t.0.0" のように途中へ
        // 制御文字が紛れた形)では、<b>存在しないものを探させる案内</b>になり、
        // しかも実際の症状(実測では毎リクエストが例外)とも噛み合わない
        var reason = AllowedHostsPolicy.ClassifyPermissive(allowedHosts);

        // 警告に値するかの判断も AllowedHostsPolicy に持たせる ——ここで
        // reason != NotPermissive と書くと規則の写しが 1 つ増え、「警告に値しない原因」を
        // 足したときに片方だけが古い判断のまま残る(IsPermissive の docstring が禁じている形)
        if (!AllowedHostsPolicy.WarrantsWarning(reason)) return;

        // 運用者が気づけるよう Warning レベルで通知する
        logger.LogWarning(
            "AllowedHosts is permissive in the {Environment} environment " +
            "(current value: {AllowedHosts}). {Cause} " +
            "Set it to the real hostname(s) via the AllowedHosts setting or environment " +
            "variable (semicolon-separated) to prevent Host-header spoofing, especially " +
            "behind a reverse proxy (issue #64).",
            // 環境名を載せる。<b>こちらも生のままでは載せない</b> ——環境名は
            // ASPNETCORE_ENVIRONMENT 由来＝AllowedHosts とまったく同じ
            // 「運用者が設定する外部の文字列」で、同じテンプレート展開や
            // コピー & ペーストで行区切りが紛れうる(issue #258 / #263)
            AllowedHostsPolicy.DescribeValueForLog(environmentName),
            // 値を載せる ——"0.0.0.0" を書いた運用者が自分の設定だと気づけるように
            // (AllowedHosts は秘密情報ではなく、配備先のホスト名そのもの)。
            // <b>生のままでは載せない。</b> UnparsableEntry という分類がある時点でこの値には
            // 制御文字が入りうるので、行区切りが混ざると 1 本の警告がログ上は複数の
            // レコードに見える ——docs/security.md が案内する「警告が出ていないことの確認」が
            // 偽の継続行で破れ、ログの収集・解析がまさにその設定ミスのときに壊れる。
            // 可視化の規則は AllowedHostsPolicy に置く(2 本の警告で書き写さないため)
            AllowedHostsPolicy.DescribeValueForLog(allowedHosts),
            // その設定に合った原因の説明(直し方は原因によらず同じなので次の文で共通)
            AllowedHostsPolicy.PermissiveCauseMessage(reason));
    }

    /// <summary>
    /// どの <c>Host</c> とも一致しえない項目があれば、項目ごとの理由を添えて警告する（2 本目）。
    /// </summary>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値。</param>
    private void ReportNeverMatchingEntries(string? allowedHosts)
    {
        // 上の警告の<b>裏返し</b>を拾う。あちらは「絞ったつもりで全部通る」形しか見ないので、
        // 「並べたつもりで一部が通らない」形は素通りする ——踏みやすいのは区切りのうしろに
        // 空白を入れた複数指定 "a.example.test; b.example.test" で、一覧を書くときの自然な形。
        // フレームワークは項目をトリムしないため 2 件目はどの Host とも一致せず、実測では
        // 1 件目が 200・2 件目が 400 になる。つまり<b>サイトは生きたまま特定のホスト名だけが
        // 静かに落ちる</b>ので、監視にもヘルスチェックにも出ない。しかも IsPermissive は
        // 正しく false を返すため、docs/security.md が案内する「警告が出ていないことの確認」が
        // そのまま誤った安心になる。
        // <b>名指しする項目と直し方は 1 本の呼び出しで受け取る。</b> 別々に呼ぶと、同じ値を
        // 2 度割って同じ正規化を 2 周するうえ、両者が同じ項目を見ていることを保証するものが
        // 無くなる(判定の条件を片方にだけ足す変更が通ってしまう)
        var (neverMatching, deletionOutcome) =
            AllowedHostsPolicy.InspectNeverMatchingEntries(allowedHosts);

        // 一致しえない項目が 1 つも無ければ、知らせることは無い
        if (neverMatching.Count == 0) return;

        // <b>直し方の案内は、消したときに何が起きるかで変える。</b> 死んだ項目を消したあと、
        // 残る一覧がどの Host でも受け付ける状態になるなら「消す」は直し方ではない
        // (400 が止まるので直ったように見えるが、実際は issue #64 へ移るだけ)
        var howToFix = AllowedHostsPolicy.DeadEntryFixAdvice(deletionOutcome);

        // 上の警告とは原因も対処も違うので、別のメッセージとして出す
        // (同じ文面にまとめると「全許可」と「一部だけ全拒否」を取り違える)。
        // <b>理由は項目ごとに添える（1 文にまとめない）。</b> 一致しえない理由は 1 つではなく、
        // 混在した一覧で 1 つの文面しか出せないと<b>どの項目がなぜ落ちているか</b>を追えない。
        // しかも文面を 1 つに決め打つと、理由を足した瞬間にその文が<b>名指しした項目について
        // 事実と違うこと</b>を言い出す（実際この行は「これらの項目は前後に空白が残っている」と
        // 断定していた。issue #256）
        logger.LogWarning(
            "AllowedHosts contains {Count} entry/entries that can never match any Host header " +
            "in the {Environment} environment: {NeverMatchingEntries}. {HowToFix} (issue #64).",
            // 何件あるかを先に出す ——値が長いときでも件数だけは読める
            neverMatching.Count,
            // どの環境の話かを添える(可視化を通す理由も上の警告と同じ)
            AllowedHostsPolicy.DescribeValueForLog(environmentName),
            // 死んでいる項目を "[ ]" で囲んで並べる ——空白は目で見えないので、
            // 囲まないと「なぜこれが一致しないのか」が運用者に伝わらない
            AllowedHostsPolicy.DescribeEntriesForLog(neverMatching),
            // その設定に合った直し方(消してよいかどうかで文面が変わる)
            howToFix);
    }
}
