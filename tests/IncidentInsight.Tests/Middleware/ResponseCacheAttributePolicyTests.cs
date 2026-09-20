// 走査と判定の共通処理を使う
using IncidentInsight.Tests.Helpers;
// 綴りの表を名前ではなく宣言から導くために反射を使う
using System.Reflection;
// ResponseCacheAttribute / ResponseCacheLocation / ControllerBase を使う
using Microsoft.AspNetCore.Mvc;

// 既存の Middleware 配下テストと同じ名前空間に置く
namespace IncidentInsight.Tests.Middleware;

/// <summary>
/// アプリのアクションが<b>キャッシュ可能な</b> <c>[ResponseCache]</c> を名乗っていないことを、
/// アプリ全体から導出して固定する検査。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(この検査が塞ぐ fail-open)。</b>
/// <c>SecurityHeadersMiddleware</c> は「誰もキャッシュ指示を書いていない応答」にだけ
/// <c>no-store</c> を入れ、<b>既に指示がある応答には一切触れない</b>。それは静的アセットを
/// キャッシュ可能なまま残すための唯一の仕組みなので、この「譲る」挙動自体は正しい。
/// ところが譲る相手は<b>指示の中身を問わない</b>ため、PHI を返すアクションへ
/// <c>[ResponseCache(Duration = 300, Location = ResponseCacheLocation.Any)]</c> を
/// 足すだけで、そのアクションの応答は <c>public,max-age=300</c> で返る ——
/// 社内リバースプロキシが保存し、ある職員の集計を別の職員へ配りうる状態になる。
/// これは「遅い集計を速くする」ごく自然な最適化として書かれうるうえ、
/// <b>実測でアプリ全体のテストが緑のまま通った</b>(<c>AnalyticsController.ByCause</c> に
/// 上記の属性を足して確認した)。</para>
///
/// <para><b>なぜミドルウェア側を直さないのか。</b> 「制限の緩い指示は上書きする」形にすると、
/// 静的アセットの <c>public,max-age=3600</c> まで潰れる ——
/// <c>SecurityHeadersMiddleware.StaticAssetCacheControl</c> がまさにその値で、
/// 譲る挙動が消えた瞬間に css/js が毎回再取得になる(§8)。実際に危ないのは
/// <b>MVC のアクションが名乗る指示</b>だけなので、そこだけを宣言の形で禁じる。</para>
///
/// <para><b>指示は属性の宣言以外からも来る。</b> 口は 3 つあり、担当が分かれている:</para>
/// <list type="number">
///   <item><description><b>属性の宣言</b>(このクラス)。</description></item>
///   <item><description><b><c>MvcOptions.Filters</c> のグローバルフィルタと
///     <c>MvcOptions.CacheProfiles</c></b> ——どちらも属性のソースには現れない。
///     起動したアプリの設定を読む <c>ResponseCacheHeaderIntegrationTests</c> が、
///     <b>同じ判定関数</b>(<see cref="ResponseCachePolicy.Judge(ResponseCacheAttribute)"/>)で見る。
///     </description></item>
///   <item><description><b>応答ヘッダーへの直接の書き込み</b>
///     (<c>Response.Headers.CacheControl = "public,max-age=300";</c>)——
///     属性も設定も通らないので上の 2 つには映らない。
///     <see cref="OnlyIntendedWriters_SetCacheControlDirectly"/> が落とす。
///     <b>実測</b>: この 1 行を <c>AnalyticsController.ByCause</c> の先頭へ足すと、
///     PHI の集計 JSON が <c>public,max-age=300</c> で返るのに 878 件すべて緑のまま通った。
///     </description></item>
///   <item><description><b>サーバー側の出力キャッシュ</b>(<c>[OutputCache]</c> ＋
///     <c>UseOutputCache</c>)——これは上の 3 つと<b>性質が違う</b>。
///     応答を<b>サーバーのメモリに溜めて別の利用者へ配る</b>仕組みで、既定のポリシーは
///     パスとクエリだけをキーにし、認証は <c>Authorization</c> ヘッダーしか見ない
///     (クッキー認証のこのアプリでは「認証済みだから除外」が効かない)。しかも
///     <b>応答側の <c>no-store</c> を尊重しない</b>ので、ミドルウェアの既定では止められない。
///     職員 A の集計が職員 B へそのまま返るため、このアプリでは<b>使用そのものを禁じる</b>
///     (<see cref="NoActionEnablesServerSideOutputCaching"/>)。
///     </description></item>
/// </list>
///
/// <para><b>直接の書き込みは Web プロジェクト全体を見る</b>(<c>.cs</c> と <c>.cshtml</c>)。
/// 以前はコントローラとビューのパスで絞っていたが、その外に置いた同じコード
/// (<c>Pages/</c> のビュー、別フォルダの <c>partial class</c>)が素通りしたため、
/// 走査を全体へ広げ、<b>意図して書く 2 か所だけ</b>を理由付きの許可表
/// <see cref="IntendedCacheControlWriters"/> に置く形へ変えた。</para>
///
/// <para><b>残っている境界。</b> その許可表は人が判断するエスケープハッチで、
/// 「その場所が本当に書いてよいか」は機械では決められない。エントリが増える差分は
/// レビューで理由の妥当性を必ず確認すること(§6 のエスケープハッチと同じ扱い)。</para>
///
/// <para><b>導出で作る(表を書かない)。</b> 「見るべきアクションの一覧」を手で持つと、
/// 新しいコントローラを足した人が載せ忘れた時点でその画面だけ黙って検査から外れる。
/// 対象は <see cref="AppControllerScan.CacheDirectiveHosts"/> から導く ——
/// <b>基底型で絞らない</b>のが要点で、<c>[ResponseCache]</c> は <c>ControllerBase</c> 専用では
/// なく <c>PageModel</c>(Razor Pages)でも同じように効く。<c>ControllerBase</c> で絞っていた頃は
/// <c>Pages/Export.cshtml.cs</c> に <c>[ResponseCache(Duration = 300, Location = Any)]</c> を
/// 付けた PHI のページが<b>どの検査からも見えなかった</b> ——属性名にはヘッダー名の綴りが
/// 無いので、ソースを見る側の走査でも拾えない。
/// <b>ここで絞り込みを書き写さない</b>のは、写した瞬間にこのファイルだけが
/// 導出のガードの射程から外れるため(コントローラ側の導出
/// <see cref="AppControllerScan.Controllers"/> が狭まっていないことは、独立な手がかり
/// (ソースファイルの実在)で照合する
/// <c>UnlistedFilterValuePolicyTests.ControllerScan_ReachesEveryControllerFile</c> が見張る)。</para>
/// </remarks>
public class ResponseCacheAttributePolicyTests
{
    // アプリ全体のアクションが名乗る [ResponseCache] は、すべてキャッシュ保存を禁じていること。
    //
    // これが落ちたときの直し方は 2 つだけ: (a) その属性へ NoStore = true を付ける、
    // (b) そもそも属性を外して既定の no-store に任せる。
    // 「キャッシュさせたい」場合は、その応答が PHI を含まないことを確かめたうえで
    // この検査の規則そのものを更新する(黙って除外を足さない)。
    [Fact]
    public void EveryResponseCacheAttributeInTheApp_SuppressesStorage()
    {
        // アプリ全体の宣言を集める
        var declarations = ResponseCachePolicy
            .DeclarationsOn(AppControllerScan.CacheDirectiveHosts(), AppControllerScan.WebAssembly)
            .ToList();

        // 規則に反している宣言だけを、失敗文言の形に整えて取り出す
        var violations = declarations
            // 各宣言について、名乗っている内容が保存を禁じているかを判定する
            .Select(declaration => (declaration, verdict: ResponseCachePolicy.Judge(declaration.Attribute)))
            // 禁じていないものだけを残す
            .Where(pair => !pair.verdict.IsSuppressing)
            // 「どこに付いた、どういう宣言が、なぜ駄目か」を 1 行にまとめる
            .Select(pair => $"{pair.declaration.DeclaredOn}: {pair.verdict.Reason}")
            .ToList();

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "PHI を返しうるアクションがキャッシュ可能な [ResponseCache] を名乗っています。"
                + "SecurityHeadersMiddleware は既に指示がある応答へは一切触れないため、"
                + "この宣言はそのまま共有キャッシュへの保存許可になります。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 判定そのものが、許す側と落とす側の両方で意図どおりに働くこと。
    //
    // <b>なぜ合成入力で固定するのか。</b> 上の検査はアプリの実際の宣言を読むので、
    // 実在する [ResponseCache] がたまたま 1 件(HomeController.Error)で、それが
    // NoStore = true である限り、<b>判定を「常に true」へ潰しても全件緑のまま</b>になる。
    // 実際の配線が準拠していることと、判定が正しいことは別なので、ここで後者を固定する。
    [Theory]
    // NoStore を宣言していれば許す(このアプリで唯一正しい書き方)
    [InlineData(true, 0, ResponseCacheLocation.None, null, true)]
    // 期間や場所を添えていても、NoStore があれば保存は禁じられる
    [InlineData(true, 300, ResponseCacheLocation.Any, null, true)]
    // 共有キャッシュへの保存を許す形は落とす(実測でこの形が素通りしていた)
    [InlineData(false, 300, ResponseCacheLocation.Any, null, false)]
    // ブラウザだけの保存(private)も、共用端末のディスクに PHI を残すので落とす
    [InlineData(false, 300, ResponseCacheLocation.Client, null, false)]
    // 期間 0 でも NoStore が無ければ「保存してよいが毎回検証せよ」でしかないので落とす
    [InlineData(false, 0, ResponseCacheLocation.None, null, false)]
    // キャッシュプロファイル名での指定は、属性自身のフィールドから中身を読めないので落とす
    [InlineData(true, 0, ResponseCacheLocation.None, "NoCache", false)]
    public void Judge_AllowsOnlyStorageSuppressingDeclarations(
        bool noStore,
        int duration,
        ResponseCacheLocation location,
        string? cacheProfileName,
        bool expectedIsSuppressing)
    {
        // 与えられた内容の属性を組み立てる
        var attribute = new ResponseCacheAttribute
        {
            // 保存を禁じるかどうか
            NoStore = noStore,
            // キャッシュしてよい秒数
            Duration = duration,
            // どの層でのキャッシュを許すか
            Location = location,
            // 設定ファイル側のプロファイル名(使っていれば非 null)
            CacheProfileName = cacheProfileName,
        };

        // 判定を実行する
        var verdict = ResponseCachePolicy.Judge(attribute);

        // 期待どおりの可否になっていることを確認する
        Assert.Equal(expectedIsSuppressing, verdict.IsSuppressing);
        // 落とす場合は理由が空でないこと(失敗文言が「何が駄目か」を伝えられること)
        if (!expectedIsSuppressing)
        {
            // 理由が空だと、落ちたときに直し方が分からない
            Assert.False(string.IsNullOrWhiteSpace(verdict.Reason));
        }
    }

    // 走査が、クラスに付いた属性とアクションに付いた属性の<b>両方</b>を拾うこと。
    //
    // <b>なぜ要るのか。</b> アプリの実際の宣言はアクション側に 1 件だけなので、
    // クラス側を見る行を消しても上の検査は全件緑のまま通る。[ResponseCache] は
    // コントローラ全体にも付けられる(その場合は全アクションに効く)ので、
    // 拾い漏らすとコントローラ 1 つ分がまるごと検査から外れる。
    [Fact]
    public void DeclarationScan_ReadsBothClassAndActionAttributes()
    {
        // クラス側とアクション側の両方に属性を持つ合成コントローラを走査する
        var declarations = ScanProbes(typeof(BothLevelsProbeController));

        // クラス側の宣言(Duration = 11)が拾えていること
        Assert.Contains(declarations, d => d.Attribute.Duration == 11);
        // アクション側の宣言(Duration = 22)が拾えていること
        Assert.Contains(declarations, d => d.Attribute.Duration == 22);
        // どこに付いていたかが失敗文言のために保持されていること
        Assert.All(declarations, d => Assert.False(string.IsNullOrWhiteSpace(d.DeclaredOn)));
    }

    // 走査が、<b>抽象基底へ引き上げたアクション</b>に付いた属性も拾うこと。
    //
    // <b>なぜ要るのか(実測した fail-open)。</b> アクションの絞り込みを
    // 「その型が宣言したメソッドか」(DeclaringType != controller で弾く)で書くと、
    // 抽象基底に置いたアクションはどこからも見えなくなる ——
    // 基底は抽象なので走査対象に入らず、具象の側では宣言元が基底なので弾かれるため。
    // それでも URL としては具象コントローラ経由で<b>実際に到達できる</b>。
    // 実測では、その形で [ResponseCache(Duration = 300, Location = Any)] を足すと
    // 全件緑のまま、<b>テスト件数すら変わらずに</b>通った。
    [Fact]
    public void DeclarationScan_ReadsActionsPulledUpToAnAbstractBase()
    {
        // 抽象基底にアクションを持つ具象コントローラだけを走査する(基底は抽象なので対象外)
        var declarations = ScanProbes(typeof(InheritedActionProbeController));

        // 基底に宣言されたアクションの属性(Duration = 33)が拾えていること
        Assert.Contains(declarations, d => d.Attribute.Duration == 33);
        // 「どこを直せばよいか」が分かるよう、宣言元の基底の名前で名指しされていること
        Assert.Contains(
            declarations,
            d => d.DeclaredOn.Contains(nameof(InheritedActionProbeControllerBase), StringComparison.Ordinal));
    }

    // 同じ基底のアクションを複数の具象が継承していても、宣言は 1 件に畳まれること。
    //
    // 畳まないと、基底のアクション 1 つに対して派生の数だけ同じ失敗文言が並び、
    // 「何か所直せばよいのか」が読めなくなる(直す場所は基底の 1 か所だけ)。
    [Fact]
    public void DeclarationScan_ReportsAnInheritedActionOnlyOnce()
    {
        // 同じ基底を継承する 2 つの具象コントローラを走査する
        var declarations = ScanProbes(
            typeof(InheritedActionProbeController),
            typeof(SecondInheritedActionProbeController));

        // 基底のアクションに由来する宣言が 1 件だけであること
        Assert.Single(declarations, d => d.Attribute.Duration == 33);
    }

    /// <summary>
    /// 意図して <c>Cache-Control</c> を書く 1 行ぶんの登録内容。
    /// </summary>
    /// <param name="ExpectedCount">
    /// その行がそのファイルに現れてよい回数。<b>複製を「回数が合わない」として落とすためだけに持つ</b>
    /// （内容の一致だけで許すと、共有定数を再利用したコピーが素通りする）。
    /// </param>
    /// <param name="Reason">なぜその行が書いてよいのかの説明（空文字・空白は別の検査が落とす）。</param>
    private readonly record struct IntendedWrite(int ExpectedCount, string Reason);

    /// <summary>
    /// <c>Cache-Control</c> を<b>意図して</b>書いてよい行
    /// （ファイル × その行の内容 × 期待する出現回数の許可表）。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ「書いてよい場所」を列挙する形にしたのか。</b> 最初は
    /// 「コントローラとビューだけを走査する」形にしていたが、走査対象をパスの形
    /// （<c>Controllers/</c> ・ <c>Views/</c>）で当てる限り、その外に置いた同じコードが
    /// 素通りする ——<c>Pages/</c> のビューも、別フォルダに置いた
    /// <c>partial class AnalyticsController</c> も落ちなかった（実測）。
    /// <see cref="RepositoryPaths.EnumerateViewFiles"/> の docstring が、まさに同じ
    /// 「<c>Views/</c> 配下だけに絞ると <c>Pages/</c> が静かに外れる」事故を記録している。</para>
    ///
    /// <para><b>だから走査は Web プロジェクト全体にし、例外だけを表に置く。</b>
    /// 表が小さく、理由を持ち、増える差分が必ず 1 行として現れるなら、
    /// パスの形を当て続けるより安全側に倒れる。<b>この表にエントリが増える差分は、
    /// 理由の妥当性をレビューで必ず確認すること</b>（§6 のエスケープハッチと同じ扱い。
    /// 「絞り込みを狭める」変更は差分にもテスト件数にも現れないが、
    /// 表への 1 行は必ず現れる）。</para>
    ///
    /// <para><b>除外はファイル単位ではなく「その行の内容」と「出現回数」まで見る。</b>
    /// ファイルごと外すと、許可した 2 つの書き込み以外も同じファイルの中では自由になる ——
    /// たとえば <c>Program.cs</c> へ 2 つ目の <c>UseStaticFiles</c>（<c>wwwroot</c> の外を
    /// <c>/attachments</c> として配り、<c>public,max-age=86400</c> を名乗る）を足すと、
    /// この検査も <see cref="StaticAssets_AreOnlyApprovedPublicAssets"/>（<c>wwwroot</c> の外は
    /// 見ない）も素通りする。</para>
    ///
    /// <para><b>行の内容だけでは足りない（ここが要点）。</b> 以前この解説は「行の内容まで表に
    /// 持てば必ず止まる」と書いていたが、<b>成り立つのは 2 つ目が別の綴りを使った場合だけ</b>
    /// だった。2 つ目の <c>UseStaticFiles</c> が共有定数
    /// （<c>SecurityHeadersMiddleware.StaticAssetCacheControl</c>）を再利用すると行が一字一句
    /// 同じになり、<c>ContainsKey</c> での照合はそのまま通る ——しかも定数の再利用は §6 が
    /// 積極的に要求している書き方で、既存ブロックのコピーでも自然にそうなる。
    /// 結果として <c>/attachments/&lt;id&gt;/report.pdf</c> が <c>public,max-age=3600</c> で返り、
    /// 共有プロキシと共用端末のディスクに PHI が 1 時間残る差分が<b>全件緑で通っていた</b>。
    /// そこで表は<b>期待する出現回数</b>（現状はすべて 1 回）まで持ち、
    /// 多くても少なくても落とす。複製は必ず「回数が合わない」として現れる。</para>
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IntendedWrite>>
        IntendedCacheControlWriters =
        new Dictionary<string, IReadOnlyDictionary<string, IntendedWrite>>(StringComparer.Ordinal)
        {
            // 既定値(誰も書かなかった応答へ no-store を入れる)を書く唯一の場所
            [Path.Combine("Middleware", "SecurityHeadersMiddleware.cs")] =
                new Dictionary<string, IntendedWrite>(StringComparer.Ordinal)
                {
                    // 既定値そのものの定数
                    ["public const string NoStoreCacheControl = \"no-store\";"] =
                        new IntendedWrite(1, "キャッシュ抑止の既定値そのもの。"),
                    // 静的アセット用の指示の定数(値の正本)
                    ["public const string StaticAssetCacheControl = \"public,max-age=3600\";"] =
                        new IntendedWrite(1, "静的アセット用の指示の値の正本。docs/security.md と突き合わせている。"),
                    // 既定値を入れるコールバック
                    ["private static readonly Func<object, Task> ApplyDefaultCacheControl = state =>"] =
                        new IntendedWrite(1, "既定値を入れる OnStarting コールバックの宣言。"),
                    // 既に指示があるかの判定
                    ["if (StringValues.IsNullOrEmpty(response.Headers.CacheControl))"] =
                        new IntendedWrite(1, "誰かが既に書いているかを見る判定(書き込みではない)。"),
                    // 既定値の書き込み
                    ["response.Headers.CacheControl = NoStoreCacheControl;"] =
                        new IntendedWrite(1, "誰も書かなかった応答へ既定の no-store を入れる、唯一の書き込み。"),
                    // コールバックの登録
                    ["context.Response.OnStarting(ApplyDefaultCacheControl, context.Response);"] =
                        new IntendedWrite(1, "上のコールバックを応答開始前に登録する。"),
                },
            // 静的アセットが既定の対象から外れるための自己申告を書く場所
            ["Program.cs"] =
                new Dictionary<string, IntendedWrite>(StringComparer.Ordinal)
                {
                    // 静的ファイル配信の自己申告
                    ["ctx.Context.Response.Headers.CacheControl = SecurityHeadersMiddleware.StaticAssetCacheControl;"] =
                        new IntendedWrite(
                            1,
                            "UseStaticFiles の OnPrepareResponse が静的アセット用の指示を名乗る。"
                                + "これが無いと css/js が no-store になり毎回再取得になる(§8)。"),
                },
        };

    // 意図した 2 か所以外が Cache-Control を直接書いていないこと。
    //
    // <b>なぜ属性と MvcOptions だけでは足りないのか。</b> 応答ヘッダーは素直に書ける:
    //   Response.Headers.CacheControl = "public,max-age=300";
    // これは属性のソースにも MvcOptions にも現れないので、上の 2 つの検査には映らない。
    // 一方 SecurityHeadersMiddleware は「既に指示がある」ので触れず、PHI がそのまま
    // 共有キャッシュへ保存可能になる。実測でも、この 1 行を AnalyticsController.ByCause の
    // 先頭へ足すと 878 件すべて緑のまま通った。
    //
    // <b>手がかりはソースの実在</b>(型の走査ではない)。書き込みは実行時の 1 文なので、
    // リフレクションでは原理的に見えない。
    [Fact]
    public void OnlyIntendedWriters_SetCacheControlDirectly()
    {
        // 直接書き込みが見つかったファイルと行を集める
        var violations = new List<string>();

        // Web プロジェクト配下のソース(.cs と .cshtml)をすべて見る
        foreach (var sourcePath in ScannedSources())
        {
            // 許可表と突き合わせるためのキー(Web プロジェクトからの相対パス)
            var tableKey = Path.GetRelativePath(RepositoryPaths.WebProject, sourcePath);
            // そのファイルに許可された行(無ければ null＝どの行も許可されない)
            IntendedCacheControlWriters.TryGetValue(tableKey, out var allowedLines);
            // 許可した行が実際に何回現れたかを数える(複製を「回数が合わない」として落とすため)
            var seenCounts = new Dictionary<string, int>(StringComparer.Ordinal);

            // コメントを取り除いたうえで、ヘッダー名を含む行を探す
            foreach (var (lineNumber, text, code) in CodeLines(sourcePath))
            {
                // 実コードがヘッダー名を含まない行は関係ない
                if (!CacheControlTokens.Any(t => code.Contains(t, StringComparison.OrdinalIgnoreCase))) continue;

                // <b>突き合わせるのは「コメントを取り除いた実コード」。</b>
                // 元の行で照合すると、§5 が明示的に許している行末コメントを
                // 許可済みの行へ足しただけで「表に無い行」と「回数が 0 回」と
                // 「許可表の行が実在しない」が同時に出て、原因が読み取れなくなる
                if (allowedLines is not null && allowedLines.ContainsKey(code))
                {
                    // その行の出現回数を 1 つ増やす
                    seenCounts[code] = seenCounts.GetValueOrDefault(code) + 1;
                    // 数えたので、この行は違反として記録しない
                    continue;
                }

                // リポジトリからの相対パスと行番号で名指しする(見せるのは元の行)
                violations.Add($"{Path.GetRelativePath(RepositoryPaths.Root, sourcePath)}:{lineNumber}: {text}");
            }

            // 許可表を持たないファイルは、ここで数え合わせるものが無い
            if (allowedLines is null) continue;

            // <b>回数まで突き合わせる。</b> 内容の一致だけで許すと、共有定数を再利用した
            // 2 つ目の UseStaticFiles が一字一句同じ行になって素通りする(解説を参照)
            foreach (var (allowedLine, intended) in allowedLines)
            {
                // 実際に現れた回数(1 度も現れなければ 0)
                var actual = seenCounts.GetValueOrDefault(allowedLine);
                // 期待どおりなら何もしない
                if (actual == intended.ExpectedCount) continue;
                // 多くても少なくても落とす(複製も、消し忘れた許可も、どちらも表の更新が要る)
                violations.Add(
                    $"{Path.GetRelativePath(RepositoryPaths.Root, sourcePath)}: "
                        + $"許可した行の出現回数が {intended.ExpectedCount} 回ではなく {actual} 回です: {allowedLine}");
            }
        }

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "意図した 2 か所以外が Cache-Control を直接書いています。"
                + "SecurityHeadersMiddleware は既に指示がある応答へは触れないため、"
                + "この 1 行がそのままキャッシュ保存の許可になります。"
                + "キャッシュを抑止したいだけなら何も書かずに既定(no-store)へ任せ、"
                + "本当に許可したいなら PHI を含まないことを確かめたうえでこの規則を更新してください。"
                + "「出現回数が … 回ではなく … 回です」と出ている場合は、許可済みの行が複製されています"
                + "(2 つ目の静的ファイル配信など)。複製先が PHI を配らないことを確かめたうえで、"
                + "許可表の ExpectedCount を実際の回数へ直してください。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 走査が「見るべき対象ゼロ＝緑」で無力化されていないこと(fail-closed)。
    //
    // 上の検査は違反が 0 件なら緑になるので、絞り込みが 1 ファイルも拾えなくなる変異
    // (拡張子の条件を間違える・列挙の根を狭めすぎる)は、そのままでは気付けない。
    [Fact]
    public void CacheControlSourceScan_SeesBothCodeAndViews()
    {
        // 走査が実際に見ているファイルを取り出す
        var scanned = ScannedSources().ToList();

        // C# のソースが拾えていること
        Assert.Contains(scanned, p => Path.GetExtension(p).Equals(".cs", StringComparison.OrdinalIgnoreCase));
        // <b>ビューのソースも拾えていること。</b> 以前は *.cs だけを列挙していたため、
        // Views 配下に .cs が 1 つも無いこのリポジトリでは「ビューを見る」条件が
        // 一度も成立せず、走査が死んでいた(実測: ビューへ直接書き込みを足しても全件緑)。
        // 「件数が 0 でないこと」だけでは、C# が拾えている限り緑になるので気付けない
        Assert.Contains(scanned, p => Path.GetExtension(p).Equals(".cshtml", StringComparison.OrdinalIgnoreCase));
    }

    // 許可表のエントリが、実在するファイルを指し、理由を持っていること。
    //
    // 表そのものは人が判断するエスケープハッチなので、せめて (a) 綴りが実在すること
    // (実在しないパスは「除外したつもり」を作り、その場所を黙って検査対象へ戻す)、
    // (b) 理由が空でないこと(値を誰も読んでいないと、空白を入れるだけで黙らせられる)
    // は機械的に固定する。
    [Fact]
    public void IntendedCacheControlWriters_AreAllRealAndExplained()
    {
        // 表のエントリを 1 つずつ確かめる
        foreach (var (relativePath, allowedLines) in IntendedCacheControlWriters)
        {
            // Web プロジェクトからの相対パスとして実在すること
            var fullPath = Path.Combine(RepositoryPaths.WebProject, relativePath);
            Assert.True(
                File.Exists(fullPath),
                $"許可表が実在しないファイルを指しています: {relativePath}。"
                    + "移動・改名したなら、この表も同じ変更セットで直してください"
                    + "(実在しないエントリは「除外したつもり」を作ります)。");

            // そのファイルの中身を読んで、許可した行が実在するかを確かめる。
            // <b>本体の照合と同じ「コメントを取り除いた実コード」で見る</b> ——
            // ここだけ元の行で見ると、行末コメントを足したときにこのテストだけが
            // 別の理由（「許可表の行が実在しません」）で落ち、原因の切り分けを妨げる
            var actualLines = CodeLines(fullPath).Select(l => l.Code).ToHashSet(StringComparer.Ordinal);
            // 許可した行を 1 つずつ確かめる
            foreach (var (allowedLine, intended) in allowedLines)
            {
                // その行が実在すること(実在しない許可は「除外したつもり」を作る)
                Assert.True(
                    actualLines.Contains(allowedLine),
                    $"許可表の行が {relativePath} に実在しません: {allowedLine}。"
                        + "書き換えたなら、この表も同じ変更セットで直してください。");
                // 理由が空でも空白だけでもないこと
                Assert.False(
                    string.IsNullOrWhiteSpace(intended.Reason),
                    $"許可表のエントリに理由がありません: {relativePath} / {allowedLine}。");
                // <b>回数が 1 以上であること。</b> 0 を登録できると「実在するのに 1 度も許可されない」
                // 表になり、負の値は本体の数え合わせが決して満たせない要求になる
                Assert.True(
                    intended.ExpectedCount >= 1,
                    $"許可表の ExpectedCount は 1 以上にしてください: {relativePath} / {allowedLine} "
                        + $"(いまは {intended.ExpectedCount})。書かなくてよい行なら表から削ってください。");
                // <b>その行自体がヘッダー名を含んでいること。</b> 含まない行を登録すると、
                // 本体の走査はその行に辿り着けないまま「0 回」と報告する一方、
                // この検査は「実在する」と言う —— 原因が読み取れない矛盾した組になる
                Assert.True(
                    CacheControlTokens.Any(t => allowedLine.Contains(t, StringComparison.OrdinalIgnoreCase)),
                    $"許可表の行がヘッダー名を含んでいません: {relativePath} / {allowedLine}。"
                        + "この走査が拾うのはヘッダー名を含む行だけなので、"
                        + "含まない行を登録しても「0 回」としか報告されません。");
            }
        }
    }

    // サーバー側の出力キャッシュ([OutputCache])を、どのアクションも使っていないこと。
    //
    // <b>なぜ Cache-Control の検査では止まらないのか。</b> 出力キャッシュは応答を
    // サーバーのメモリに溜めて別の利用者へ配る仕組みで、応答ヘッダーの no-store を
    // 尊重しない。既定のポリシーはパスとクエリだけをキーにし、認証は Authorization
    // ヘッダーしか見ないので、クッキー認証のこのアプリでは「認証済みだから除外」も効かない。
    // 結果として職員 A の PHI 集計が職員 B へそのまま返る。
    //
    // <b>属性は型名で照合する</b>(型を直接参照しない)。参照すると、この検査を通すために
    // テストプロジェクトが出力キャッシュのパッケージへ依存することになり、
    // 「禁じたい機能を自分で引き込む」形になる。
    [Fact]
    public void NoActionEnablesServerSideOutputCaching()
    {
        // 共有の走査へ「出力キャッシュの属性であること」を渡して宣言を集める
        // (クラス側とアクション側の両方を読む・宣言元で名指しする・派生の数だけ並べない、
        //  という手当ては走査側が持っている。ここに書き写すと片方だけ古くなる)
        var violations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                AppControllerScan.CacheDirectiveHosts(),
                AppControllerScan.WebAssembly,
                IsOutputCacheAttribute)
            .Select(d => d.DeclaredOn)
            .ToList();

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "サーバー側の出力キャッシュ([OutputCache])が使われています。"
                + "出力キャッシュは応答をサーバーに溜めて別の利用者へ配る仕組みで、"
                + "応答側の no-store を尊重せず、既定のポリシーはクッキー認証を見ません。"
                + "PHI を返すアプリでは職員間の取り違えに直結するため、このアプリでは使いません。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 出力キャッシュが<b>全体の配線</b>としても入っていないこと。
    //
    // <b>なぜ属性の走査だけでは足りないのか。</b> 出力キャッシュは属性を 1 つも書かずに
    // 有効化できる: AddOutputCache(o => o.AddBasePolicy(...)) と UseOutputCache() を足せば
    // 既定ポリシーが全エンドポイントへ効き、エンドポイント単位の CacheOutput() でも入る。
    // どちらも属性として現れないので上の検査には映らず、Cache-Control の走査にも
    // 引っかからない(その文字列を含まないうえ、Program.cs は許可表に載っている)。
    // <b>この検査には許可表を置かない</b> ——このアプリに「ここでなら使ってよい」場所は無い。
    [Fact]
    public void NoSourceWiresUpServerSideOutputCaching()
    {
        // 配線が見つかったファイルと行を集める
        var violations = new List<string>();

        // Web プロジェクト配下のソース(.cs と .cshtml)をすべて見る
        foreach (var sourcePath in ScannedSources())
        {
            // コメントを取り除いたうえで、配線を表す綴りを含む行を探す
            foreach (var (lineNumber, text) in CodeLinesContaining(sourcePath, OutputCacheWiringTokens))
            {
                // リポジトリからの相対パスと行番号で名指しする
                violations.Add($"{Path.GetRelativePath(RepositoryPaths.Root, sourcePath)}:{lineNumber}: {text}");
            }
        }

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "サーバー側の出力キャッシュの配線が見つかりました。"
                + "出力キャッシュは応答をサーバーに溜めて別の利用者へ配る仕組みで、"
                + "応答側の no-store を尊重せず、既定のポリシーはクッキー認証を見ないため、"
                + "職員 A の PHI が職員 B へ返ります。このアプリでは使いません。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 出力キャッシュの配線を表す綴り。属性を書かずに有効化できる経路をすべて含める
    private static readonly string[] OutputCacheWiringTokens =
        ["AddOutputCache", "UseOutputCache", "CacheOutput("];

    /// <summary>
    /// 静的ファイル配信を組み立てる綴り（この 1 つ 1 つが「新しい配信ルート」になりうる）。
    /// </summary>
    /// <remarks>
    /// <para><b>配信ルートは「呼び出しを増やす」以外に「既存の呼び出しを広げる」形でも増える。</b>
    /// 実測した形: 既存の <c>UseStaticFiles</c> に
    /// <c>FileProvider = new CompositeFileProvider(WebRootFileProvider, ContentRootFileProvider)</c>
    /// を足すと、呼び出しの回数も指示の行も 1 つも変わらないまま
    /// <c>/appsettings.json</c> ・ <c>/incident_insight.db</c> ・ <c>/Views/**/*.cshtml</c> が
    /// <c>public,max-age=3600</c> で配られ、<b>919 件すべて緑のまま通った</b>。
    /// だから配信の<b>根を差し替える綴り</b>も見張る。</para>
    ///
    /// <para>配信の根を差し替える綴りと、配る対象を広げる綴りは Web プロジェクトに
    /// <b>現時点で 1 つも無い</b>ので、許可表に載せていない＝1 つでも現れたら落ちる。
    /// 本当に変えたくなったときに、理由を添えて表へ登録する差分が必ず 1 行として現れる。</para>
    ///
    /// <para><b>残っている境界（過大評価しないこと）。</b> これは綴りの走査なので、
    /// <b>「見張っている綴りを使わずに配信を広げる書き方」までは覆えない</b>。
    /// 実際 <c>ServeUnknownFileTypes</c> は、この表を作ったあとのレビューで見つかって
    /// 足したもの（それまで 923 件すべて緑のまま通った）。
    /// <b>「配信ルートを増やせば必ずここに現れる」とは言えない</b> ——
    /// この検査は増やしたことに<b>気付きやすくする</b>ための網であって証明ではなく、
    /// 静的ファイル配信の設定を触る差分はレビューで必ず見ること。</para>
    /// </remarks>
    private static readonly string[] StaticFileWiringTokens =
    [
        // 配信そのものを組み立てる呼び出し
        "UseStaticFiles", "UseFileServer", "UseDirectoryBrowser",
        // 配信の根(どのディレクトリを配るか)を差し替える綴り。
        // パイプラインの組み立てだけでなく、ビルダの生成時にも差し替えられる
        // (WebApplicationOptions.WebRootPath / builder.UseWebRoot)——実測で、
        // WebRootPath = "." にすると呼び出しも指示も 1 つも変わらないまま
        // /appsettings.json ・ /incident_insight.db が public,max-age=3600 で配られた
        // ("FileProvider" は PhysicalFileProvider / CompositeFileProvider /
        //  WebRootFileProvider / ContentRootFileProvider をすべて部分一致で覆うので、
        //  長い綴りを並べない ——並べると 1 行が 2 つの counter に引っかかり、
        //  許可表へ登録する側が同じ行を 2 回登録する羽目になる)
        "FileProvider",
        "WebRootPath", "UseWebRoot",
        // 配る「根」は同じでも、配る「対象」を広げる綴り
        "ServeUnknownFileTypes",
    ];

    /// <summary>
    /// 静的ファイル配信の配線を書いてよい場所（ファイル × 綴り × 期待する出現回数）。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ「行の内容 × 回数」の許可表だけでは足りなかったのか。</b>
    /// <see cref="IntendedCacheControlWriters"/> は <c>Cache-Control</c> を<b>書いている行</b>を
    /// 数えるので、2 つ目の <c>UseStaticFiles</c> が<b>その行を増やさずに</b>同じ指示を名乗ると
    /// 素通りする。実測した形は 2 つある:</para>
    /// <list type="number">
    ///   <item><description><c>StaticFileOptions</c> を変数へ括り出して 2 回渡す。</description></item>
    ///   <item><description>2 つ目の <c>OnPrepareResponse</c> に 1 つ目の
    ///     <c>OnPrepareResponse</c> をそのまま代入する。</description></item>
    /// </list>
    /// <para>どちらも許可済みの行は 1 回しか現れないので回数の照合を通り、
    /// <see cref="StaticAssets_AreOnlyApprovedPublicAssets"/> は <c>wwwroot</c> の外を見ないため
    /// <c>/attachments/&lt;id&gt;/report.pdf</c> が <c>public,max-age=3600</c> で返る差分が
    /// <b>全件緑のまま通った</b>。しかも括り出しは §6 が要求する書き方そのもの。</para>
    ///
    /// <para><b>だから手がかりを「指示の綴り」から「配線の綴り」へ変える。</b>
    /// 配信ルートを増やす以上 <see cref="StaticFileWiringTokens"/> のどれかは必ず増えるので、
    /// 指示をどう書いても（あるいは 1 文字も書かなくても）差分がここに現れる。
    /// 出力キャッシュに対して <see cref="OutputCacheWiringTokens"/> を置いたのと同じ形。</para>
    ///
    /// <para><b>残っている境界</b>: この表も人が判断するエスケープハッチ。
    /// <b>エントリと回数が増える差分は、その配信ルートが PHI を配らないことを
    /// レビューで必ず確認すること</b>（<c>LengthGovernanceExclusions</c> と同じ扱い）。</para>
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IntendedWrite>>
        IntendedStaticFileWiring =
        new Dictionary<string, IReadOnlyDictionary<string, IntendedWrite>>(StringComparer.Ordinal)
        {
            // 静的ファイル配信を組み立てる唯一の場所
            ["Program.cs"] = new Dictionary<string, IntendedWrite>(StringComparer.Ordinal)
            {
                // wwwroot を配る唯一の呼び出し
                ["UseStaticFiles"] =
                    new IntendedWrite(1, "wwwroot を配る唯一の呼び出し。指示は OnPrepareResponse が名乗る。"),
            },
        };

    // 静的ファイル配信の配線が、確認済みの 1 か所だけであること。
    //
    // <b>なぜ Cache-Control の走査と別に要るのか。</b> あちらは「指示を書いている行」を
    // 数えるので、2 つ目の配信ルートが指示を<b>共有</b>して名乗ると差分が現れない
    // (実測: StaticFileOptions を変数へ括り出す形・OnPrepareResponse を代入する形の
    //  どちらも 917 件すべて緑のまま通り、/attachments が public,max-age=3600 で返った)。
    // 配線そのものを見れば、指示の書き方によらず新しい配信ルートが必ず現れる。
    [Fact]
    public void OnlyIntendedPlacesWireUpStaticFileServing()
    {
        // 想定と違う配線を集める
        var violations = new List<string>();
        // 走査対象(1 本も読めないなら「違反ゼロ＝緑」になるので先に落とす)
        var sources = ScannedSources().ToList();
        Assert.NotEmpty(sources);

        // Web プロジェクト配下のソース(.cs と .cshtml)をすべて見る
        foreach (var sourcePath in sources)
        {
            // 許可表と突き合わせるためのキー(Web プロジェクトからの相対パス)
            var tableKey = Path.GetRelativePath(RepositoryPaths.WebProject, sourcePath);
            // そのファイルに許可された配線(無ければ null＝どの綴りも許可されない)
            IntendedStaticFileWiring.TryGetValue(tableKey, out var allowed);
            // リポジトリからの相対パス(名指し用)
            var display = Path.GetRelativePath(RepositoryPaths.Root, sourcePath);
            // ファイルは 1 度だけ読み、全綴りの数え上げで使い回す(§8)
            var codeLines = CodeLines(sourcePath);

            // 綴りごとに、その綴りが何回現れるかを数える
            foreach (var token in StaticFileWiringTokens)
            {
                // <b>行の本数ではなく出現回数</b>を数える ——
                // 同じ行に 2 つ書く形(app.UseStaticFiles(a); app.UseStaticFiles(b);)は
                // 本数だと 1 のままで、配線が増えたことが差分に現れない(実測)
                var actual = codeLines.Sum(l => CountOccurrences(l.Code, token));
                // 許可された回数(表に無ければ 0 回＝1 つでもあれば違反)
                var expected = allowed is not null && allowed.TryGetValue(token, out var intended)
                    ? intended.ExpectedCount
                    : 0;
                // 期待どおりなら何もしない
                if (actual == expected) continue;
                // 多くても少なくても落とす(増えた配線も、消し忘れた許可も、表の更新が要る)
                violations.Add($"{display}: {token} が {expected} 回ではなく {actual} 回現れています。");
            }
        }

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "静的ファイル配信の配線が、確認済みの場所・回数と違います。"
                + "新しい配信ルートは、SecurityHeadersMiddleware の既定(no-store)を"
                + "自分のキャッシュ指示で上書きできる立場になります ——"
                + "PHI を含みうるもの(添付・エクスポート)は静的配信に載せず、"
                + "認可を通すアクションから返してください。"
                + "公開して問題ない資産を配るなら、理由と回数を添えて"
                + "IntendedStaticFileWiring へ登録します。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 静的ファイル配線の許可表が、実在するファイルを指し、理由を持っていること。
    [Fact]
    public void IntendedStaticFileWiring_IsAllRealAndExplained()
    {
        // 表のエントリを 1 つずつ確かめる
        foreach (var (relativePath, allowed) in IntendedStaticFileWiring)
        {
            // Web プロジェクトからの相対パスとして実在すること
            Assert.True(
                File.Exists(Path.Combine(RepositoryPaths.WebProject, relativePath)),
                $"静的ファイル配線の許可表が実在しないファイルを指しています: {relativePath}。");

            // 綴りごとの登録を確かめる
            foreach (var (token, intended) in allowed)
            {
                // 見張っている綴りであること(表にだけある綴りは誰にも照合されない)
                Assert.Contains(token, StaticFileWiringTokens);
                // 理由が空でも空白だけでもないこと
                Assert.False(
                    string.IsNullOrWhiteSpace(intended.Reason),
                    $"静的ファイル配線の許可表に理由がありません: {relativePath} / {token}。");
                // 回数が 1 以上であること(0 の登録は「許可したつもり」を作る)
                Assert.True(
                    intended.ExpectedCount >= 1,
                    $"静的ファイル配線の許可表の ExpectedCount は 1 以上にしてください: {relativePath} / {token}。");
            }
        }
    }

    // 数える綴りの表に、空の綴りが 1 つも無いこと。
    //
    // <b>なぜ「落ちる」より手前で止めるのか。</b> 空の綴りは CountOccurrences を
    // 永久に回す(進める幅が 0 になる)。呼ばれた側でも落ちるようにしたが、そこで出るのは
    // 「綴りが空です」だけで、<b>どの表が壊れているか</b>は読み手に伝わらない。
    // 表ごとに名指しして落とせば、直す場所がそのまま失敗文言に出る。
    //
    // 空が紛れ込む経路は実在する(綴りを文字列連結や定数の参照で組み立てたときのタイポ)。
    // 以前はどの検査も綴りの中身を見ていなかったので、混入は<b>緑のスイートを
    // 失敗文言の無いハングへ変えていた</b>。
    //
    // <b>見る表を手で書き並べず、名前の規約にも頼らない。</b> 包含リストにすると、
    // 4 つ目の表を足した人が登録を忘れたときにその表だけが黙って照合から外れ、
    // 痕跡はテスト件数が 1 減ることだけ ——正当なリファクタと見分けが付かない
    // (CLAUDE.md がこの形の事故を繰り返し記録している)。<b>名前の末尾で絞るのも同じ穴</b>で、
    // 4 つ目を StaticFileWiringSpellings という名前で足すだけで静かに外れる。
    // <b>このクラスが宣言している string[] をすべて</b>見れば、登録も命名も要らない
    // (綴りの表でない string[] が混ざっても、見るのは「空の綴りが無いこと」だけ ——
    // 許可リストであれ綴りの表であれ、空文字が混ざっているのは等しく不具合なので害は無い)。
    [Fact]
    public void WiringTokenTables_ContainNoEmptySpelling()
    {
        // このクラスが自分で宣言している「文字列の並び」をすべて拾う。
        // <b>型でも絞らない</b> ——string[] だけを見ると、4 つ目の表を
        // IReadOnlyList<string> で宣言した瞬間に黙って外れる(このファイルは
        // CodeLinesContaining の引数型に既に IReadOnlyList<string> を使っているので、
        // そう書くのはごく自然)。名前でも型でも絞らなければ、登録も命名も要らない
        var tables = typeof(ResponseCacheAttributePolicyTests)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
            .Where(f => typeof(IEnumerable<string>).IsAssignableFrom(f.FieldType))
            .OrderBy(f => f.Name, StringComparer.Ordinal)
            .ToList();

        // 1 つも拾えないなら導出が壊れている(「見るべき表ゼロ＝緑」を避ける)
        Assert.True(
            tables.Count > 0,
            "このクラスが宣言している string[] が 1 つも見つからない。"
                + "導出を変えたなら、この検査も同じ変更セットで直すこと。");

        // 表ごとに、空の綴りを含まないことを確かめる
        foreach (var table in tables)
        {
            // 実際の値を読む(static なのでインスタンスは要らない)
            var tokens = (IEnumerable<string>?)table.GetValue(null);

            // <b>null は「空の綴り」より先に落とす。</b> そのまま長さを読むと
            // NullReferenceException になり、どの表が壊れているかを名指しする
            // この検査の役目がスタックトレースに変わってしまう
            Assert.True(tokens is not null, $"{table.Name} が null です。綴りの表は必ず初期化してください。");

            // <b>ここで「空でないこと」は求めない。</b> 対象を名前で絞るのをやめた結果、
            // 綴りの表でない string[] も含まれる ——「現時点で該当が 1 つも無い」ことを
            // 表す空の配列は正当なので、一律に禁じると正しいコードで赤くなる。
            // 綴りの表が空になって検査が無力化する形は、その表を使う検査自身が
            // 「見るべき対象ゼロ＝緑」を避ける形で受け持つ

            // 1 つずつ、空でも空白だけでもないことを確かめる
            Assert.All(
                tokens!,
                token => Assert.False(
                    string.IsNullOrWhiteSpace(token),
                    $"{table.Name} に空の綴りがあります。空の綴りは出現回数の数え上げを永久に回します。"));
        }
    }

    // 空の綴りを渡されたら、黙って回り続けるのではなくその場で落ちること。
    //
    // <b>上の表の検査だけでは足りない。</b> あちらは実在する表しか見ないので、
    // 数え上げ側の歯止めを外しても(表が正しい限り)全件緑のまま通る。
    // 「黙って止まる」を「落ちる」へ変えたことそのものを、合成入力で固定する。
    [Fact]
    public void CountOccurrences_RejectsAnEmptyToken_RatherThanLoopingForever()
    {
        // 空文字はその場で落ちること(戻ってこない代わりに例外で知らせる)
        Assert.Throws<ArgumentException>(() => CountOccurrences("UseStaticFiles", string.Empty));

        // 普通の綴りは今までどおり数えられること(歯止めが数え上げを壊していないこと)
        Assert.Equal(2, CountOccurrences("UseStaticFiles(a); UseStaticFiles(b);", "UseStaticFiles"));
    }

    // 判定(属性の型名の照合)が、拾う側と見逃さない側の両方で働くこと。
    //
    // 実在の宣言が 0 件なので、判定を「常に false」へ潰しても上の検査は緑のまま通る。
    [Theory]
    // 出力キャッシュの属性(名前空間ごと一致)
    [InlineData("Microsoft.AspNetCore.OutputCaching.OutputCacheAttribute", true)]
    // 名前空間が違っても、型名が OutputCacheAttribute なら拾う(自前のラッパー等)
    [InlineData("Acme.Web.OutputCacheAttribute", true)]
    // 応答キャッシュの属性は別物(こちらは JudgeDirective が担当する)
    [InlineData("Microsoft.AspNetCore.Mvc.ResponseCacheAttribute", false)]
    // 無関係な属性は拾わない
    [InlineData("Microsoft.AspNetCore.Authorization.AuthorizeAttribute", false)]
    public void IsOutputCacheAttribute_MatchesOnlyOutputCaching(string typeFullName, bool expected)
    {
        // 型名の末尾だけで判定していることを、合成した名前で確かめる
        Assert.Equal(expected, IsOutputCacheAttributeTypeName(typeFullName));
    }

    // wwwroot 配下が、キャッシュ可能にしてよいと確認済みの入れ物・資産だけであること。
    //
    // <b>なぜ要るのか。</b> 静的ファイル配信の OnPrepareResponse は wwwroot 配下の
    // <b>すべて</b>に public,max-age=3600 を名乗らせる。つまり wwwroot に新しい入れ物を
    // 足すと、その中身は<b>1 行のコードも書かずに</b>キャッシュ可能側へ入る ——
    // 添付画像やエクスポートした CSV を wwwroot/attachments や wwwroot/exports へ置くと、
    // 共有キャッシュと共用端末のディスクにログアウト後 1 時間残る。
    // 属性・MvcOptions・直接書き込みのどの検査にも現れない(Program.cs は許可表に載っている)。
    //
    // <b>直下だけを見てはいけない(issue #254)。</b> 以前は wwwroot の<b>直下</b>だけを
    // 列挙していたため、<b>承認済みの入れ物の中に新しい入れ物を作ると素通りした</b> ——
    // wwwroot/js/exports/patient-report.pdf も wwwroot/lib/reports/… も、直下のエントリを
    // 1 つも増やさないので検査は緑のままだった。配信されるのは配下のすべてなので、
    // 走査もそこへ合わせる。ファイルは<b>種類(拡張子)</b>で見る —— 入れ物を増やさずに
    // wwwroot/css/patient-report.pdf と置く形が、同じ理由で素通りするため。
    //
    // <b>ただし「中を見ない」入れ物が要る。</b> wwwroot/lib は CDN 由来の取得物が数百件入り、
    // 1 件ずつ承認しても中身はこちらが書いたものではない。OpaqueStaticDirectories に
    // 理由付きで登録した入れ物だけは中へ降りない —— 降りないという判断そのものが、
    // 表の 1 行としてレビューに現れる。
    //
    // <b>残っている境界。</b> 種類での判定なので、承認済みの拡張子を名乗る PHI
    // (例: 患者一覧を .js として書き出す)は拾えない。拡張子の表を広げる差分が
    // レビューに現れることと、配信ルート自体を見張る OnlyIntendedPlacesWireUpStaticFileServing
    // が対になって支えている。
    [Fact]
    public void StaticAssets_AreOnlyApprovedPublicAssets()
    {
        // wwwroot(静的ファイル配信の根)の絶対パスを組み立てる
        var root = Path.Combine(RepositoryPaths.WebProject, "wwwroot");

        // 配下を再帰で列挙する(中を見ない入れ物の内側へは降りない)
        var entries = EnumerateStaticAssets(root);

        // 1 つも読めないなら走査が壊れている(「見るべき対象ゼロ＝緑」を避ける)
        Assert.NotEmpty(entries);

        // 承認済みの表に無いものを集める
        var unapproved = FindUnapprovedStaticAssets(entries);

        // 想定外の入れ物・資産が無いことを、名指しの一覧付きで確認する
        Assert.True(
            unapproved.Count == 0,
            "wwwroot に、キャッシュ可能にしてよいと確認していないものがあります: "
                + string.Join(", ", unapproved.Select(item => $"{item.RelativePath}({item.Cause})"))
                + "。静的ファイル配信は wwwroot 配下のすべてに "
                + "public,max-age=3600 を名乗らせるため、ここへ置いたものは 1 行のコードも"
                + "書かずにキャッシュ可能になります(共用端末のディスクにログアウト後も残ります)。"
                + "PHI を含みうるもの(添付・エクスポート)は wwwroot の外に置き、"
                + "認可を通すアクションから返してください。"
                + $"公開して問題ない資産なら、入れ物は {nameof(ApprovedStaticDirectories)} へ、"
                + $"ファイルの種類は {nameof(ApprovedStaticFileExtensions)} へ理由を添えて登録します。");
    }

    // 走査が「承認済みの入れ物の中へ実際に降りている」ことと、
    // 「中を見ない入れ物の手前で止まっている」ことを、実在のツリーで確かめる。
    //
    // <b>なぜ別に要るのか。</b> 上の検査は<b>違反が 0 件なら緑</b>なので、走査が降りるのを
    // やめても(＝直下しか見なかった頃へ戻っても)全件緑のまま通る —— issue #254 の
    // fail-open がそのまま復活し、痕跡はどこにも出ない。降りたこと自体を固定する。
    //
    // 手がかりは判定とは独立に選ぶ: css/site.css は Git が追跡している実ファイルで、
    // 承認済みの入れ物の 1 階層下にある(降りなければ絶対に現れない)。
    [Fact]
    public void EnumerateStaticAssets_DescendsIntoApprovedDirectories_ButStopsAtOpaqueOnes()
    {
        // wwwroot の絶対パスを組み立てる
        var root = Path.Combine(RepositoryPaths.WebProject, "wwwroot");

        // 配下を再帰で列挙する
        var entries = EnumerateStaticAssets(root);

        // 承認済みの入れ物の中へ降りていること(1 階層下の実ファイルが現れる)
        Assert.Contains(entries, entry => entry.RelativePath == "css/site.css");

        // 中を見ない入れ物そのものは 1 件として現れること
        Assert.Contains(entries, entry => entry is { RelativePath: "lib", IsDirectory: true });

        // その内側へは降りていないこと(数百件の取得物を列挙していない)
        Assert.DoesNotContain(entries, entry => entry.RelativePath.StartsWith("lib/", StringComparison.Ordinal));
    }

    // 判定(承認済みかどうかの突き合わせ)が、拾う側と見逃さない側の両方で働くこと。
    //
    // 実在のツリーには違反が 1 件も無いので、判定を「常に空を返す」へ潰しても上の検査は
    // 緑のまま通る。合成した入力で判定そのものを固定する。
    [Fact]
    public void FindUnapprovedStaticAssets_ReportsNestedContainersAndUnexpectedFileTypes()
    {
        // 合成の承認表(実在の表に依存しないので、表を書き換えてもこの検査の意味は変わらない)
        var approvedDirectories = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // 検査用の入れ物を 1 つだけ承認しておく
            ["js"] = "テスト用の承認済みの入れ物。",
        };

        // 合成の拡張子表(こちらも 1 種類だけ承認しておく)
        var approvedExtensions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // 検査用のファイル種別を 1 つだけ承認しておく
            [".js"] = "テスト用の承認済みの種類。",
        };

        // 承認済み・未承認を混ぜた入力を組み立てる
        var entries = new[]
        {
            // 承認済みの入れ物(通る)
            new StaticAssetEntry("js", IsDirectory: true),
            // 承認済みの種類のファイル(通る)
            new StaticAssetEntry("js/site.js", IsDirectory: false),
            // 大文字で綴った同じ種類(URL の配信は綴りの大小を区別しないので通す)
            new StaticAssetEntry("js/SITE.JS", IsDirectory: false),
            // 承認済みの入れ物の中に作った新しい入れ物(issue #254 の本体。落とす)
            new StaticAssetEntry("js/exports", IsDirectory: true),
            // その中のエクスポート(種類も承認されていないので落とす)
            new StaticAssetEntry("js/exports/patient-report.pdf", IsDirectory: false),
            // 拡張子を持たないファイル(種類が判断できないので落とす)
            new StaticAssetEntry("js/LICENSE", IsDirectory: false),
        };

        // 合成の表で判定する
        var unapproved = FindUnapprovedStaticAssets(entries, approvedDirectories, approvedExtensions);

        // 落ちるのは 3 件で、入力の順に並ぶこと
        Assert.Equal(
            new[] { "js/exports", "js/exports/patient-report.pdf", "js/LICENSE" },
            unapproved.Select(item => item.RelativePath).ToArray());

        // 入れ物とファイルで理由が分かれていること(失敗文言が直し方を取り違えないため)
        Assert.Equal(UnapprovedDirectoryCause, unapproved[0].Cause);
        Assert.Equal(UnapprovedExtensionCause, unapproved[1].Cause);
        Assert.Equal(UnapprovedExtensionCause, unapproved[2].Cause);
    }

    // 承認済みだけの入力では 1 件も落とさないこと(「常に落とす」判定への退行を止める)。
    [Fact]
    public void FindUnapprovedStaticAssets_ReportsNothingWhenEverythingIsApproved()
    {
        // 合成の承認表(入れ物 1 つ)
        var approvedDirectories = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // 検査用の入れ物
            ["js"] = "テスト用の承認済みの入れ物。",
        };

        // 合成の拡張子表(種類 1 つ)
        var approvedExtensions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // 検査用のファイル種別
            [".js"] = "テスト用の承認済みの種類。",
        };

        // 承認済みだけを並べた入力
        var entries = new[]
        {
            // 承認済みの入れ物
            new StaticAssetEntry("js", IsDirectory: true),
            // 承認済みの種類のファイル
            new StaticAssetEntry("js/site.js", IsDirectory: false),
        };

        // 1 件も落ちないこと
        Assert.Empty(FindUnapprovedStaticAssets(entries, approvedDirectories, approvedExtensions));
    }

    // 「中を見ない入れ物か」の判定が、登録した入れ物だけに当たること。
    [Theory]
    // 登録済みの入れ物(降りない)
    [InlineData("lib", true)]
    // 承認済みだが登録していない入れ物(降りる)
    [InlineData("css", false)]
    // 登録済みの入れ物の配下(そもそも列挙されないが、完全一致だけで判定していることを固定する)
    [InlineData("lib/jquery", false)]
    // 綴りが前方一致するだけの別の入れ物(降りる)
    [InlineData("library", false)]
    public void IsOpaqueStaticDirectory_MatchesOnlyRegisteredContainers(string relativePath, bool expected)
    {
        // 完全一致でのみ「中を見ない」と判断していることを確かめる
        Assert.Equal(expected, IsOpaqueStaticDirectory(relativePath));
    }

    // 「中を見ない」入れ物は、承認済みの入れ物でもあること。
    //
    // 片方だけに載せると、<b>中へ降りないのに入れ物自身は未承認</b>(＝毎回落ちる)か、
    // その逆で<b>承認したつもりの入れ物の中を誰も見ない</b>状態になる。
    [Fact]
    public void OpaqueStaticDirectories_AreAlsoApproved()
    {
        // 承認表に載っていない「中を見ない入れ物」を集める
        var missing = OpaqueStaticDirectories.Keys
            .Where(name => !ApprovedStaticDirectories.ContainsKey(name))
            .ToList();

        // 1 つも無いことを、名指しの一覧付きで確認する
        Assert.True(
            missing.Count == 0,
            $"{nameof(OpaqueStaticDirectories)} に載せた入れ物は "
                + $"{nameof(ApprovedStaticDirectories)} にも載せてください: "
                + string.Join(", ", missing));
    }

    // 3 つの表のすべてに、空でない理由が書かれていること。
    //
    // 理由を誰も読まないままにすると、空文字を入れるだけで検査を黙らせられる
    // (LengthGovernanceExclusions_AllHaveAReason と同じ扱い)。
    [Fact]
    public void StaticAssetTables_AllHaveAReason()
    {
        // 3 つの表を「表の名前 → 中身」の組にして順に見る
        var tables = new (string Name, IReadOnlyDictionary<string, string> Entries)[]
        {
            // 承認済みの入れ物
            (nameof(ApprovedStaticDirectories), ApprovedStaticDirectories),
            // 中を見ない入れ物
            (nameof(OpaqueStaticDirectories), OpaqueStaticDirectories),
            // 承認済みのファイル種別
            (nameof(ApprovedStaticFileExtensions), ApprovedStaticFileExtensions),
        };

        // 理由が空・空白のエントリを、表の名前付きで集める
        var blank = tables
            .SelectMany(table => table.Entries
                .Where(entry => string.IsNullOrWhiteSpace(entry.Value))
                .Select(entry => $"{table.Name}[{entry.Key}]"))
            .ToList();

        // 1 つも無いことを、名指しの一覧付きで確認する
        Assert.True(
            blank.Count == 0,
            "理由の書かれていない登録があります: " + string.Join(", ", blank)
                + "。理由を書かない登録は、検査を黙らせるためだけの 1 行と区別が付きません。");
    }

    // 承認済みのファイル種別が、拡張子の綴り(先頭が . の小文字)で登録されていること。
    //
    // "css" や ".CSS" と書いても突き合わせ相手(Path.GetExtension の戻り値)と形が合わず、
    // <b>その 1 行だけが何にも当たらない</b>まま表に残る(登録したつもりの種別が通らない)。
    [Fact]
    public void ApprovedStaticFileExtensions_AreSpelledAsExtensions()
    {
        // 拡張子の綴りになっていないキーを集める
        var malformed = ApprovedStaticFileExtensions.Keys
            .Where(extension =>
                !extension.StartsWith('.')
                || extension.Length < 2
                || extension != extension.ToLowerInvariant())
            .ToList();

        // 1 つも無いことを、名指しの一覧付きで確認する
        Assert.True(
            malformed.Count == 0,
            $"{nameof(ApprovedStaticFileExtensions)} のキーは先頭が . の小文字(例: .css)で"
                + "書いてください: " + string.Join(", ", malformed));
    }

    /// <summary>
    /// <c>wwwroot</c> 配下で見つけた 1 件（走査の結果を判定へ渡すための入れ物）。
    /// </summary>
    /// <param name="RelativePath"><c>wwwroot</c> からの相対パス（区切りは <c>/</c> に正規化済み）。</param>
    /// <param name="IsDirectory">入れ物（ディレクトリ）なら true、ファイルなら false。</param>
    private readonly record struct StaticAssetEntry(string RelativePath, bool IsDirectory);

    /// <summary>
    /// 承認されていない 1 件と、その理由（失敗文言に名指しで出す）。
    /// </summary>
    /// <param name="RelativePath"><c>wwwroot</c> からの相対パス。</param>
    /// <param name="Cause">入れ物として未承認か、種類として未承認か。</param>
    private readonly record struct UnapprovedStaticAsset(string RelativePath, string Cause);

    /// <summary>入れ物そのものが承認されていないときの理由。</summary>
    private const string UnapprovedDirectoryCause = "承認されていない入れ物";

    /// <summary>ファイルの種類が承認されていないときの理由。</summary>
    private const string UnapprovedExtensionCause = "承認されていない種類のファイル";

    /// <summary>
    /// <c>wwwroot</c> 配下に置いてよい（キャッシュ可能で問題ない）入れ物と、その理由。
    /// キーは <c>wwwroot</c> からの相対パス（区切りは <c>/</c>）。
    ///
    /// <para><b>「実在するか」は検査しない。</b> <c>js</c> は TypeScript の出力先で
    /// <c>.gitignore</c> 済みのため、ビルド前のツリーには存在しない。実在を要求すると
    /// 「ビルドしていない手元でだけ落ちる」検査になり、直し方が「ビルドする」しか
    /// 無くなる（この repo が繰り返し避けている、直しようの無い要求）。</para>
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> ApprovedStaticDirectories =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // アプリ自身のスタイルシート
            ["css"] = "アプリのスタイルシート。利用者ごとの内容を持たない。",
            // アプリ自身のスクリプト
            ["js"] = "アプリのスクリプト(TypeScript の出力)。利用者ごとの内容を持たない。",
            // 第三者ライブラリ
            ["lib"] = "第三者ライブラリ(jQuery 等)。版付き URL でないため期間を短く保つ。",
        };

    /// <summary>
    /// 中を見ない（走査が降りない）入れ物と、その理由。
    /// <see cref="ApprovedStaticDirectories"/> にも載っている必要がある。
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> OpaqueStaticDirectories =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // 第三者ライブラリの取得物(数百件)。1 件ずつ承認しても中身はこちらが書いたものではない
            ["lib"] = "CDN 由来の取得物が数百件入る。中身はこちらが書いたものではなく、1 件ずつ承認しても意味が無い。",
        };

    /// <summary>
    /// <c>wwwroot</c> 配下（中を見ない入れ物の外）に置いてよいファイルの種類と、その理由。
    /// キーは先頭が <c>.</c> の小文字（<c>Path.GetExtension</c> の戻り値と同じ形）。
    ///
    /// <para><b>先回りで足さない。</b> 実際に置いてある種類だけを載せる。使う予定の無い
    /// 種類を先に承認すると、その分だけ検出網が黙って広がる（§6 の「将来を見越した
    /// 過度な抽象化を避ける」）。ソースマップ等を出すようにしたときは、
    /// その変更と同じ差分でここへ 1 行足す。</para>
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> ApprovedStaticFileExtensions =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // スタイルシート
            [".css"] = "アプリのスタイルシート。利用者ごとの内容を持たない。",
            // スクリプト(TypeScript の出力)
            [".js"] = "アプリのスクリプト(TypeScript の出力)。利用者ごとの内容を持たない。",
            // ブラウザのタブに出るアイコン
            [".ico"] = "ブラウザのアイコン。公開情報。",
        };

    /// <summary>
    /// <c>wwwroot</c> 配下を再帰的に列挙する。
    /// <see cref="OpaqueStaticDirectories"/> に登録した入れ物の中へは降りない
    /// （その入れ物自身は 1 件として返す）。
    /// </summary>
    /// <param name="root"><c>wwwroot</c> の絶対パス。</param>
    /// <returns>見つかった入れ物・ファイル（相対パスと種別）の一覧。</returns>
    private static IReadOnlyList<StaticAssetEntry> EnumerateStaticAssets(string root)
    {
        // 見つけたものを順に積む入れ物
        var found = new List<StaticAssetEntry>();

        // これから中を見るディレクトリの待ち行列(再帰ではなく反復で辿る)
        var pending = new Stack<string>();

        // 出発点は wwwroot 自身
        pending.Push(root);

        // 待ち行列が空になるまで辿り続ける
        while (pending.Count > 0)
        {
            // 次に中を見るディレクトリを取り出す
            var directory = pending.Pop();

            // その直下にあるものを 1 件ずつ見る
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                // 入れ物(ディレクトリ)かどうかを調べる
                var isDirectory = Directory.Exists(path);

                // wwwroot からの相対パスにし、区切りを / に揃える(OS 差を持ち込まない)
                var relativePath = Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

                // 見つけた 1 件として記録する
                found.Add(new StaticAssetEntry(relativePath, isDirectory));

                // 入れ物で、かつ「中を見ない」登録が無ければ、その中も辿る
                if (isDirectory && !IsOpaqueStaticDirectory(relativePath))
                {
                    // 後で中を見るために待ち行列へ積む
                    pending.Push(path);
                }
            }
        }

        // 見つかったものをそのまま返す
        return found;
    }

    /// <summary>
    /// その入れ物が「中を見ない」登録を持つかを返す（判定の純粋関数）。
    /// </summary>
    /// <param name="relativePath"><c>wwwroot</c> からの相対パス。</param>
    /// <returns>中を見ない入れ物なら true。</returns>
    private static bool IsOpaqueStaticDirectory(string relativePath) =>
        // 完全一致でのみ判断する(前方一致にすると library のような別の入れ物まで巻き込む)
        OpaqueStaticDirectories.ContainsKey(relativePath);

    /// <summary>
    /// 承認されていない入れ物・ファイルを集める（実在の表を使う入口）。
    /// </summary>
    /// <param name="entries">走査で見つかった一覧。</param>
    /// <returns>承認されていないものの一覧（入力の順を保つ）。</returns>
    private static IReadOnlyList<UnapprovedStaticAsset> FindUnapprovedStaticAssets(
        IEnumerable<StaticAssetEntry> entries) =>
        // 実在の 2 つの表を渡して、判定そのものは下の純粋関数に任せる
        FindUnapprovedStaticAssets(entries, ApprovedStaticDirectories, ApprovedStaticFileExtensions);

    /// <summary>
    /// 承認されていない入れ物・ファイルを集める（判定の純粋関数）。
    ///
    /// <para>表を引数で受けるのは、実在のツリーに違反が 1 件も無いため
    /// 合成入力で判定そのものを固定する必要があるから。</para>
    /// </summary>
    /// <param name="entries">走査で見つかった一覧。</param>
    /// <param name="approvedDirectories">承認済みの入れ物の表。</param>
    /// <param name="approvedExtensions">承認済みのファイル種別の表。</param>
    /// <returns>承認されていないものの一覧（入力の順を保つ）。</returns>
    private static IReadOnlyList<UnapprovedStaticAsset> FindUnapprovedStaticAssets(
        IEnumerable<StaticAssetEntry> entries,
        IReadOnlyDictionary<string, string> approvedDirectories,
        IReadOnlyDictionary<string, string> approvedExtensions)
    {
        // 承認されていなかったものを順に積む入れ物
        var unapproved = new List<UnapprovedStaticAsset>();

        // 見つかったものを 1 件ずつ順に判定する
        foreach (var entry in entries)
        {
            // 入れ物(ディレクトリ)は、相対パスが承認表にあるかで判断する
            if (entry.IsDirectory)
            {
                // 表に無ければ「承認されていない入れ物」として記録する
                if (!approvedDirectories.ContainsKey(entry.RelativePath))
                {
                    // 相対パスと理由を添えて積む
                    unapproved.Add(new UnapprovedStaticAsset(entry.RelativePath, UnapprovedDirectoryCause));
                }

                // 入れ物の判定はここで終わり(拡張子では見ない)
                continue;
            }

            // ファイルは種類(拡張子)で判断する。拡張子が無ければ空文字になり、表にも無い
            var extension = Path.GetExtension(entry.RelativePath);

            // 表に無ければ「承認されていない種類のファイル」として記録する
            if (!approvedExtensions.ContainsKey(extension))
            {
                // 相対パスと理由を添えて積む
                unapproved.Add(new UnapprovedStaticAsset(entry.RelativePath, UnapprovedExtensionCause));
            }
        }

        // 入力の順を保ったまま返す
        return unapproved;
    }

    /// <summary>
    /// その属性インスタンスが出力キャッシュの属性かを返す。
    /// </summary>
    /// <param name="attribute">調べる属性。</param>
    /// <returns>出力キャッシュの属性なら true。</returns>
    private static bool IsOutputCacheAttribute(object attribute) =>
        // 型の完全修飾名で判定する(型を直接参照しないのは docstring の理由による)
        IsOutputCacheAttributeTypeName(attribute.GetType().FullName ?? attribute.GetType().Name);

    /// <summary>
    /// 型の完全修飾名が出力キャッシュの属性を指すかを返す(判定の純粋関数)。
    /// </summary>
    /// <param name="typeFullName">属性の型の完全修飾名。</param>
    /// <returns>出力キャッシュの属性なら true。</returns>
    private static bool IsOutputCacheAttributeTypeName(string typeFullName) =>
        // 名前空間を問わず、型名が OutputCacheAttribute のものを拾う
        typeFullName.Split('.').Last().Equals("OutputCacheAttribute", StringComparison.Ordinal);

    // 「Cache-Control を名指ししている行か」の判定が、拾う側と見逃さない側の両方で働くこと。
    //
    // 実在のソースには違反が 1 件も無いので、判定を「常に false」へ潰しても上の検査は
    // 全件緑のまま通る。合成入力で判定そのものを固定する。
    [Theory]
    // 型付きのプロパティ経由の代入(いちばん素直な書き方)
    [InlineData("        Response.Headers.CacheControl = \"public,max-age=300\";", true)]
    // 文字列キーでの代入(綴りを変えただけの抜け道)
    [InlineData("        Response.Headers[\"Cache-Control\"] = \"public\";", true)]
    // Append での追加も同じく書き込み
    [InlineData("        Response.Headers.Append(\"Cache-Control\", \"public\");", true)]
    // ビューから書く形(Razor でも到達できる)
    [InlineData("    @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // 無関係な行は拾わない(誤検知すると、いずれ検査ごと緩められる)
    [InlineData("        var incidents = await _db.Incidents.ToListAsync();", false)]
    // 似ているが別物のヘッダー名も拾わない
    [InlineData("        Response.Headers.ContentType = \"application/json\";", false)]
    // すべて小文字の綴りも拾う(HTTP のヘッダー名は大文字小文字を区別しない)
    [InlineData("        Response.Headers[\"cache-control\"] = \"public\";", true)]
    // すべて大文字の綴りも拾う
    [InlineData("        Response.Headers[\"CACHE-CONTROL\"] = \"public\";", true)]
    // Razor のコメントも同じ扱い
    [InlineData("    @* Cache-Control はミドルウェアの既定に任せる *@", false)]
    // <b>同じ行で閉じたコメントの後ろの実コードは拾う</b>(綴りを変えただけの抜け道にしない)
    [InlineData("    @* メモ *@ @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // <b>ビューも C# のブロックコメントを扱う</b>ので、閉じた後ろの実コードは拾う
    // (inline script / style のために残している扱い。経路ごとに固定する)
    [InlineData("    /* メモ */ Response.Headers.CacheControl = \"public\";", true)]
    // 行コメントの<b>前</b>にある実コードも、ビューの経路で拾えること
    [InlineData("        Response.Headers.CacheControl = \"public\"; // 速くするため", true)]
    // <b>属性値の中の URL の "//" を行コメントと読まない。</b> href=" の二重引用符が
    // リテラルの開きと判定され、中身ごと読み飛ばされるので // に行き当たらない。
    // <b>裸の URL(引用符の外)は別の話で、そちらは行が切れる</b> ——
    // ビューは // を行コメントとして扱うため。CLAUDE.md の「残っている境界 (b)」が正本
    [InlineData("    <a href=\"https://example.com\">x</a> @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // 文字列の中の "@*" でもコメントが始まったと読まない
    [InlineData("        private const string Odd = \"a@*b\";", false)]
    // 地の文のアポストロフィ(1 つ)があっても、後ろの Razor コメントはコメントとして落ちる。
    // 実測: 縛りを入れる前は、この行が「違反」として報告されていた
    [InlineData("    <p>It's fine</p> @* Cache-Control はミドルウェアの既定に任せる *@", false)]
    // アポストロフィが 2 つある行。あいだはリテラル扱いになるが中身は実コードとして残るので、
    // 後ろの Razor コメントはこれまでどおりコメントとして落ちる
    [InlineData("    <p>It's Bob's report</p> @* Cache-Control は書かない *@", false)]
    // <b>単一引用符の属性値に URL がある行。</b> 中の // を行コメントと読むと、
    // 同じ行にある書き込みが走査から丸ごと落ちる(実測した fail-open の再発防止)
    [InlineData("    <script src='https://cdn.example.com/x.js'></script> @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // 同じ形でも、書き込みではなくコメントなら拾わない(誤検知側にも倒れないこと)
    [InlineData("    <script src='https://cdn.example.com/x.js'></script> @* Cache-Control は書かない *@", false)]
    // <b>地の文のアポストロフィと属性の引用符が同じ行にある形。</b> 「閉じているか」だけで
    // 判断すると Bob's の ' が href=' の ' で閉じ、あいだのコメントが読まれず赤くなった(実測)
    [InlineData("    <p>Bob's report</p> @* Cache-Control は書かない *@ <a href='x'>x</a>", false)]
    // 同じ形でも、コメントではなく実際の書き込みなら拾う(見逃し側にも倒れないこと)
    [InlineData("    <p>Bob's</p> @{ Context.Response.Headers.CacheControl = \"public\"; } <a href='x'>x</a>", true)]
    // <b>地の文の二重引用符。</b> ' と同じ手当てが要る(片方だけだと同じ誤検知が残る)
    [InlineData("    <p>重症度は \"レベル3 以上が対象</p> @* Cache-Control は既定に任せる *@", false)]
    // 同じ形でも、実際の書き込みなら拾う
    [InlineData("    <p>重症度は \"レベル3</p> @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // 本物の文字リテラルは今までどおりリテラルとして扱う(中の @* をコメント開始と読まない)
    [InlineData("        var marker = '@'; Response.Headers.CacheControl = \"public\";", true)]
    // アポストロフィの後ろに実コードがあれば、今までどおり拾う(見逃す方向へ倒れない)
    [InlineData("    <p>It's</p> @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    public void MentionsCacheControl_MatchesOnlyCacheControlWrites(string line, bool expected)
    {
        // 判定を実行して、期待どおりかを確認する
        Assert.Equal(expected, MentionsCacheControl(line));
    }

    // C# の 1 行では、C# のコメントだけがコメントとして落ちること。
    //
    // <b>言語ごとに走査が分かれたので、検査も分ける。</b> 同じ綴り(// ・ /* */ ・ ///)を
    // .cs は字句解析が、ビューは近似の走査が読む ——<b>同じ答えを返すのは今たまたまで、
    // 拠って立つ規則が違う</b>。1 つの [Theory] にまとめると、どちらかの規則を直したときに
    // 「どちらの経路の期待値だったのか」が読み取れなくなる。経路ごとに固定する。
    [Theory]
    // 日本語コメントで規則を説明する行は拾わない(§5 が求める書き方で赤くしない)
    [InlineData("    // エラーページ。Cache-Control は属性側で no-store を宣言する", false)]
    // XML ドキュメントコメントも同じ扱い
    [InlineData("    /// <c>Cache-Control</c> をここでは書かない。", false)]
    // 閉じたブロックコメントの後ろの実コードは拾う(綴りを変えただけの抜け道にしない)
    [InlineData("    /* メモ */ Response.Headers.CacheControl = \"public\";", true)]
    // 行コメントの<b>前</b>に実コードがある行も拾う
    [InlineData("        Response.Headers.CacheControl = \"public\"; // 速くするため", true)]
    // 文字列の中の "/*" でコメントが始まったと読まない(実測でファイル全体が盲になった形)
    [InlineData("        private const string GlobPattern = \"Models/*.cs\";", false)]
    // <b>issue #249 の形</b>: return の後ろのリテラルに // があっても、行の残りが落ちない
    [InlineData("        string Url() { return \"https://example.test\"; } void F() { Response.Headers.CacheControl = \"public\"; }", true)]
    // ふつうの書き込みは今までどおり拾う
    [InlineData("        Response.Headers[\"Cache-Control\"] = \"no-store\";", true)]
    // 無関係な行は拾わない
    [InlineData("        var incidents = await _db.Incidents.ToListAsync();", false)]
    public void CSharpLine_MentionsCacheControl_MatchesOnlyCacheControlWrites(string line, bool expected)
    {
        // C# の経路(字句解析)を通して判定する
        var scanned = CSharpCommentScanner.CodeLines(line);
        // 1 行しか渡していないので、実コードもちょうど 1 行
        var code = Assert.Single(scanned).Code;
        // 照合の規則は 1 か所が持つ(言語ごとの経路で答えが割れないようにする)
        Assert.Equal(expected, ContainsCacheControlToken(code));
    }

    // 複数行にまたがるコメントの中身を、実コードと取り違えないこと。
    //
    // <b>なぜ行単位の検査では足りないのか。</b> @*…*@ も /*…*/ も複数行にまたがれる。
    // 「行頭が * ならコメントの続き」という当て方は、このリポジトリで実際に使われている
    // 書き方(@* だけの行で始めて次の行から本文を書く形。Views/Incidents/Create.cshtml の
    // 大半がこれ)を拾えず、規約どおりの日本語コメントで CI が赤くなる(実測)。
    [Fact]
    public void CodeScan_CarriesBlockCommentStateAcrossLines()
    {
        // Razor の複数行コメント(本文の行頭に記号が無い形)は、すべてコメントとして扱う
        Assert.Empty(ScanLines(
            "@*",
            "  この画面は Cache-Control をミドルウェアの既定に任せる",
            "*@"));

        // C# の複数行コメントも同じ
        Assert.Empty(ScanLines(
            "/*",
            "  Cache-Control はここでは書かない",
            "*/"));

        // コメントが閉じたあとの実コードは、行をまたいでいても拾う
        Assert.Equal(
            new[] { 3 },
            ScanLines(
                "@*",
                "  メモ",
                "*@ @{ Context.Response.Headers.CacheControl = \"public\"; }"));

        // 閉じていないコメントの中で終わっても、実コードを拾わない。
        // <b>ここで落とす(fail-closed)形は試して戻した</b> ——正しいビュー
        // (表示テキストの incident_/*.csv)を赤くするうえ、取り違えた開きを
        // 後ろの本物の閉じ綴りが閉じてしまうと何も言わない。理由は ReadCodeLines の解説が正本
        Assert.Empty(ScanLines(
            "/*",
            "  Response.Headers.CacheControl = \"public\";"));
    }

    // C# の 3 つの文字列リテラルすべてで、リテラルの終わりを取り違えないこと。
    //
    // <b>判定は字句解析に任せたが、任せたこと自体を固定しておく。</b> ここが自前の走査へ
    // 戻ると、姉妹の走査が<b>過去に踏んだ不具合として明記していた</b>2 つ
    // ——逐語的かどうかを直前 1 文字だけで見る形と、生文字列 """…""" を扱わない形——が
    // そのまま戻る。Web プロジェクトにこの 2 つの書き方が 1 つも無い間は、
    // 戻しても全件緑になるので、合成した行で固定する。
    [Fact]
    public void CSharpScan_FindsTheEndOfEveryKindOfStringLiteral()
    {
        // 逐語的な補間文字列は、末尾のバックスラッシュで閉じ引用符を飲み込まない。
        // 飲み込むと、その先のコメントがコメントとして落ちず、§5 どおりの日本語コメントが
        // 「Cache-Control への直接の書き込み」として報告される(＝正しいコードで赤くなる)
        Assert.Empty(ScanCSharpLines(
            "void F() { var path = @$\"logs\\\\\"; } // Cache-Control はミドルウェアの既定に任せる"));

        // 順序を入れ替えた $@"…" も同じ(接頭辞は遡って見るので、どちらの並びでも逐語的)
        Assert.Empty(ScanCSharpLines(
            "void F() { var path = $@\"logs\\\\\"; } // Cache-Control はミドルウェアの既定に任せる"));

        // 生文字列は開始フェンスと同じ数の引用符までが中身。
        // 「空のリテラル + 余った引用符」と読むと、中身の // から先が行コメント扱いになり、
        // <b>同じ行に書かれた本物のキャッシュ指示を取り落とす</b>(＝見逃す側へ倒れる)
        Assert.Equal(
            new[] { 1 },
            ScanCSharpLines(
                "void F() { var url = \"\"\"https://example.test\"\"\"; Response.Headers.CacheControl = \"public\"; }"));
    }

    // C# のソースでは、<b>リテラルの開きを直前の文字から当てない</b>こと。
    //
    // <b>直していた穴(issue #249)。</b> 以前は「直前の非空白文字が = ( , [ { : ? + @ $ の
    // いずれかなら開き」という近似でリテラルを見分けていた。C# でいちばん普通の形の
    // いくつか(return "…" ・ =&gt; "…" ・ case "…":)がその集合に無いので、
    // それらのリテラルは 1 文字ずつ実コードとして貯められ、<b>中身に // があると
    // その行の残りが丸ごと走査から落ちた</b>。URL 文字列(https://…)がまさにこの形で、
    // 同じ行に書かれた本物のキャッシュ指示を取り落とす＝見逃す側へ倒れる。
    //
    // <b>綴りを足す直し方はしていない。</b> &gt; を集合へ足すと、今度は Razor の地の文
    // (&lt;p&gt;"レベル3 以上&lt;/p&gt;)が開きと判定されて正しいコードで赤くなる ——
    // 向きを逆に踏み直すだけ。C# は C# のパーサに読ませる(CSharpCommentScanner)。
    [Fact]
    public void CSharpScan_ReadsLiteralsWithoutGuessingFromTheCharacterBefore()
    {
        // return の後ろのリテラル: 中身の // で行の残りが落ちないこと
        Assert.Equal(
            new[] { 1 },
            ScanCSharpLines(
                """string Url() { return "https://example.test"; } void F() { Response.Headers.CacheControl = "public"; }"""));

        // 式形式のメンバー(=> の後ろ)も同じ。このリポジトリ全体に普通に現れる形
        Assert.Equal(
            new[] { 1 },
            ScanCSharpLines(
                """string Url() => "https://example.test"; void F() { Response.Headers.CacheControl = "public"; }"""));

        // case ラベルの後ろも同じ
        Assert.Equal(
            new[] { 1 },
            ScanCSharpLines(
                """void F(string s) { switch (s) { case "https://example.test": Response.Headers.CacheControl = "public"; break; } }"""));

        // <b>見逃さないだけでなく、誤検知もしないこと。</b> コメントの中の綴りは拾わない
        // (リテラルを正しく読めるようになった代わりにコメントを読み落とす、では意味がない)
        Assert.Empty(ScanCSharpLines(
            """string Url() => "https://example.test"; // Cache-Control はミドルウェアの既定に任せる"""));
    }

    // C# のソースでは、<b>改行をまたぐリテラルの中身を実コードとして走査しない</b>こと。
    //
    // <b>直していた穴(issue #252)。</b> 以前はブロックコメントの状態だけを行をまたいで
    // 持ち越し、リテラルの状態は持ち越さなかった。そのため逐語的 @"…" ・ 生文字列 """…""" の
    // <b>2 行目以降が素の実コードとして走査</b>され、そこに /* があると
    // 閉じ綴りはリテラルの中にしか無いので永久に閉じず、<b>以降のファイル全体が
    // コメント扱い</b>になって走査から落ちた。
    [Fact]
    public void CSharpScan_DoesNotInterpretTheBodyOfAMultiLineLiteral()
    {
        // 逐語的リテラルの 2 行目にある /* が、以降のファイルを飲み込まないこと
        Assert.Equal(
            new[] { 4 },
            ScanCSharpLines(
                "void F() { var sql = @\"SELECT",
                "  /* inner",
                "\"; }",
                "void G() { Response.Headers.CacheControl = \"public,max-age=300\"; }"));

        // 生文字列でも同じ(複数行の生文字列は、開始フェンスの次の行から中身が始まる)
        Assert.Equal(
            new[] { 4 },
            ScanCSharpLines(
                "void F() { var sql = \"\"\"",
                "  SELECT /* inner",
                "  \"\"\"; }",
                "void G() { Response.Headers.CacheControl = \"public,max-age=300\"; }"));

        // <b>リテラルの中身は実コードとして残ること。</b> ヘッダー名は文字列キーとして
        // 書かれる(Response.Headers["Cache-Control"])ので、読み飛ばすと本命を取り落とす
        Assert.Equal(
            new[] { 1 },
            ScanCSharpLines("void F() { Response.Headers[\"Cache-Control\"] = \"public\"; }"));
    }

    // <c>#if</c> で無効化された領域の中のコメントも、コメントとして取り除くこと。
    //
    // <b>なぜ要るのか。</b> 字句解析は成立しない側を丸ごと <c>DisabledTextTrivia</c> として
    // 扱い、その中の <c>//</c> をコメントとして分類しない。読み直さずに実コードとして残すと、
    // <b>§5 が求める日本語コメントがそのまま「キャッシュ指示の直接の書き込み」として
    // 報告される</b> ——書いた人にできるのは「規約が求めるコメントを消す」ことだけで、
    // 直しようの無い指示になる(実測)。
    //
    // <b>Web プロジェクトに <c>#if</c> は 1 つも無いので、合成した行でしか固定できない。</b>
    // 実在のソースに頼ると、読み直す分岐を消しても<b>全件緑のまま</b>通る(実測)。
    [Fact]
    public void CSharpScan_RemovesCommentsInsideDisabledPreprocessorRegions()
    {
        // 成立しない側に置いた §5 のコメントは、違反として報告されないこと
        Assert.Empty(ScanCSharpLines(
            "#if NEVER",
            "    // Cache-Control はミドルウェアの既定に任せる",
            "    var unused = 1;",
            "#endif"));

        // <b>成立する側でも同じ</b>(どちらが無効化されるかは記号の定義次第なので、
        // 片側だけ手当てすると反対側が同じ穴になる)
        Assert.Empty(ScanCSharpLines(
            "#if NEVER",
            "    // Cache-Control はここでは書かない",
            "#else",
            "    // Cache-Control はこちらでも書かない",
            "#endif"));

        // <b>無効化された領域の実コードは残ること</b>(条件次第で有効になりうるので、
        // 取りこぼす側ではなく多く報告する側へ倒す)
        Assert.Equal(
            new[] { 2 },
            ScanCSharpLines(
                "#if NEVER",
                "    Response.Headers.CacheControl = \"public\";",
                "#endif"));
    }

    // ビューでも、改行をまたぐリテラルの状態を持ち越すこと（issue #252 のビュー側）。
    //
    // <b>Razor は C# のパーサでは読めない</b>（地の文の閉じない引用符で解釈が総崩れになる）ので、
    // ビューは引き続き近似の走査が読む。issue #252 の壊れ方はビューでも同じように起きるため、
    // リテラルの持ち越しはそちらにも入れてある ——<b>C# 側だけ直すと、同じ穴が
    // .cshtml に残ったまま「直した」ことになる</b>。
    [Fact]
    public void RazorScan_CarriesMultiLineLiteralStateAcrossLines()
    {
        // issue #252 の再現そのもの。4 行目の本物の書き込みが報告されること
        Assert.Equal(
            new[] { 4 },
            ScanLines(
                "@{ var sql = @\"SELECT",
                "  /* inner",
                "\"; }",
                "@{ Context.Response.Headers.CacheControl = \"public,max-age=300\"; }"));

        // Razor のコメント開始が中身にある形も同じ(閉じ綴りはリテラルの中にしか無い)
        Assert.Equal(
            new[] { 4 },
            ScanLines(
                "@{ var sql = @\"SELECT",
                "  @* inner",
                "\"; }",
                "@{ Context.Response.Headers.CacheControl = \"public,max-age=300\"; }"));

        // <b>持ち越しが行き過ぎていないこと。</b> リテラルが閉じたあとの行は
        // ふつうに走査される(閉じても持ち越したままだと、以降が全部中身になる)
        Assert.Equal(
            new[] { 2, 3 },
            ScanLines(
                "@{ var sql = @\"SELECT",
                "x\"; Context.Response.Headers.CacheControl = \"public\"; }",
                "@{ Context.Response.Headers.CacheControl = \"private\"; }"));

        // 逐語的リテラルの中の "" は引用符 1 つを表す本文なので、そこで閉じないこと
        Assert.Equal(
            new[] { 3 },
            ScanLines(
                "@{ var sql = @\"SELECT",
                "  a\"\" b /* inner",
                "\"; Context.Response.Headers.CacheControl = \"public\"; }"));
    }

    // Razor の <c>@@</c>（地の文に <c>@</c> を書くための綴り）を 2 文字として読むこと。
    //
    // <b>実測した誤検知。</b> 1 文字ずつ進めると、<c>support@@*.example.com</c> のような
    // <b>正しいビュー</b>で 2 つ目の <c>@</c> から <c>@*</c> が始まったと読み、
    // そこから下の行が走査から落ちる。地の文に <c>@</c> を書くには <c>@@</c> と書くしか
    // ないので、メールアドレスや価格表記で普通に現れる形。
    [Fact]
    public void RazorScan_ReadsAnEscapedAtSignAsTwoPlainCharacters()
    {
        // @@* の後ろに置いた本物の書き込みが、走査から落ちないこと
        Assert.Equal(
            new[] { 2 },
            ScanLines(
                "<p>連絡先: support@@*.example.com</p>",
                "@{ Context.Response.Headers.CacheControl = \"public\"; }"));

        // <b>本物の Razor コメントは今までどおり落ちること</b>(読み飛ばしすぎていないこと)
        Assert.Empty(ScanLines(
            "<p>連絡先: support@@*.example.com</p>",
            "@* Cache-Control はミドルウェアの既定に任せる *@"));

        // <b>@@ の直後の引用符を「逐語的リテラルの開き」と読まないこと。</b>
        // 読むと、閉じないリテラルが持ち越されて<b>以降の行まで実コード扱い</b>になり、
        // §5 どおりの Razor コメントが「キャッシュ指示の書き込み」として報告される
        // (実測。持ち越しを足すまでは被害がその行に留まっていた)
        Assert.Equal(
            new[] { 3 },
            ScanLines(
                "<p>表記: support@@\"x</p>",
                "@* Cache-Control はミドルウェアの既定に任せる *@",
                "@{ Context.Response.Headers.CacheControl = \"public\"; }"));

        // 単一引用符でも同じ(片方だけ手当てすると、もう片方の綴りで同じ誤検知が残る)
        Assert.Equal(
            new[] { 3 },
            ScanLines(
                "<p>表記: support@@'x</p>",
                "@* Cache-Control はミドルウェアの既定に任せる *@",
                "@{ Context.Response.Headers.CacheControl = \"public\"; }"));
    }

    // ビューの inline script に書いた <c>//</c> のコメントを、実コードとして読まないこと。
    //
    // <b>なぜ要るのか。</b> §5 は 1 行ごとの日本語コメントを求めており、
    // <c>Views/Incidents/Create.cshtml</c> の inline script には実際に数十本の
    // <c>//</c> コメントがある。ここを実コードとして読むと、その中に走査対象の綴りを
    // 1 つ書いただけで<b>「キャッシュ指示を直接書いた」と報告される</b> ——
    // 直し方は「規約が求めるコメントを消す」しかなく、実行不能な指示になる（実測）。
    [Fact]
    public void RazorScan_DoesNotReadScriptCommentsAsCode()
    {
        // inline script の中のコメントは拾わない
        Assert.Empty(ScanLines(
            "<script>",
            "    // Cache-Control はミドルウェアの既定に任せる（この画面では触らない）",
            "</script>"));

        // 同じ行でも、コメントの<b>前</b>に実コードがあれば拾う(見逃す側へ倒れないこと)
        Assert.Equal(
            new[] { 2 },
            ScanLines(
                "<script>",
                "    @{ Context.Response.Headers.CacheControl = \"public\"; } // メモ",
                "</script>"));
    }

    /// <summary>
    /// 合成した複数行の<b>C# の</b>ソースを走査し、該当した行番号を返す(検査用の入り口)。
    /// </summary>
    /// <remarks>
    /// <b>拡張子を <c>.cs</c> にするのが要点。</b> 走査は拡張子で読み方を選ぶので、
    /// <see cref="ScanLines"/>(<c>.cshtml</c>)と同じ入力でも通る経路が違う。
    /// 片方だけを検査すると、もう片方の経路が黙って壊れても緑のまま通る。
    /// </remarks>
    /// <param name="lines">合成したソースの各行。</param>
    /// <returns>該当した行番号(1 始まり)。</returns>
    private static int[] ScanCSharpLines(params string[] lines) =>
        // 読み方を選ぶのは拡張子なので、それだけを変えて同じ入り口を使う
        ScanLinesWithExtension(".cs", lines);

    /// <summary>
    /// 合成した複数行のソースを走査し、該当した行番号を返す(検査用の入り口)。
    /// </summary>
    /// <param name="lines">合成したソースの各行。</param>
    /// <returns>該当した行番号(1 始まり)。</returns>
    private static int[] ScanLines(params string[] lines) =>
        // ビューとして読ませる(Razor 用の近似の走査を通る)
        ScanLinesWithExtension(".cshtml", lines);

    /// <summary>
    /// 合成したソースを指定の拡張子で書き出し、本物と同じ経路で走査する。
    /// </summary>
    /// <param name="extension">読み方を決める拡張子(<c>.cs</c> か <c>.cshtml</c>)。</param>
    /// <param name="lines">合成したソースの各行。</param>
    /// <returns>該当した行番号(1 始まり)。</returns>
    private static int[] ScanLinesWithExtension(string extension, string[] lines)
    {
        // 使い捨ての作業場へ書き出して、本物と同じ経路で走査する
        var path = Path.Combine(Path.GetTempPath(), $"ii-scan-{Guid.NewGuid():N}{extension}");
        // 後始末を必ず行う
        try
        {
            // 合成したソースを書き出す
            File.WriteAllLines(path, lines);
            // 本物の走査を通して、該当した行番号だけを取り出す
            return CodeLinesContaining(path, CacheControlTokens).Select(h => h.LineNumber).ToArray();
        }
        finally
        {
            // 使い捨てのファイルを消す
            File.Delete(path);
        }
    }

    /// <summary>
    /// 走査対象(Web プロジェクト配下の <c>.cs</c> と <c>.cshtml</c> すべて)。
    /// </summary>
    /// <remarks>
    /// <b>パスの形で絞らない。</b> <c>Controllers/</c> ・ <c>Views/</c> のような形で当てると、
    /// その外に置いた同じコード(<c>Pages/</c> のビュー、別フォルダの <c>partial class</c>)が
    /// 静かに外れる(実測)。除外は理由付きの
    /// <see cref="IntendedCacheControlWriters"/> だけにする。
    /// </remarks>
    /// <returns>走査対象のファイルパス。</returns>
    private static IEnumerable<string> ScannedSources() =>
        // C# のソースと Razor ビューを両方たどる(どちらの列挙も生成物を除いている)
        RepositoryPaths.EnumerateWebSourceFiles().Concat(RepositoryPaths.EnumerateViewFiles());

    // Cache-Control ヘッダーを名指ししている綴り(大文字小文字は無視して照合する)
    private static readonly string[] CacheControlTokens = ["Cache-Control", "CacheControl"];

    /// <summary>
    /// ソースからコメントを取り除いたうえで、指定した綴りを含む行を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>行を独立に見てはいけない。</b> <c>@*…*@</c> も <c>/*…*/</c> も複数行にまたがれる。
    /// 「行頭が <c>*</c> ならコメントの続き」といった行単位の当て方をすると、
    /// <b>このリポジトリで実際に使われている</b>書き方 ——<c>@*</c> だけの行で始めて
    /// 次の行から本文を書く形(<c>Views/Incidents/Create.cshtml</c> の大半がこれ)—— が
    /// コメントと見なされず、規約どおりの日本語コメントで CI が赤くなる(実測)。
    /// だからファイル全体を <b>1 本の流れ</b>として読み、ブロックコメントの内外を持ち越す。</para>
    ///
    /// <para>逆に、閉じたコメントの<b>後ろ</b>にある実コードは拾う ——
    /// <c>@* メモ *@ @{ … CacheControl = "public" … }</c> を見逃すと、
    /// この検査が塞ごうとしている「綴りを変えただけの抜け道」そのものになる。</para>
    ///
    /// <para><b><see cref="Helpers.RazorSource"/> の正規表現と統合しないのは意図的。</b>
    /// あちらが持つのは「ファイル全体の文字列から <c>@*…*@</c> を落とす」正規表現で、
    /// 入力の形（1 本の文字列 対 行ごと＋持ち越し状態）も守備範囲（Razor コメントだけ 対
    /// <c>//</c> ・ <c>/*…*/</c> ・文字列リテラル）も違う。片方へ寄せると、
    /// 既に 3 つの検査が依存しているあちらの挙動を変えることになる。
    /// §6 の「2〜3 箇所目で共通化」に照らしても、この形の利用側はまだ 1 つなので
    /// <b>ここに private のまま置く</b>。2 つ目が同じものを必要としたときに
    /// <c>Helpers/</c> へ移すこと（Razor コメントの綴り自体は言語仕様で固定なので、
    /// 2 つあることによる食い違いは起きない）。</para>
    /// </remarks>
    /// <param name="sourcePath">読み取るソースファイル。</param>
    /// <param name="tokens">探す綴り(いずれかを含めば該当)。</param>
    /// <returns>該当した行の番号(1 始まり)と、その行の内容。</returns>
    private static IEnumerable<(int LineNumber, string Text)> CodeLinesContaining(
        string sourcePath,
        IReadOnlyList<string> tokens) =>
        // 実コードだけを見て絞り込み、読み手には元の行を見せる
        CodeLines(sourcePath)
            .Where(l => tokens.Any(t => l.Code.Contains(t, StringComparison.OrdinalIgnoreCase)))
            .Select(l => (l.LineNumber, l.Text));

    /// <summary>
    /// ソースを 1 行ずつ、<b>元の行</b>と<b>コメントを取り除いた実コード</b>の対で返す。
    /// </summary>
    /// <remarks>
    /// <para><b>両方を返すのが要点。</b> 判定に使うのは実コード（コメントで検査を満たしたり
    /// 破ったりできないようにするため）だが、失敗文言に出すのは元の行でなければ
    /// 読み手が自分のファイルの中でその行を見つけられない。</para>
    ///
    /// <para><b>ファイルの読み取りは 1 回だけ。</b> 綴りごとに呼び直すと、
    /// 読み取りとコメント除去の状態機械を綴りの数だけ繰り返すことになる
    /// （CLAUDE.md §8「同じ計算・取得を繰り返さない」）。</para>
    /// </remarks>
    /// <param name="sourcePath">読み取るソースファイル。</param>
    /// <returns>行番号(1 始まり)・元の行(前後の空白を落としたもの)・実コードの組。</returns>
    private static IReadOnlyList<(int LineNumber, string Text, string Code)> CodeLines(string sourcePath)
    {
        // <b>リポジトリのソースは 1 回だけ読んで使い回す。</b> ファイルを走査する検査は
        // 4 つあり、どれも Web プロジェクト配下を丸ごと回る。素直に書くと同じ .cs を
        // 4 回 字句解析することになり、CodeLines 自身が掲げている「読み取りは 1 回だけ」
        // (§8 同じ計算・取得を繰り返さない)が、綴り単位から検査単位へ移っただけになる。
        //
        // <b>使い捨ての合成ソースは覚えない。</b> ScanLines が作る一時ファイルは
        // 毎回名前が違ううえ読み終わったら消えるので、覚えても当たらず溜まるだけ
        if (IsRepositorySource(sourcePath))
        {
            // 同じパスを読み直さずに済ませる(検査は並行して走りうるので並行辞書)
            return CodeLineCache.GetOrAdd(sourcePath, path => ReadCodeLines(path));
        }

        // 合成ソースはその場で読む
        return ReadCodeLines(sourcePath);
    }

    /// <summary>読み取り済みのソースを検査どうしで使い回すための覚え書き。</summary>
    /// <remarks>
    /// <b>配る一覧は読み取り専用にする。</b> 同じ実体を 4 つの検査が受け取るので、
    /// どれか 1 つが並べ替えや絞り込みを<b>その場で</b>行うと、残りの 3 つが
    /// 書き換わった一覧を見る ——xUnit は順番を保証しないので、結果が実行のたびに変わり、
    /// しかも「行を落とした一覧を走査して違反ゼロ」という<b>見逃す側</b>へ倒れる。
    /// 読み取り専用で配れば、その書き方はコンパイルの時点で通らない。
    /// </remarks>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<
        string, IReadOnlyList<(int LineNumber, string Text, string Code)>> CodeLineCache = new(StringComparer.Ordinal);

    /// <summary>そのパスが<b>リポジトリの中の</b>ソースかどうかを返す。</summary>
    /// <remarks>
    /// 使い捨ての合成ソース(一時領域)と分けるためだけの判定。覚えてよいのは、
    /// 1 回の実行のあいだ中身が変わらないリポジトリのファイルだけ。
    /// </remarks>
    /// <param name="sourcePath">判定するパス。</param>
    /// <returns>リポジトリ配下なら true。</returns>
    private static bool IsRepositorySource(string sourcePath) =>
        // リポジトリの根から始まっているかで見る
        Path.GetFullPath(sourcePath).StartsWith(
            Path.GetFullPath(RepositoryPaths.Root) + Path.DirectorySeparatorChar,
            StringComparison.Ordinal);

    /// <summary>
    /// ソースを 1 行ずつ、<b>元の行</b>と<b>コメントを取り除いた実コード</b>の対で読む。
    /// </summary>
    /// <param name="sourcePath">読み取るソースファイル。</param>
    /// <returns>行番号(1 始まり)・元の行・実コードの組。</returns>
    private static List<(int LineNumber, string Text, string Code)> ReadCodeLines(string sourcePath)
    {
        // <b>C# は C# のパーサに読ませる。</b> 自前の走査はリテラルとコメントの境目を
        // 綴りの前後から当てる近似なので、外れ方が「見逃す側」へ倒れていた
        // (issue #249 / #252。詳しい壊れ方は CSharpCommentScanner の解説が正本)。
        // Razor には使えない(地の文の閉じない引用符で解釈が総崩れになる)ので、拡張子で分ける
        if (Path.GetExtension(sourcePath).Equals(".cs", StringComparison.OrdinalIgnoreCase))
        {
            // 字句解析でコメントだけを取り除いた行を返す
            return CSharpCommentScanner.CodeLines(File.ReadAllText(sourcePath));
        }

        // ここから下はビュー(.cshtml)用の近似。Razor のパーサを持ち込むまでの当面の形
        // 行の分け方は C# 側と同じ規則を使う(同じ検査の 2 つの経路で行番号の数え方が
        // 割れると、失敗文言が指す行がどちらの規則のものか読み手に分からない)
        var lines = CSharpCommentScanner.SplitLines(File.ReadAllText(sourcePath));
        // コメント・リテラルの途中かどうかを行をまたいで持ち越す状態(最初はどちらの外でもない)
        var carry = RazorScanCarry.None;
        // 結果を貯める
        var result = new List<(int, string, string)>(lines.Count);

        // 先頭から順に、コメントとリテラルの内外を持ち越しながら見る
        for (var i = 0; i < lines.Count; i++)
        {
            // この行からコメントを取り除き、次の行へ持ち越す状態を受け取る
            var (code, next) = StripRazorComments(lines[i], carry);
            // 次の行の判定に使う状態を更新する
            carry = next;
            // 行番号(1 始まり)・元の行・実コードを記録する
            result.Add((i + 1, lines[i].Trim(), code.Trim()));
        }

        // <b>閉じないままファイルが終わっても、ここでは落とさない(意図的)。</b>
        //
        // 一度 fail-closed にしたが、<b>正しいビューを赤くする</b>ことが実測で分かった:
        // 表示テキストの incident_/*.csv は閉じないブロックコメントを開くし、
        // support@@*.example.com（@@ の手当てを入れる前）も同じ形で落ちた。
        // どちらも「C# のリテラルを直せ」という<b>当てはまらない指示</b>を出す。
        // しかも歯止めとしても弱く、取り違えた開きを<b>後ろの本物の閉じ綴りが閉じて
        // しまうと何も言わない</b> ——§5 がビューにコメントを求めている以上、
        // 閉じ綴りはたいていのビューに実在する(実測)。
        //
        // <b>誤検知で赤くする代わりに、見逃しを issue として持つ。</b> この走査は
        // 近似である限りどちらかの穴を持つので、綴りを足して埋めるのではなく
        // ビューを本物の Razor パーサで読むところまで運ぶ(issue #260)。

        // 全行を返す
        return result;
    }

    /// <summary>
    /// 文字列の中に綴りが<b>何回</b>現れるかを、大文字小文字を無視して数える。
    /// </summary>
    /// <remarks>
    /// <b>「含む行の本数」では足りない。</b> 同じ行に 2 つ書けば
    /// （<c>app.UseStaticFiles(a); app.UseStaticFiles(b);</c>）本数は 1 のままで、
    /// 配線が増えたことが差分に現れない（実測でこの形が素通りした）。
    /// </remarks>
    /// <param name="text">走査する文字列。</param>
    /// <param name="token">数える綴り(空は不可)。</param>
    /// <returns>現れた回数。</returns>
    /// <exception cref="ArgumentException">綴りが空のとき。</exception>
    private static int CountOccurrences(string text, string token)
    {
        // <b>空の綴りは受け付けない。</b> string.IndexOf("", i) は i を返し、
        // 進める幅が 0 なので探索位置が動かず、<b>このループは永久に回る</b> ——
        // スイートは失敗文言も無くハングし、どのテストで止まったのかも分からない。
        // 空が紛れ込む経路は実在する(綴りの表を文字列連結で組み立てたときのタイポ等)ので、
        // 黙って止まるのではなく<b>その場で落ちる</b>ほうを取る(§9 fail-closed)
        if (string.IsNullOrEmpty(token))
        {
            // 呼び出し側の綴りの表が壊れていることを名指しして落とす
            throw new ArgumentException("数える綴りが空です。綴りの表を確認してください。", nameof(token));
        }

        // 見つかった回数
        var count = 0;
        // 先頭から順に、見つかるたびにその綴りのぶんだけ進める
        for (var i = text.IndexOf(token, StringComparison.OrdinalIgnoreCase);
             i >= 0;
             i = i + token.Length <= text.Length
                 ? text.IndexOf(token, i + token.Length, StringComparison.OrdinalIgnoreCase)
                 : -1)
        {
            // 1 件数える
            count++;
        }

        // 数えた回数を返す
        return count;
    }

    /// <summary>
    /// ビュー(<c>.cshtml</c>)の走査が行をまたいで持ち越す状態。
    /// </summary>
    /// <remarks>
    /// <para><b>コメントだけでなくリテラルも持ち越す。</b> 以前はブロックコメントの
    /// 閉じ綴りしか持ち越しておらず、改行をまたぐリテラル(逐語的 <c>@"…"</c> ・
    /// 生文字列 <c>"""…"""</c>)の<b>2 行目以降が素の実コードとして走査</b>されていた。
    /// そこに <c>/*</c> や <c>@*</c> があると、閉じ綴りはリテラルの中にしか無いので
    /// 永久に閉じず、<b>以降のファイル全体がコメント扱い</b>になって走査から落ちる
    /// (issue #252。実測で、その次の行に置いた本物のキャッシュ指示が報告されなくなった)。</para>
    ///
    /// <para>持ち越すリテラルは<b>改行をまたげる 2 種類だけ</b>。ふつうの <c>"…"</c> は
    /// 改行をまたげない(またいだら文法として壊れている)ので持ち越さない ——
    /// 持ち越すと、閉じ忘れの 1 行がファイルの残り全部をリテラルの中へ引きずり込む。</para>
    /// </remarks>
    /// <param name="PendingCloser">
    /// 持ち越したブロックコメントの閉じ綴り(コメントの外なら <c>null</c>)。
    /// </param>
    /// <param name="PendingFence">
    /// 持ち越したリテラルの終端の形。<c>0</c> はリテラルの外、
    /// <see cref="VerbatimFence"/> は逐語的リテラル、
    /// <see cref="CSharpLiteral.RawStringFenceLength"/> 以上は生文字列の開始フェンスの長さ。
    /// </param>
    private readonly record struct RazorScanCarry(string? PendingCloser, int PendingFence)
    {
        /// <summary>コメントの外・リテラルの外(行の走査を素直に始めてよい状態)。</summary>
        public static RazorScanCarry None => new(null, 0);
    }

    /// <summary>
    /// 逐語的リテラル(<c>@"…"</c>)を持ち越していることを表す <c>PendingFence</c> の値。
    /// </summary>
    /// <remarks>
    /// 生文字列のフェンスは <see cref="CSharpLiteral.RawStringFenceLength"/>(3) 以上なので、
    /// それより小さい 1 を目印に使えば、同じ 1 つの数で両方を表せて取り違えようがない。
    /// </remarks>
    private const int VerbatimFence = 1;

    /// <summary>
    /// 1 行からコメントを取り除き、次の行へ持ち越す状態を返す。
    /// </summary>
    /// <param name="line">対象の 1 行。</param>
    /// <param name="carry">直前の行から持ち越した状態。</param>
    /// <returns>コメントを除いた実コードと、次の行へ持ち越す状態。</returns>
    private static (string Code, RazorScanCarry Carry) StripRazorComments(string line, RazorScanCarry carry)
    {
        // 実コードだけを貯める入れ物
        var code = new System.Text.StringBuilder();
        // 読み取り位置
        var i = 0;
        // 持ち越したブロックコメントの閉じ綴り(この行の中で書き換える)
        var pendingCloser = carry.PendingCloser;

        // <b>リテラルの途中から始まる行は、まず終端を探す。</b> ここを飛ばすと
        // リテラルの中身が実コードとして解釈され、中の /* や @* でファイルの残りが潰れる
        if (carry.PendingFence != 0)
        {
            // この行のどこでリテラルが終わるかを探す(終わらなければ -1)
            var literalEnd = FindPendingLiteralEnd(line, carry.PendingFence);

            // この行の中で終わらないなら、行すべてが中身(状態はそのまま持ち越す)
            if (literalEnd < 0)
            {
                // 中身も実コードとして貯める(ヘッダー名は文字列キーとして書かれるため)
                code.Append(line);
                // リテラルの中のままで次の行へ
                return (code.ToString(), carry);
            }

            // 終端までを中身として貯める
            code.Append(line, 0, literalEnd + 1);
            // リテラルの直後から、ふつうの走査を続ける
            i = literalEnd + 1;
        }

        // 行の終わりまで 1 文字ずつ進む
        while (i < line.Length)
        {
            // ブロックコメントの途中なら、閉じ綴りを探す
            if (pendingCloser is not null)
            {
                // この行に閉じ綴りがあるかを見る
                var close = line.IndexOf(pendingCloser, i, StringComparison.Ordinal);
                // 無ければ、この行はすべてコメント(状態は持ち越す)
                if (close < 0) return (code.ToString(), new RazorScanCarry(pendingCloser, 0));
                // あれば、その直後から実コードとして読み直す
                i = close + pendingCloser.Length;
                // コメントの外へ戻る
                pendingCloser = null;
                // 続きを見る
                continue;
            }

            // 文字列リテラルの中は、コメントの開始として読まない。
            // <b>実測した事故</b>: "Models/*.cs" のような値が 1 つあるだけで、
            // そこから先のファイル全体が「コメントの途中」と見なされ、走査が丸ごと盲になった
            // (この repo には実際にその綴りの定数がある)。URL の "https://" も同じ形で
            // 行の途中から先を落としていた
            if (line[i] == '\'')
            {
                // <b>アポストロフィは「文字リテラルとして閉じている」ときだけリテラル扱いにする。</b>
                // Razor のビューには地の文のアポストロフィ(<c>It's</c>)が普通に現れ、
                // それを開き引用符と読むと行末まで文字リテラルの中になる ——
                // 後ろに置かれた <c>@* Cache-Control … *@</c> がコメントとして落ちず、
                // <b>規約どおりの日本語コメントで CI が赤くなる</b>(誤検知で赤くなる検査は、
                // いずれ検査ごと緩められる ——この repo が繰り返し避けている形)
                if (TryReadQuotedRun(line, i, out var charLiteralEnd))
                {
                    // 閉じている文字リテラルなので、中身は実コードとして残したまま読み飛ばす
                    code.Append(line, i, charLiteralEnd - i);
                    // リテラルの直後から続きを見る
                    i = charLiteralEnd;
                    // 続きを見る
                    continue;
                }

                // 閉じていなければ地の文のアポストロフィなので、ただの 1 文字として読む
                code.Append(line[i]);
                // 次の文字へ
                i++;
                // 続きを見る
                continue;
            }

            if (line[i] == '"')
            {
                // <b>地の文の二重引用符は開きとして読まない。</b> アポストロフィと同じ理由で、
                // 閉じない " が地の文にあると行末までリテラル扱いになり、後ろの
                // @*…*@ がコメントとして落ちず §5 どおりのコメントで赤くなる
                // (例: <p>重症度は "レベル3 以上が対象</p> @* Cache-Control は既定に任せる *@)
                if (!IsQuoteOpener(line, i))
                {
                    // 地の文の 1 文字として実コードへ残す
                    code.Append(line[i]);
                    // 次の文字へ
                    i++;
                    // 続きを見る
                    continue;
                }

                // 閉じ引用符の位置を共有ヘルパーに求める(逐語的 @"…" ・ 生文字列 """…""" もここで扱う)
                var closingQuote = CSharpLiteral.FindStringLiteralEnd(line, i);
                //
                // <b>「開きの直後から走査を続ける」形にしてはいけない。</b> 一度そうしたが、
                // リテラルの中身が実コードとして<b>解釈される</b>ようになり、中に // や /* が
                // あるとそこで打ち切られる/以降の行がコメント状態のまま潰される ——
                // 実測で @"SELECT /* inner … の次の行に置いた本物の書き込みが報告されなく
                // なった。<b>誤検知を消すつもりで見逃しを作る</b>、この repo が繰り返し
                // 記録している向きの誤りそのもの。
                //
                // 代償は「開始行の後ろに置いたコメントも中身として扱われる」こと。
                // 正しい C# ではそこは実際にリテラルの中身なので解釈としては正しく、
                // 倒れる向きも<b>多く報告する側</b>(この走査は中身を実コードとして貯める
                // 設計なので、もともと過剰報告を許容している)。見逃すよりこちらを取る。
                // 閉じなかったら行末までを中身と見なす(解釈しないので、そこに書かれた
                // キャッシュ指示は見逃さない)。<b>この向きは main から変えていない</b> ——
                // 逆向き(地の文として走査を続ける)にすると、中身の // や /* が解釈されて
                // 以降が潰れる。どちらの向きにも穴が残るが、それはこの走査が本物のパーサでは
                // ないことから来るもので、綴りを足して直すべきではない(issue #249 / #252)
                var end = closingQuote >= 0 ? closingQuote + 1 : line.Length;

                // <b>この行で閉じなかったリテラルは、次の行へ持ち越す。</b>
                // 持ち越さないと 2 行目以降が素の実コードとして走査され、中の /* や @* で
                // ファイルの残りがコメント扱いになる(issue #252)。またげるのは
                // 逐語的リテラルと生文字列だけなので、その 2 つだけを持ち越す
                if (closingQuote < 0)
                {
                    // 開きの引用符が何個続いているか(3 つ以上なら生文字列のフェンス)
                    var fence = CSharpLiteral.QuoteRunLength(line, i);

                    // 生文字列なら、同じ長さのフェンスが終端になる
                    if (!CSharpLiteral.IsVerbatim(line, i) && fence >= CSharpLiteral.RawStringFenceLength)
                    {
                        // 中身をすべて貯めて、フェンスの長さを持ち越す
                        code.Append(line, i, line.Length - i);
                        // 生文字列の中のまま次の行へ
                        return (code.ToString(), new RazorScanCarry(pendingCloser, fence));
                    }

                    // 逐語的リテラルなら、重ねていない " が終端になる
                    if (CSharpLiteral.IsVerbatim(line, i))
                    {
                        // 中身をすべて貯めて、逐語的であることを持ち越す
                        code.Append(line, i, line.Length - i);
                        // 逐語的リテラルの中のまま次の行へ
                        return (code.ToString(), new RazorScanCarry(pendingCloser, VerbatimFence));
                    }

                    // ふつうの "…" は改行をまたげないので持ち越さない
                    // (持ち越すと、閉じ忘れの 1 行がファイルの残り全部を飲み込む)
                }

                // <b>中身は実コードとして残す。</b> ヘッダー名は文字列キーとして書かれる
                // (Response.Headers["Cache-Control"] = …)ので、読み飛ばすと本命を取り落とす。
                // ここでやりたいのは「リテラルの中の記号をコメントの開始と読まない」ことだけ
                code.Append(line, i, end - i);
                // リテラルの直後から続きを見る
                i = end;
                // 続きを見る
                continue;
            }

            // 行コメントが始まったら、そこから先は読まない
            if (StartsWithAt(line, i, "//")) break;

            // <b>@@ は Razor の「@ そのもの」のエスケープなので、2 文字まとめて読む。</b>
            // 1 文字ずつ進めると、support@@*.example.com のような<b>正しいビュー</b>で
            // 2 つ目の @ から @* が始まったと読み、そこから下の行が走査から落ちる(実測)。
            // 地の文に @ を書くには @@ と書くしかないので、この形は普通に現れる
            if (StartsWithAt(line, i, "@@"))
            {
                // エスケープされた @ を実コードとして残す(2 文字ぶん)
                code.Append(line, i, 2);
                // 次の文字へ
                i += 2;

                // <b>直後の引用符は「逐語的リテラルの開き」ではない。</b>
                // 開きの判定は直前の非空白文字を見るので、@@ の 2 つ目の @ を
                // <c>@"</c> の接頭辞と取り違える ——地の文の <c>support@@"x</c>
                // (Razor として正しく、@ を 1 つ表示する)が閉じない逐語的リテラルを開き、
                // <b>持ち越しによって以降の行まで実コード扱い</b>になって、
                // §5 どおりの Razor コメントが「キャッシュ指示の書き込み」として
                // 報告される(実測。持ち越しを足すまでは被害がその行に留まっていた)。
                // エスケープされた @ は接頭辞になりえないので、ここで 1 文字進めて断ち切る
                if (i < line.Length && (line[i] == '"' || line[i] == '\''))
                {
                    // 引用符をただの 1 文字として残す
                    code.Append(line[i]);
                    // その次から続きを見る
                    i++;
                }

                // 続きを見る
                continue;
            }

            // Razor のブロックコメントが始まったら、閉じ綴りを待つ状態にする
            if (StartsWithAt(line, i, "@*")) { pendingCloser = "*@"; i += 2; continue; }
            // C# のブロックコメントも同様
            if (StartsWithAt(line, i, "/*")) { pendingCloser = "*/"; i += 2; continue; }

            // ここまで来た文字は実コードなので貯める
            code.Append(line[i]);
            // 次の文字へ
            i++;
        }

        // 実コードと、次の行へ持ち越す状態を返す
        // (ここに来た時点でリテラルは閉じているので、持ち越すのはコメントの状態だけ)
        return (code.ToString(), new RazorScanCarry(pendingCloser, 0));
    }

    /// <summary>
    /// 直前の行から持ち越したリテラルが、この行のどこで終わるかを返す(終わらなければ <c>-1</c>)。
    /// </summary>
    /// <remarks>
    /// <para>終端の規則はリテラルの種類で違う。
    /// <list type="bullet">
    ///   <item>逐語的(<c>@"…"</c>) … 重ねていない <c>"</c> が終端。<c>""</c> は引用符 1 つを表す本文。</item>
    ///   <item>生文字列(<c>"""…"""</c>) … 開始と<b>同じ数以上</b>の引用符の連なりが終端。</item>
    /// </list>
    /// どちらの規則も <see cref="CSharpLiteral"/> が持つ数え方
    /// (<see cref="CSharpLiteral.QuoteRunLength"/>)の上に書いてあり、ここで数え直さない。</para>
    ///
    /// <para><b>開きの行と同じ関数で扱わない理由。</b> 開きの行は
    /// <see cref="CSharpLiteral.FindStringLiteralEnd"/> が「開きの引用符の位置」から読むが、
    /// 2 行目以降には開きが無い ——同じ関数に渡すと、行頭の文字を開きと取り違える。</para>
    /// </remarks>
    /// <param name="line">対象の行。</param>
    /// <param name="fence">
    /// 持ち越したリテラルの終端の形(<see cref="VerbatimFence"/> か、生文字列のフェンスの長さ)。
    /// </param>
    /// <returns>終端の最後の文字の位置。この行で終わらなければ <c>-1</c>。</returns>
    private static int FindPendingLiteralEnd(string line, int fence)
    {
        // 生文字列は、開始と同じ数以上の引用符の連なりが終端になる
        if (fence >= CSharpLiteral.RawStringFenceLength)
        {
            // 行の先頭から 1 文字ずつ、引用符の連なりを探す
            for (var i = 0; i < line.Length; i++)
            {
                // その位置から続く引用符の数を数える
                var run = CSharpLiteral.QuoteRunLength(line, i);
                // フェンスに満たないなら本文の一部(0 のときも 1 文字進める)
                if (run < fence) { i += run; continue; }
                // 満たしたので、その連なりの最後の文字が終端
                return i + fence - 1;
            }

            // この行では終わらなかった
            return -1;
        }

        // 逐語的リテラルは、重ねていない " が終端になる
        for (var i = 0; i < line.Length; i++)
        {
            // 引用符でなければ本文の一部
            if (line[i] != '"') continue;

            // 2 つ続いているなら引用符 1 つを表す本文なので、まとめて読み飛ばす
            if (i + 1 < line.Length && line[i + 1] == '"') { i++; continue; }

            // 重ねていない引用符なので、ここが終端
            return i;
        }

        // この行では終わらなかった
        return -1;
    }

    /// <summary>単一引用符が「リテラルの開き」だと見なせる直前の文字。</summary>
    /// <remarks>
    /// 属性値（<c>src=</c>）と、文字列・文字リテラル（<c>= "x"</c> ・ <c>f('x')</c> ・
    /// <c>[ 'x' ]</c> ・ 連結の <c>+ "x"</c> ・ 逐語的の <c>@"x"</c> ・ 補間の <c>$"x"</c>）を
    /// 覆い、地の文（直前が英数字の <c>Bob's</c> ・ <c>重症度は "レベル3</c>）を外すための集合。
    /// <b><c>'</c> と <c>"</c> の両方に同じ規則を当てる</b> ——片方だけ手当てすると、
    /// もう片方の綴りで同じ誤検知が残る。
    /// </remarks>
    private const string QuoteOpenerPredecessors = "=(,[{:?+@$";

    /// <summary>
    /// その位置の引用符が、リテラルの<b>開き</b>に見えるかを返す。
    /// </summary>
    /// <remarks>
    /// 直前の非空白文字が <see cref="QuoteOpenerPredecessors"/> のいずれかなら開き。
    /// 行頭（直前に文字が無い）も開きとして扱う ——継続行の先頭に置かれたリテラル
    /// （<c>"https://…".Length</c> のような形）を地の文と誤判定しないため。
    /// </remarks>
    /// <param name="line">対象の行。</param>
    /// <param name="index">引用符の位置。</param>
    /// <returns>リテラルの開きに見えれば true。</returns>
    private static bool IsQuoteOpener(string line, int index)
    {
        // 直前の非空白文字を探す(空白は読み飛ばす)
        var previous = index - 1;
        // 空白のあいだは戻り続ける
        while (previous >= 0 && char.IsWhiteSpace(line[previous])) previous--;

        // 行頭なら開きとして扱う
        if (previous < 0) return true;

        // 直前が「開きに見える文字」かどうかで決める
        return QuoteOpenerPredecessors.Contains(line[previous]);
    }

    /// <summary>
    /// その位置の単一引用符が<b>リテラル（文字リテラル・属性値）の開き</b>かを判定し、
    /// そうなら閉じ引用符の直後の位置を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>判定は 2 つ: 「開きに見えるか」と「その行の中で閉じているか」。</b>
    /// 開きに見えるかは<b>直前の非空白文字</b>で決める ——
    /// <c>=</c> <c>(</c> <c>,</c> <c>[</c> <c>{</c> <c>:</c> <c>?</c> のいずれかなら
    /// 属性値（<c>src='…'</c>）か文字リテラル（<c>= 'x'</c> ・ <c>f('x')</c>）で、
    /// 英数字なら地の文のアポストロフィ（<c>Bob's</c>）。</para>
    ///
    /// <para><b>なぜ「閉じているか」だけでは足りないのか（実測）。</b>
    /// <c>&lt;p&gt;Bob's report&lt;/p&gt; @* Cache-Control … *@ &lt;a href='x'&gt;</c> は
    /// <c>Bob's</c> の <c>'</c> が <c>href='</c> の <c>'</c> で閉じてしまい、
    /// あいだの <c>@*…*@</c> がコメントとして読まれず、§5 どおりの日本語コメントで
    /// CI が赤くなった。直前の文字を見れば <c>Bob's</c> は開きではないと分かる。</para>
    ///
    /// <para><b>なぜ「長さ」で縛らないのか（実測）。</b> 一度「中身が 8 文字まで」で
    /// 縛ったが、Razor では <c>'</c> が属性の引用符にもなるため <c>src='https://…'</c> が
    /// リテラルとして読めなくなり、中の <c>//</c> で行の残りが走査から落ちた ——
    /// <b>誤検知を消すつもりで見逃しを作っていた</b>（向きを間違えた手当ての実例）。</para>
    ///
    /// <para><b>残っている境界。</b> これは「増やしたことに気付く」ための網であって
    /// 証明ではない（<see cref="CSharpLiteral.FindStringLiteralEnd"/> の解説と同じ立場）。
    /// 開きの判定は綴りの前後を見るだけなので、補間文字列の入れ子のような形は追わない。
    /// <b>次に穴が出たら、綴りを 1 つずつ足すのではなく本物のパーサへ移すこと。</b></para>
    ///
    /// <para><b>外し方は安全側。</b> リテラルでないと判断したアポストロフィは
    /// ただの 1 文字として実コードへ残すので、取りこぼす方向（＝見逃し）には倒れない。
    /// 倒れるとしても「コメントの開始をコメントとして正しく読む」方向だけ。</para>
    ///
    /// <para><b><c>"</c> 側に同じ歯止めを置かない理由。</b> C# の文字列リテラルは長さに上限が無く、
    /// 上限を決めると本物のリテラルを取りこぼす。閉じないアポストロフィと違って、
    /// 閉じない <c>"</c> がマークアップの地の文に現れることは実質無い
    /// （属性値は必ず閉じる）ので、単純な走査のままにしてある。</para>
    /// </remarks>
    /// <param name="line">対象の行。</param>
    /// <param name="start">アポストロフィの位置。</param>
    /// <param name="end">読めた場合、リテラルの直後の位置。</param>
    /// <returns>リテラルの開きで、かつその行の中で閉じていれば true。</returns>
    private static bool TryReadQuotedRun(string line, int start, out int end)
    {
        // 直前の文字から、リテラルの開きに見えるかを判定する
        if (!IsQuoteOpener(line, start))
        {
            // 呼び出し側が読み進める位置を変えないようにする
            end = start;
            // リテラルではない
            return false;
        }

        // 開きに見えるので、その行の中で閉じているかを見る(長さでは縛らない)
        var close = CSharpLiteral.FindCharLiteralEnd(line, start);

        // 閉じなかった(または長すぎた)ので、地の文のアポストロフィとして扱う
        if (close < 0)
        {
            // 呼び出し側が読み進める位置を変えないようにする
            end = start;
            // 文字リテラルではない
            return false;
        }

        // リテラルの直後の位置を返す
        end = close + 1;
        // 文字リテラルとして読めた
        return true;
    }

    /// <summary>指定位置がその綴りで始まるかを返す(範囲外でも例外にしない)。</summary>
    /// <param name="line">対象の行。</param>
    /// <param name="index">調べる位置。</param>
    /// <param name="token">綴り。</param>
    /// <returns>その位置が綴りで始まれば true。</returns>
    private static bool StartsWithAt(string line, int index, string token) =>
        // 残りの長さが足りていて、かつその綴りで始まるか
        index + token.Length <= line.Length
            && string.CompareOrdinal(line, index, token, 0, token.Length) == 0;

    /// <summary>
    /// その 1 行が、コメントを取り除いたうえで <c>Cache-Control</c> ヘッダーを名指ししているかを返す。
    /// </summary>
    /// <remarks>
    /// 単独の行として判定する入り口(合成入力の検査が使う)。ファイル全体を読むときは
    /// <see cref="CodeLinesContaining"/> がブロックコメントの内外を持ち越す。
    /// </remarks>
    /// <param name="line">判定するソースの 1 行。</param>
    /// <returns>コメントを除いた部分がヘッダー名を含んでいれば true。</returns>
    private static bool MentionsCacheControl(string line)
    {
        // コメントの外・リテラルの外から読み始めて、この行の実コードを取り出す
        var (code, _) = StripRazorComments(line, RazorScanCarry.None);
        // 照合の規則は 1 か所が持つ
        return ContainsCacheControlToken(code);
    }

    /// <summary>
    /// その実コードが <c>Cache-Control</c> ヘッダーを名指ししているかを返す。
    /// </summary>
    /// <remarks>
    /// <b>照合の規則を 1 か所に置く。</b> ビューの経路と C# の経路で同じ問いを立てるので、
    /// 書き写すと綴りを足したときに片方だけが新しい規則で答える(§6 DRY)。
    /// 大文字小文字は無視する ——HTTP のヘッダー名は区別しない。
    /// </remarks>
    /// <param name="code">コメントを取り除いた実コード。</param>
    /// <returns>ヘッダー名を含んでいれば true。</returns>
    private static bool ContainsCacheControlToken(string code) =>
        // 見張っている綴りのどれかを含むか
        CacheControlTokens.Any(t => code.Contains(t, StringComparison.OrdinalIgnoreCase));


    // クラスに付いた属性が、基底で宣言されていれば<b>基底の名前で 1 件だけ</b>報告されること。
    //
    // <b>なぜ要るのか。</b> 継承した属性は派生型からも見えるので、具象の名前で報告すると
    // (a) 同じ 1 つの宣言が派生の数だけ並び、(b) 名指しされたファイルを開いても属性が無く、
    // 直すべき 1 か所(基底)がどこにも出てこない。アクション側には同じ内容の検査
    // (DeclarationScan_ReportsAnInheritedActionOnlyOnce)があるが、クラス側には無かった。
    //
    // <b>この検査は一度「走査の作り直し」で巻き添えに消えた。</b> 消えている間、
    // ResponseCachePolicy.DeclaringTypeOf(Type) の本体を `return controller;` に潰しても
    // 898 件すべて緑のまま通った(実測)——クラス側の宣言を持つ合成コントローラが
    // 自分で宣言している 1 つだけになり、基底をたどる経路が一度も実行されないため。
    [Fact]
    public void DeclarationScan_ReportsAnInheritedClassAttributeOnceAndNamesTheBase()
    {
        // 同じ抽象基底を継承する 2 つの具象コントローラを走査する
        var declarations = ScanProbes(
            typeof(ClassLevelInheritedProbeController),
            typeof(SecondClassLevelInheritedProbeController));

        // 基底のクラス属性(Duration = 77)に由来する宣言が 1 件だけであること
        var inherited = Assert.Single(declarations, d => d.Attribute.Duration == 77);
        // 名指しが、属性を実際に宣言している基底であること(派生の名前ではない)
        Assert.Contains(
            nameof(ClassLevelInheritedProbeControllerBase),
            inherited.DeclaredOn,
            StringComparison.Ordinal);
    }

    // 2 種類以上に一致する述語を渡したとき、<b>同じ宣言元に付いた別々の属性が両方とも返る</b>こと。
    //
    // <b>なぜ要るのか（fail-open の実例）。</b> AttributeDeclarationsOn は自身を
    // 「属性の種類を問わない走査」と名乗り、新しい属性種別での再利用を促している。
    // ところが重複除去のキーが「どの属性が一致したか」を持っていなかった頃は、
    // 3 つ目のキャッシュ指示（[OutputCache] 等）を見るために述語を
    // <c>a => a is ResponseCacheAttribute || a is OutputCacheAttribute</c> と広げた瞬間、
    // 同じコントローラに両方が付いていても<b>先に返った 1 件しか yield されず</b>、
    // もう 1 件は違反の一覧へ到達しなかった。検査は緑のまま、PHI を含みうる応答に
    // 共有キャッシュ可能な指示が残る ——<b>痕跡はテスト件数にも出ない</b>。
    //
    // <b>現在の配線は 1 種類しか見ていないので、合成入力でしか固定できない。</b>
    // ResponseCacheAttribute だけを渡している限り、キーを直しても本番の挙動は変わらず、
    // 直したこと自体が無検証になる（この repo が Stripe の API 版ガードで学んだ形）。
    //
    // <b>この検査が固定する範囲。</b> 「宣言元だけをキーにする」版（＝この PR 以前）を落とす
    // （実測: キーから属性の型を落とすと、クラス側・アクション側の Assert.Single が落ちる）。
    // <b>覆うのは「同じ宣言元に 2 種類」の形だけ</b>で、宣言元が具象と基底に分かれる形は
    // AttributeScan_KeepsEachKindOnItsOwnDeclaringType_WhenAConcreteTypeRedeclaresOne が見る。
    [Fact]
    public void AttributeScan_ReturnsEveryMatchedKind_NotJustTheFirstOnEachDeclaration()
    {
        // 「2 種類のどちらかなら拾う」という、3 つ目の指示を足すときに最も自然な述語
        var declarations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                [typeof(TwoKindsProbeController)],
                typeof(ResponseCacheAttributePolicyTests).Assembly,
                a => a is ResponseCacheAttribute or SecondKindProbeAttribute)
            .ToList();

        // クラス側の宣言は、宣言元の表示名が<b>型の完全修飾名そのもの</b>になる。
        // <b>".Probe で終わるか" で切らない</b> ——合成型の名前が Probe で終わるように
        // 変わっただけで、クラス側の宣言がアクション側として数えられ、
        // 「本物の退行なのに緑」にも「正しいのに赤」にも振れる
        var classLevelName = typeof(TwoKindsProbeController).FullName;
        var classLevel = declarations
            .Where(d => string.Equals(d.DeclaredOn, classLevelName, StringComparison.Ordinal))
            .ToList();

        // クラス側の 1 種類目（キーが宣言元だけ＝型も通し番号も無い版では、
        // どちらか一方しか返らず落ちる）
        Assert.Single(classLevel, d => d.Attribute is ResponseCacheAttribute { Duration: 88 });
        // クラス側の 2 種類目
        Assert.Single(classLevel, d => d.Attribute is SecondKindProbeAttribute);

        // アクション側の宣言は、その名前にアクション名が続く
        var actionLevel = declarations
            .Where(d => !string.Equals(d.DeclaredOn, classLevelName, StringComparison.Ordinal))
            .ToList();

        // アクション側の 1 種類目（キーがシグネチャだけだと、こちらも 1 件に畳まれる）
        Assert.Single(actionLevel, d => d.Attribute is ResponseCacheAttribute { Duration: 99 });
        // アクション側の 2 種類目
        Assert.Single(actionLevel, d => d.Attribute is SecondKindProbeAttribute);
    }

    // 2 種類以上に一致する述語のとき、<b>名指しが「その属性を実際に宣言している型」</b>であること。
    //
    // <b>なぜ要るのか。</b> 宣言元をたどる条件にも述語をそのまま渡していた頃は、
    // 基底が A・派生が B を宣言していると、A についても「派生が宣言している」と答えた
    // （派生が B に一致してしまうため）。名指しされたファイルを開いても A が無く、
    // 直すべき 1 か所が出てこない ——基底へ引き上げた宣言で一度直した形そのもの。
    [Fact]
    public void AttributeScan_NamesTheTypeThatDeclaredThatKind_WhenKindsAreSplitAcrossTheHierarchy()
    {
        // 基底が [ResponseCache]、派生が 2 種類目を宣言している形を走査する
        var declarations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                [typeof(SplitKindsProbeController)],
                typeof(ResponseCacheAttributePolicyTests).Assembly,
                a => a is ResponseCacheAttribute or SecondKindProbeAttribute)
            .ToList();

        // 基底で宣言された [ResponseCache] の宣言を取り出す
        var inherited = Assert.Single(
            declarations,
            d => d.Attribute is ResponseCacheAttribute { Duration: 66 });

        // 名指しは基底（派生は 2 種類目しか宣言していない）
        Assert.Contains(
            nameof(SplitKindsProbeControllerBase),
            inherited.DeclaredOn,
            StringComparison.Ordinal);
    }

    // 重複除去のキーの<b>属性の型</b>の部分が効いていること。
    //
    // <b>なぜ上の検査と別に要るのか。</b> AttributeScan_ReturnsEveryMatchedKind は
    // 2 種類が<b>同じ宣言元</b>に付いた形しか見ない。こちらは<b>宣言元が具象と基底に
    // 分かれる</b>形 ——具象が 2 種類目を宣言し直すと、その具象からは基底の 2 種類目が
    // 見えなくなり、走査ごとに「その宣言元で見える同じ種類の数」が変わる。
    // 宣言元をたどる側（SameKindAs）とキーの側が噛み合っていないと、ここで崩れる:
    //
    //   Base   : [SecondKindProbe] [ResponseCache(12)]
    //   LeafA  : [SecondKindProbe]（自分で宣言し直す。AllowMultiple = false なので基底の分は見えない）
    //   LeafB  : 素の継承
    //
    // 正しい実装では 3 件（LeafA の 2 種類目 / Base の 1 種類目 / Base の 2 種類目）。
    // キーから型を落とすと Base の宣言元で 2 種類が同じキーになり、<b>2 件に減る</b>
    // （実測: 落ちるのは下の Assert.Equal(3, …)）。内訳の Assert.Single は
    // 「どちらが消えたか」まで押さえるために置いてあるので、件数だけに削らないこと。
    [Fact]
    public void AttributeScan_KeepsEachKindOnItsOwnDeclaringType_WhenAConcreteTypeRedeclaresOne()
    {
        // 2 種類に一致する述語で、2 つの具象を走査する
        var declarations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                [typeof(SharedSiteProbeLeafA), typeof(SharedSiteProbeLeafB)],
                typeof(ResponseCacheAttributePolicyTests).Assembly,
                a => a is ResponseCacheAttribute or SecondKindProbeAttribute)
            .ToList();

        // 内訳が「これで全部」であることの締め（下の 3 つと必ずセットで読む）
        Assert.Equal(3, declarations.Count);

        // <b>ここからが検出器。</b> 基底の 1 種類目が、基底の名前で 1 件
        // （型をキーから落とすと、ここが 2 件になって落ちる）
        Assert.Single(
            declarations,
            d => d.Attribute is ResponseCacheAttribute { Duration: 12 }
                && d.DeclaredOn.Contains(nameof(SharedSiteProbeBase), StringComparison.Ordinal));

        // 基底の 2 種類目が、基底の名前で 1 件
        Assert.Single(
            declarations,
            d => d.Attribute is SecondKindProbeAttribute
                && d.DeclaredOn.EndsWith(nameof(SharedSiteProbeBase), StringComparison.Ordinal));

        // 具象が宣言し直した 2 種類目が、その具象の名前で 1 件
        Assert.Single(
            declarations,
            d => d.Attribute is SecondKindProbeAttribute
                && d.DeclaredOn.EndsWith(nameof(SharedSiteProbeLeafA), StringComparison.Ordinal));
    }

    /// <summary>2 種類の属性をクラス側に宣言する抽象基底。</summary>
    /// <remarks>期間の値(12)は、この経路で拾えたことを見分けるための目印。</remarks>
    [SecondKindProbe]
    [ResponseCache(Duration = 12)]
    private abstract class SharedSiteProbeBase : ControllerBase;

    /// <summary>2 種類目だけを自分で宣言し直す具象（宣言元が基底から移る）。</summary>
    [SecondKindProbe]
    private sealed class SharedSiteProbeLeafA : SharedSiteProbeBase;

    /// <summary>基底の 2 種類をそのまま継承する具象。</summary>
    private sealed class SharedSiteProbeLeafB : SharedSiteProbeBase;

    // 同じ宣言元へ<b>複数付けられる種類</b>の属性に出会ったら、黙って畳まずに落ちること。
    //
    // <b>なぜ畳まずに落とすのか。</b> この走査は (宣言元, 属性の種類) で重複を畳むので、
    // AllowMultiple = true の属性が同じ宣言元に 2 つ付いていると 2 個目以降が消える。
    // <b>許す側の宣言がたまたま 2 個目だと、検査は緑のまま PHI を含みうる応答に
    // 共有キャッシュ可能な指示が残る</b>。
    //
    // <b>なぜキーへ位置を入れて「直して」おかないのか。</b> 実在のキャッシュ指示属性は
    // すべて AllowMultiple = false なので、この形は今のところ作れない。先回りで入れると
    // GetCustomAttributes の規定されていない並び順に答えが依存し、基底の宣言が派生の名前でも
    // 報告される境界を新たに作る ——実在しない事情のために払う代償としては大きい
    // （CLAUDE.md §6）。代わりに門番を置いて、<b>実際に足す人が必ず一度手を止める</b>ようにした。
    [Fact]
    public void AttributeScan_RefusesToScan_WhenTheAttributeCanBeAppliedMoreThanOnce()
    {
        // 複数付けられる属性を拾う述語で走査すると落ちること
        var error = Assert.Throws<NotSupportedException>(() =>
            ResponseCachePolicy
                .AttributeDeclarationsOn(
                    [typeof(RepeatedKindProbeController)],
                    typeof(ResponseCacheAttributePolicyTests).Assembly,
                    a => a is RepeatableProbeAttribute)
                .ToList());

        // 何が問題かが失敗文言から分かること（黙って畳まれたのと区別が付くように）
        Assert.Contains(nameof(RepeatableProbeAttribute), error.Message, StringComparison.Ordinal);

        // 直し方まで案内していること（キーだけ直して DeclaringTypeOf を放置させない）
        Assert.Contains("DeclaringTypeOf", error.Message, StringComparison.Ordinal);
    }

    // 複数付けられる属性が<b>1 つしか付いていない</b>ときは、走査を止めないこと。
    //
    // <b>門番は「その属性を見かけたら」ではなく「実際に畳んだら」鳴らす。</b>
    // 前者だと、複数付けられる指示を 1 つ足しただけでアセンブリ全体の走査が落ち、
    // <b>本物の違反が 1 件も報告されなくなる</b>（しかも失敗文言は違反ではなくキーの話をする）。
    // fail-closed は保ったまま、正しくできる仕事は止めない。
    [Fact]
    public void AttributeScan_StillWorks_WhenARepeatableAttributeAppearsOnlyOnce()
    {
        // 複数付けられる属性が 1 つだけ付いた合成コントローラを走査する
        var declarations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                [typeof(SingleRepeatableProbeController)],
                typeof(ResponseCacheAttributePolicyTests).Assembly,
                a => a is RepeatableProbeAttribute)
            .ToList();

        // 落ちずに 1 件返ること
        var declared = Assert.Single(declarations);

        // 中身も読めること
        Assert.Equal("only", ((RepeatableProbeAttribute)declared.Attribute).Policy);
    }

    // 門番が<b>アクション側でも</b>効いていること。
    //
    // <b>なぜ別に要るのか（実測）。</b> 門番はキーを作る DeclarationKey の中にあるので、
    // アクション側がキーを自前で組み立てる形に戻ると素通りする ——値が同じなので
    // 全件緑のまま通った。この PR は SameKindAs でまったく同じクラス側／アクション側の
    // 非対称を踏んでいるので、門番にも同じ対の検査を置く。
    [Fact]
    public void AttributeScan_RefusesToScan_WhenAnActionCarriesTheAttributeMoreThanOnce()
    {
        // アクション側に複数付けた合成コントローラを走査すると落ちること
        var error = Assert.Throws<NotSupportedException>(() =>
            ResponseCachePolicy
                .AttributeDeclarationsOn(
                    [typeof(RepeatedKindOnActionProbeController)],
                    typeof(ResponseCacheAttributePolicyTests).Assembly,
                    a => a is RepeatableProbeAttribute)
                .ToList());

        // 何が問題かが失敗文言から分かること
        Assert.Contains(nameof(RepeatableProbeAttribute), error.Message, StringComparison.Ordinal);
    }

    // アクション側でも、宣言元をたどる条件が<b>その属性の型</b>まで絞られていること。
    //
    // <b>なぜクラス側の検査では足りないのか（実測）。</b> 種類が階層で分かれる形の合成は
    // クラス側にしか無く、アクション側の SameKindAs を外しても 1080 件すべて緑のまま通った。
    // 壊れ方はクラス側と同じで、基底の Export が [ResponseCache]・中間型の override が
    // 2 種類目を宣言していると、[ResponseCache] の宣言が<b>中間型の名前で報告される</b> ——
    // 名指しされたファイルを開いてもその属性は無い。
    [Fact]
    public void AttributeScan_NamesTheDeclaringTypePerKind_ForActionsToo()
    {
        // 2 種類に一致する述語で、アクション側に種類が分かれた階層を走査する
        var declarations = ResponseCachePolicy
            .AttributeDeclarationsOn(
                [typeof(SplitKindsActionProbeLeaf)],
                typeof(ResponseCacheAttributePolicyTests).Assembly,
                a => a is ResponseCacheAttribute or SecondKindProbeAttribute)
            .ToList();

        // 根が宣言した 1 種類目を取り出す
        var inherited = Assert.Single(
            declarations,
            d => d.Attribute is ResponseCacheAttribute { Duration: 23 });

        // 名指しが根であること（2 種類目を宣言している中間型ではない）
        Assert.Contains(
            nameof(SplitKindsActionProbeRoot),
            inherited.DeclaredOn,
            StringComparison.Ordinal);
    }

    /// <summary>アクションに 1 種類目だけを宣言する根。</summary>
    /// <remarks>期間の値(23)は、この経路で拾えたことを見分けるための目印。</remarks>
    private abstract class SplitKindsActionProbeRoot : ControllerBase
    {
        /// <summary>1 種類目を宣言する virtual なアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 23)]
        public virtual IActionResult Export() => NoContent();
    }

    /// <summary>同じアクションを override して<b>2 種類目だけ</b>を宣言する中間型。</summary>
    private abstract class SplitKindsActionProbeMid : SplitKindsActionProbeRoot
    {
        /// <summary>2 種類目だけを宣言する override。</summary>
        /// <returns>内容を持たない結果。</returns>
        [SecondKindProbe]
        public override IActionResult Export() => NoContent();
    }

    /// <summary>属性を付けずに override だけする具象。</summary>
    private sealed class SplitKindsActionProbeLeaf : SplitKindsActionProbeMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    // 階層の<b>途中</b>の override に付いた属性が、その型の名前で 1 件だけ報告されること。
    //
    // <b>なぜ要るのか。</b> GetBaseDefinition() が返すのは「最初に virtual として宣言された
    // 定義」なので、属性が階層の途中の override に付いていると根にも自分自身にも無い。
    // 根へ一足飛びに跳ぶ実装では<b>どちらの検査も外れて具象が名指しされ</b>、
    // 1 つの宣言が具象の数だけ違反として並び、しかも名指しされたファイルを開いても
    // 属性が無い ——DeclaringTypeOf が防ぐために存在する形そのものが復活する（実測で 2 件並んだ）。
    [Fact]
    public void DeclarationScan_NamesTheMidHierarchyOverrideThatActuallyDeclaresTheAttribute()
    {
        // 同じ中間型を継承する 2 つの具象を走査する
        var declarations = ScanProbes(
            typeof(MidOverrideProbeLeaf),
            typeof(SecondMidOverrideProbeLeaf));

        // 中間型の宣言(Duration = 55)に由来する宣言が 1 件だけであること
        var declared = Assert.Single(declarations, d => d.Attribute.Duration == 55);

        // 名指しが、属性を実際に宣言している中間型であること（具象でも根でもない）
        Assert.Contains(
            nameof(MidOverrideProbeControllerMid),
            declared.DeclaredOn,
            StringComparison.Ordinal);
    }

    /// <summary>属性を持たず、virtual なアクションを宣言するだけの根。</summary>
    private abstract class MidOverrideProbeControllerRoot : ControllerBase
    {
        /// <summary>派生が override する、何もしないアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        public virtual IActionResult Export() => NoContent();
    }

    /// <summary>階層の途中で override し、そこに属性を付ける型（直すべき 1 か所）。</summary>
    /// <remarks>期間の値(55)は、この経路で拾えたことを見分けるための目印。</remarks>
    private abstract class MidOverrideProbeControllerMid : MidOverrideProbeControllerRoot
    {
        /// <summary>属性を宣言する override。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 55)]
        public override IActionResult Export() => NoContent();
    }

    /// <summary>属性を付けずに override だけする具象。</summary>
    /// <remarks>
    /// <b>ここで override させるのが要点。</b> 素の継承にすると、走査が見つける
    /// <c>MethodInfo</c> の <c>DeclaringType</c> は中間型のままなので
    /// 「自分自身が宣言しているか」の検査で当たってしまい、<b>さかのぼる経路を一度も通らない</b>
    /// （実測: 素の継承にした版では、根へ一足飛びに跳ぶ実装へ戻しても全件緑のまま通った）。
    /// </remarks>
    private sealed class MidOverrideProbeLeaf : MidOverrideProbeControllerMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    /// <summary>同じ中間型を継承する 2 つ目の具象（畳み方の検証に使う）。</summary>
    private sealed class SecondMidOverrideProbeLeaf : MidOverrideProbeControllerMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    // <b>属性を宣言し直さない中間型</b>をまたいでも、根の宣言が根の名前で 1 件だけ報告されること。
    //
    // <b>なぜ上の検査では足りないのか。</b> あちらは「どの段も override する」形なので、
    // さかのぼりが 1 段目で必ず当たる ——<b>当たらなかった段を読み飛ばす経路（continue）を
    // 一度も通らない</b>。実測で、その continue を break に変えても全件緑のまま通り、
    // しかも Root → Mid(宣言し直さない) → Leaf ×2(属性なしの override)では
    // <b>1 つの宣言が Leaf の数だけ並び、名指しされたファイルに属性が無い</b>状態になった。
    [Fact]
    public void DeclarationScan_WalksPastIntermediateTypesThatDoNotRedeclareTheAction()
    {
        // 属性を宣言し直さない中間型をはさむ 2 つの具象を走査する
        var declarations = ScanProbes(
            typeof(SkippedMidProbeLeaf),
            typeof(SecondSkippedMidProbeLeaf));

        // 根の宣言(Duration = 66)に由来する宣言が 1 件だけであること
        var declared = Assert.Single(declarations, d => d.Attribute.Duration == 66);

        // 名指しが、属性を実際に宣言している根であること（具象でも中間型でもない）
        Assert.Contains(
            nameof(SkippedMidProbeControllerRoot),
            declared.DeclaredOn,
            StringComparison.Ordinal);
    }

    /// <summary>virtual なアクションに属性を付けて宣言する根。</summary>
    /// <remarks>期間の値(66)は、この経路で拾えたことを見分けるための目印。</remarks>
    private abstract class SkippedMidProbeControllerRoot : ControllerBase
    {
        /// <summary>属性を宣言する virtual なアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 66)]
        public virtual IActionResult Export() => NoContent();
    }

    /// <summary>アクションを宣言し直さない中間型（さかのぼりが読み飛ばす段）。</summary>
    private abstract class SkippedMidProbeControllerMid : SkippedMidProbeControllerRoot;

    /// <summary>属性を付けずに override だけする具象。</summary>
    private sealed class SkippedMidProbeLeaf : SkippedMidProbeControllerMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    /// <summary>同じ中間型を継承する 2 つ目の具象（畳み方の検証に使う）。</summary>
    private sealed class SecondSkippedMidProbeLeaf : SkippedMidProbeControllerMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    // さかのぼりが「同じアクションを宣言しているが属性は持たない段」を<b>通り抜ける</b>こと。
    //
    // <b>なぜ既存の 2 つでは足りないのか（実測）。</b> MidOverrideProbe は 1 段目で属性に当たり、
    // SkippedMidProbe は中間型がそのアクションを宣言していないので読み飛ばす。どちらも
    // 「宣言はしているが属性が無いので次の段へ進む」経路を通らず、その行を
    // 「当たらなければ具象を名指しして打ち切る」へ変えても 1080 件すべて緑のまま通った。
    [Fact]
    public void DeclarationScan_KeepsWalking_PastALevelThatRedeclaresTheActionWithoutTheAttribute()
    {
        // 属性を持たない override をはさむ 2 つの具象を走査する
        var declarations = ScanProbes(
            typeof(BareOverrideProbeLeaf),
            typeof(SecondBareOverrideProbeLeaf));

        // 根の宣言(Duration = 34)に由来する宣言が 1 件だけであること
        var declared = Assert.Single(declarations, d => d.Attribute.Duration == 34);

        // 名指しが、属性を実際に宣言している根であること
        Assert.Contains(
            nameof(BareOverrideProbeRoot),
            declared.DeclaredOn,
            StringComparison.Ordinal);
    }

    /// <summary>属性を付けた virtual なアクションを宣言する根。</summary>
    /// <remarks>期間の値(34)は、この経路で拾えたことを見分けるための目印。</remarks>
    private abstract class BareOverrideProbeRoot : ControllerBase
    {
        /// <summary>属性を宣言する virtual なアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 34)]
        public virtual IActionResult Export() => NoContent();
    }

    /// <summary>同じアクションを override するが、属性は持たない中間型（通り抜ける段）。</summary>
    private abstract class BareOverrideProbeMid : BareOverrideProbeRoot
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    /// <summary>属性を付けずに override だけする具象。</summary>
    private sealed class BareOverrideProbeLeaf : BareOverrideProbeMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    /// <summary>同じ中間型を継承する 2 つ目の具象（畳み方の検証に使う）。</summary>
    private sealed class SecondBareOverrideProbeLeaf : BareOverrideProbeMid
    {
        /// <summary>属性を持たない override。</summary>
        /// <returns>内容を持たない結果。</returns>
        public override IActionResult Export() => NoContent();
    }

    /// <summary>
    /// 同じ宣言元へ複数付けられる、検証用の属性（<c>AllowMultiple = true</c>）。
    /// </summary>
    /// <remarks>
    /// 実在のキャッシュ指示属性はいずれも <c>AllowMultiple = false</c> なので、
    /// 門番（<c>EnsureDedupKeyCanSeparate</c>）が働く経路は合成入力でしか通せない。
    /// <b>だから合成する</b> ——実在の属性だけを渡している限り、門番を消しても全件緑のまま通る。
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
    private sealed class RepeatableProbeAttribute(string policy) : Attribute
    {
        /// <summary>どちらの宣言かを見分けるための目印。</summary>
        public string Policy { get; } = policy;
    }

    /// <summary>同じ種類の属性をクラス側へ 2 つ宣言する合成コントローラ。</summary>
    [RepeatableProbe("a")]
    [RepeatableProbe("b")]
    private sealed class RepeatedKindProbeController : ControllerBase;

    /// <summary>複数付けられる属性を<b>1 つだけ</b>宣言する合成コントローラ。</summary>
    [RepeatableProbe("only")]
    private sealed class SingleRepeatableProbeController : ControllerBase;

    /// <summary>同じ種類の属性を<b>アクション側</b>へ 2 つ宣言する合成コントローラ。</summary>
    private sealed class RepeatedKindOnActionProbeController : ControllerBase
    {
        /// <summary>同じ種類の属性を 2 つ持つ、何もしないアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [RepeatableProbe("a")]
        [RepeatableProbe("b")]
        public IActionResult Probe() => NoContent();
    }

    /// <summary>
    /// 「種類を問わない走査」を検証するためだけの、2 種類目の属性。
    /// </summary>
    /// <remarks>
    /// <b>本物の <c>[OutputCache]</c> を使わない理由。</b> ここで見たいのは
    /// 「述語が 2 種類に一致したとき、両方が別件として返るか」だけで、
    /// 具体的な属性が何かは関係がない。自前の属性にしておけば、
    /// テストプロジェクトが出力キャッシュの参照を持つかどうかに左右されず、
    /// <b>重複除去のキーから属性の型が落ちた瞬間だけ</b>落ちる。
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    private sealed class SecondKindProbeAttribute : Attribute;

    /// <summary>
    /// クラス側・アクション側のそれぞれに 2 種類の属性を持つ合成コントローラ。
    /// </summary>
    /// <remarks>期間の値(88 / 99)は、どちらの経路で拾えたかを見分けるための目印。</remarks>
    [ResponseCache(Duration = 88)]
    [SecondKindProbe]
    private sealed class TwoKindsProbeController : ControllerBase
    {
        /// <summary>2 種類の属性を持つ、何もしないアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 99)]
        [SecondKindProbe]
        public IActionResult Probe() => NoContent();
    }

    /// <summary>1 種類目だけをクラス側に宣言する抽象基底。</summary>
    [ResponseCache(Duration = 66)]
    private abstract class SplitKindsProbeControllerBase : ControllerBase;

    /// <summary>2 種類目だけを自分で宣言し、1 種類目は基底から継承する具象。</summary>
    [SecondKindProbe]
    private sealed class SplitKindsProbeController : SplitKindsProbeControllerBase;

    /// <summary>
    /// 合成したコントローラに対して走査を実行する。
    /// </summary>
    /// <remarks>
    /// プローブはテストアセンブリにあるので、<b>宣言元のアセンブリ</b>もテストアセンブリを渡す
    /// (本番の走査は Web アセンブリを渡す)。走査そのものを検証するための入り口。
    /// </remarks>
    /// <param name="probes">走査する合成コントローラ。</param>
    /// <returns>見つかった宣言の一覧。</returns>
    private static List<ResponseCachePolicy.ResponseCacheDeclaration> ScanProbes(params Type[] probes) =>
        // 宣言元の判定にはこのテストアセンブリを使う
        ResponseCachePolicy.DeclarationsOn(probes, typeof(ResponseCacheAttributePolicyTests).Assembly).ToList();

    /// <summary>
    /// 走査がクラス側とアクション側の両方を読むことを確かめるための、合成コントローラ。
    /// </summary>
    /// <remarks>
    /// テストアセンブリに置いてあるので、アプリ全体を見る検査(Web アセンブリだけを走査する)
    /// には拾われない。期間の値(11 / 22 / 33)は、どちらの経路で拾えたかを見分けるための目印。
    /// </remarks>
    [ResponseCache(Duration = 11)]
    private sealed class BothLevelsProbeController : ControllerBase
    {
        /// <summary>アクション側にも属性を持つ、何もしないアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 22)]
        public IActionResult Probe() => NoContent();
    }

    /// <summary>アクションを引き上げた抽象基底(本物の repo でも起こりうる形)。</summary>
    private abstract class InheritedActionProbeControllerBase : ControllerBase
    {
        /// <summary>基底に置かれ、派生経由で URL として到達できるアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 33)]
        public IActionResult Export() => NoContent();
    }

    /// <summary>基底のアクションをそのまま継承する具象コントローラ。</summary>
    private sealed class InheritedActionProbeController : InheritedActionProbeControllerBase;

    /// <summary>同じ基底を継承する 2 つ目の具象コントローラ(畳み方の検証に使う)。</summary>
    private sealed class SecondInheritedActionProbeController : InheritedActionProbeControllerBase;

    /// <summary>クラス側に属性を持つ抽象基底(派生の数だけ見えてしまう形)。</summary>
    [ResponseCache(Duration = 77)]
    private abstract class ClassLevelInheritedProbeControllerBase : ControllerBase;

    /// <summary>基底のクラス属性を継承する具象コントローラ。</summary>
    private sealed class ClassLevelInheritedProbeController : ClassLevelInheritedProbeControllerBase;

    /// <summary>同じ基底を継承する 2 つ目の具象コントローラ。</summary>
    private sealed class SecondClassLevelInheritedProbeController : ClassLevelInheritedProbeControllerBase;

    /// <summary>
    /// <c>ControllerBase</c> を継承しない端点(Razor Pages の <c>PageModel</c> がこの形)の代わり。
    /// </summary>
    /// <remarks>
    /// <b>本物の <c>PageModel</c> を継承しないのはなぜか。</b> ここで見たいのは
    /// 「走査が <c>ControllerBase</c> で絞っていないか」だけで、Razor Pages の基底型そのものは
    /// 関係がない。素の型にしておけば、テストプロジェクトが Razor Pages の参照を持つかどうかに
    /// 左右されず、<b>絞り込みが戻った瞬間だけ</b>落ちる。
    /// 期間の値(44)は、この経路で拾えたことを見分けるための目印。
    /// </remarks>
    [ResponseCache(Duration = 44)]
    private sealed class NonControllerEndpointProbe
    {
        /// <summary>端点として公開されうる、何もしないメソッド。</summary>
        public void Probe() { }
    }

    // 走査が <c>ControllerBase</c> 以外の型に付いた宣言も拾うこと。
    //
    // <b>なぜ要るのか。</b> [ResponseCache] は MVC のコントローラ専用ではなく、
    // Razor Pages の PageModel に付けても IFilterFactory として同じように効く。
    // 走査を ControllerBase で絞っていた頃は、Pages/Export.cshtml.cs に
    // [ResponseCache(Duration = 300, Location = Any)] を付けた PHI のページが
    // <b>どの検査からも見えなかった</b> ——属性名にはヘッダー名の綴りが無いので、
    // ソースを見る側の走査(OnlyIntendedWriters_SetCacheControlDirectly)でも拾えない。
    //
    // アプリに実際の PageModel が 1 つも無い間は、導出を ControllerBase へ狭めても
    // 本番の検査は全件緑のままになる(痕跡はテスト件数にも出ない)ので、
    // 合成した型で「絞っていないこと」自体を固定する。
    [Fact]
    public void DeclarationScan_ReadsAttributesOnTypesThatAreNotControllers()
    {
        // ControllerBase を継承しない合成の端点を走査する
        var declarations = ScanProbes(typeof(NonControllerEndpointProbe));

        // クラス側の宣言(Duration = 44)が拾えていること
        var found = Assert.Single(declarations, d => d.Attribute.Duration == 44);
        // 名指しが、属性を実際に宣言している型であること
        Assert.Contains(nameof(NonControllerEndpointProbe), found.DeclaredOn, StringComparison.Ordinal);
    }

    // 「走査対象の導出」が、アセンブリ上の具象型を 1 つも取りこぼしていないこと。
    //
    // 上の検査は ScanProbes 経由で<b>型を直接渡す</b>ので、本番が使う導出
    // (AppControllerScan.CacheDirectiveHosts)を狭める変異は拾えない。
    //
    // <b>「非コントローラの型が 1 つでもあれば緑」では足りない。</b> 実測で、
    // 導出を `ControllerBase || Namespace.Contains("Models")` へ狭めると、
    // Pages/ に置いた [ResponseCache(Duration = 300)] のページが再び見えなくなるのに
    // ViewModel の型が条件を満たすため<b>全件緑のまま通った</b>。
    // だから「1 つでも含む」ではなく<b>「1 つも欠けていない」</b>を条件にする。
    //
    // <b>これは「独立な手がかり」ではない</b>(同じ式をこのテストが書き直しているだけ)。
    // 買えているのは「導出を狭めるには<b>2 か所を同じ差分で</b>書き換えるしかなくなる」
    // ことだけで、両方を一度に狭める差分は緑のまま通る ——そこはレビューで見る。
    // ソースファイルから具象型の一覧を組み立てる形にすれば本当に独立にできるが、
    // 生成された型・入れ子・partial を取りこぼすと逆に直しようの無い要求になるので、
    // ここは「気付ける」ところまでに留めている。
    [Fact]
    public void CacheDirectiveHosts_CoverEveryConcreteTypeInTheAssembly()
    {
        // 本番が使う導出をそのまま取り出す
        var hosts = AppControllerScan.CacheDirectiveHosts().ToHashSet();

        // 導出とは独立に、アセンブリ上の具象型を数え直す
        var everyConcreteType = AppControllerScan.WebAssembly.GetTypes()
            .Where(t => !t.IsAbstract)
            .ToList();

        // 「見るべき対象ゼロ＝緑」を避ける(アセンブリが読めない形になったら落とす)
        Assert.NotEmpty(everyConcreteType);

        // 導出から抜け落ちている型が 1 つも無いこと
        var missing = everyConcreteType.Where(t => !hosts.Contains(t)).Select(t => t.FullName).ToList();
        Assert.True(
            missing.Count == 0,
            "キャッシュ指示の走査対象から、アセンブリ上の具象型が抜け落ちています。"
                + "基底型・名前空間で絞ると、その条件に当たらない端点(Razor Pages の PageModel など)に"
                + "付けた [ResponseCache] がどの検査からも見えなくなります。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, missing));
    }
}
