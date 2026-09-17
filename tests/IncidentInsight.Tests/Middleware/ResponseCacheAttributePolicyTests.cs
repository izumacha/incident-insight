// 走査と判定の共通処理を使う
using IncidentInsight.Tests.Helpers;
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
/// <para><b>この検査が見ない口(別の検査が担当する)。</b> 指示は属性の宣言以外からも来る ——
/// <c>MvcOptions.Filters</c> へ登録したグローバルフィルタと <c>MvcOptions.CacheProfiles</c> が
/// それで、どちらも属性のソースには現れない。そちらは起動したアプリの設定を読む
/// <c>ResponseCacheHeaderIntegrationTests</c> が、<b>同じ判定関数</b>
/// (<see cref="ResponseCachePolicy.Judge(ResponseCacheAttribute)"/>)で見る。</para>
///
/// <para><b>導出で作る(表を書かない)。</b> 「見るべきアクションの一覧」を手で持つと、
/// 新しいコントローラを足した人が載せ忘れた時点でその画面だけ黙って検査から外れる。
/// 対象は <see cref="AppControllerScan.Controllers"/> から導く ——
/// この導出が狭まっていないことは、独立な手がかり(ソースファイルの実在)で照合する
/// <c>UnlistedFilterValuePolicyTests.ControllerScan_ReachesEveryControllerFile</c> が見張る。
/// <b>ここで絞り込みを書き写さない</b>のは、写した瞬間にこのファイルだけが
/// そのガードの射程から外れるため。</para>
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
            .DeclarationsOn(AppControllerScan.Controllers(), AppControllerScan.WebAssembly)
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
}
