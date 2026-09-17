// コントローラの型を名指しして「自分たちのアセンブリ」を特定するために使う
using IncidentInsight.Web.Controllers;
// ResponseCacheAttribute / ResponseCacheLocation / ControllerBase を使う
using Microsoft.AspNetCore.Mvc;
// 属性とアクションをリフレクションで走査するために使う
using System.Reflection;

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
/// 足すだけで、そのアクションの応答は <c>public,max-age=300</c> で返るようになる ——
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
/// <para><b>導出で作る(表を書かない)。</b> 「見るべきアクションの一覧」を手で持つと、
/// 新しいコントローラを足した人が載せ忘れた時点でその画面だけ黙って検査から外れる。
/// 対象はアセンブリ上の具象 <see cref="ControllerBase"/> すべてから導く
/// (<see cref="UnlistedFilterValuePolicyTests"/> が採っているのと同じ形)。</para>
/// </remarks>
public class ResponseCacheAttributePolicyTests
{
    /// <summary>
    /// <c>[ResponseCache]</c> が名乗っている内容と、それが許されるかどうかの判定結果。
    /// </summary>
    /// <param name="IsSuppressing">キャッシュ保存を禁じている(＝このアプリで許される)なら true。</param>
    /// <param name="Reason">許されない場合に、失敗文言へ載せる理由。許される場合は空文字。</param>
    public readonly record struct CacheDirectiveVerdict(bool IsSuppressing, string Reason);

    /// <summary>
    /// 走査が見つけた 1 件の <c>[ResponseCache]</c> 宣言(どこに付いていたかを含む)。
    /// </summary>
    /// <param name="DeclaredOn">属性が付いていた場所の表示名(失敗文言で名指しするために持つ)。</param>
    /// <param name="Attribute">宣言された属性そのもの。</param>
    public readonly record struct ResponseCacheDeclaration(string DeclaredOn, ResponseCacheAttribute Attribute);

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
        var declarations = ResponseCacheDeclarationsInTheApp().ToList();

        // 規則に反している宣言だけを、失敗文言の形に整えて取り出す
        var violations = declarations
            // 各宣言について、名乗っている内容が保存を禁じているかを判定する
            .Select(declaration => (declaration, verdict: JudgeDirective(declaration.Attribute)))
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

    // 走査が「見るべき対象ゼロ＝緑」で無力化されていないこと(fail-closed)。
    //
    // 上の検査は違反が 0 件なら緑になるので、走査がコントローラを 1 つも拾えなくなる変異
    // (アセンブリの選び方を間違える・絞り込みを狭めすぎる)は、そのままでは気付けない。
    [Fact]
    public void ControllerScan_FindsControllers()
    {
        // 走査が実際に見ているコントローラを数える
        var controllers = ScannedControllers().ToList();

        // 1 つも拾えていないなら、走査そのものが壊れている
        Assert.True(
            controllers.Count > 0,
            "コントローラを 1 つも走査できていません。アセンブリの選び方か絞り込みが壊れています。");
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
    public void JudgeDirective_AllowsOnlyStorageSuppressingDeclarations(
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
        var verdict = JudgeDirective(attribute);

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
        var declarations = ResponseCacheDeclarationsOn(new[] { typeof(BothLevelsProbeController) }).ToList();

        // クラス側の宣言(Duration = 11)が拾えていること
        Assert.Contains(declarations, d => d.Attribute.Duration == 11);
        // アクション側の宣言(Duration = 22)が拾えていること
        Assert.Contains(declarations, d => d.Attribute.Duration == 22);
        // どこに付いていたかが失敗文言のために保持されていること
        Assert.All(declarations, d => Assert.False(string.IsNullOrWhiteSpace(d.DeclaredOn)));
    }

    /// <summary>
    /// <c>[ResponseCache]</c> の宣言内容が「保存を禁じている」かどうかを判定する純粋関数。
    /// </summary>
    /// <remarks>
    /// <para><b>基準を <c>NoStore</c> だけに置く理由。</b> ASP.NET Core が
    /// <c>Cache-Control: no-store</c> を書くのは <c>NoStore = true</c> のときだけで、
    /// それ以外の組み合わせ(<c>no-cache</c> / <c>private</c> / <c>public</c>)は
    /// いずれも「保存してよい」か「保存したうえで検証せよ」を意味する。
    /// 共用端末のディスクに PHI を残さないことが目的なので、基準は保存の可否 1 本にする。</para>
    ///
    /// <para><b>プロファイル名を落とす理由。</b> <c>CacheProfileName</c> を使うと実際の指示は
    /// <c>MvcOptions.CacheProfiles</c> 側にあり、属性のフィールドからは読めない。
    /// 読めないものを「たぶん安全」と扱うと、このクラス全体が無言の fail-open になるので、
    /// 不明なら拒否する(§9 fail-closed)。使いたくなったら、プロファイルの中身まで
    /// 解決する形へこの判定を広げる。</para>
    /// </remarks>
    /// <param name="attribute">判定する属性。</param>
    /// <returns>可否と、落とす場合の理由。</returns>
    private static CacheDirectiveVerdict JudgeDirective(ResponseCacheAttribute attribute)
    {
        // プロファイル名が指定されていると、実際の指示が属性の外にあって読めない
        if (!string.IsNullOrWhiteSpace(attribute.CacheProfileName))
        {
            // 読めない以上「安全だ」と言えないので落とす
            return new CacheDirectiveVerdict(
                false,
                $"CacheProfileName=\"{attribute.CacheProfileName}\" は実際の指示が MvcOptions 側にあり、"
                    + "属性からは読み取れません。プロファイルを使わず NoStore = true を直接宣言してください。");
        }

        // NoStore が宣言されていれば、応答は保存されない
        if (attribute.NoStore)
        {
            // 許可(理由は不要なので空文字)
            return new CacheDirectiveVerdict(true, string.Empty);
        }

        // ここへ来るのは「保存を許す」宣言なので、名乗っている内容を添えて落とす
        return new CacheDirectiveVerdict(
            false,
            $"NoStore が宣言されていません(Duration={attribute.Duration}, Location={attribute.Location})。"
                + "PHI を返しうる応答が保存されます。NoStore = true を付けるか、属性ごと外して"
                + "SecurityHeadersMiddleware の既定(no-store)に任せてください。");
    }

    /// <summary>
    /// アプリ全体のコントローラが名乗る <c>[ResponseCache]</c> をすべて集める。
    /// </summary>
    /// <returns>見つかった宣言の一覧。</returns>
    private static IEnumerable<ResponseCacheDeclaration> ResponseCacheDeclarationsInTheApp() =>
        // 走査対象のコントローラを、宣言を読む共通処理へ渡す
        ResponseCacheDeclarationsOn(ScannedControllers());

    /// <summary>
    /// 渡されたコントローラ型から <c>[ResponseCache]</c> の宣言を集める。
    /// </summary>
    /// <remarks>
    /// 走査対象を引数で受け取るのは、合成したコントローラに対して
    /// <b>走査そのもの</b>を検証できるようにするため(アプリの実際の宣言が 1 件しか
    /// 無いあいだは、クラス側を読む行を消しても本番の検査は緑のまま通るため)。
    /// </remarks>
    /// <param name="controllers">走査するコントローラ型。</param>
    /// <returns>見つかった宣言の一覧。</returns>
    private static IEnumerable<ResponseCacheDeclaration> ResponseCacheDeclarationsOn(
        IEnumerable<Type> controllers)
    {
        // 渡されたコントローラを 1 つずつ見る
        foreach (var controller in controllers)
        {
            // クラス全体に付いた属性(付いていれば全アクションに効く)を読む。
            // inherit: true にするのは、基底コントローラで宣言して派生で継承する形を取りこぼさないため
            foreach (var attribute in controller.GetCustomAttributes<ResponseCacheAttribute>(inherit: true))
            {
                // どのコントローラに付いていたかが分かる形で返す
                yield return new ResponseCacheDeclaration(controller.FullName ?? controller.Name, attribute);
            }

            // 各アクション(公開されたインスタンスメソッド)に付いた属性を読む
            foreach (var method in controller.GetMethods(BindingFlags.Public | BindingFlags.Instance))
            {
                // 基底クラス(ControllerBase 等)が持つメソッドは自分たちの宣言ではないので飛ばす
                if (method.DeclaringType != controller)
                {
                    // 次のメソッドへ
                    continue;
                }

                // そのメソッドに付いた属性を読む
                foreach (var attribute in method.GetCustomAttributes<ResponseCacheAttribute>(inherit: true))
                {
                    // どのアクションに付いていたかが分かる形で返す
                    yield return new ResponseCacheDeclaration(
                        $"{controller.FullName ?? controller.Name}.{method.Name}",
                        attribute);
                }
            }
        }
    }

    /// <summary>
    /// この検査が「アプリ全体」として見るコントローラ。
    /// </summary>
    /// <remarks>
    /// 名前空間ではなく<b>所属アセンブリ</b>で絞る。名前空間の完全一致で切ると、
    /// コントローラを Areas やサブフォルダへ移すだけで検査から外れる
    /// (CLAUDE.md §3 が長さ管理の導出について同じ形の事故を記録している)。
    /// </remarks>
    /// <returns>自分たちのアセンブリにある具象コントローラ。</returns>
    private static IEnumerable<Type> ScannedControllers() =>
        // 自分たちのアセンブリの、具象のコントローラすべて(抽象基底はルートを持たないので除く)
        typeof(IncidentsController).Assembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract);

    /// <summary>
    /// 走査がクラス側とアクション側の両方を読むことを確かめるための、合成コントローラ。
    /// </summary>
    /// <remarks>
    /// テストアセンブリに置いてあるので、アプリ全体を見る検査(自アセンブリだけを走査する)
    /// には拾われない。期間の値(11 / 22)は、どちらの経路で拾えたかを見分けるための目印。
    /// </remarks>
    [ResponseCache(Duration = 11)]
    private sealed class BothLevelsProbeController : ControllerBase
    {
        /// <summary>アクション側にも属性を持つ、何もしないアクション。</summary>
        /// <returns>内容を持たない結果。</returns>
        [ResponseCache(Duration = 22)]
        public IActionResult Probe() => NoContent();
    }
}
