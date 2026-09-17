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
    /// <c>Cache-Control</c> を<b>意図して</b>書いてよい唯一の 2 か所（理由付きの許可表）。
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
    /// 表が小さく（2 件）、理由を持ち、増える差分が必ず 1 行として現れるなら、
    /// パスの形を当て続けるより安全側に倒れる。<b>この表にエントリが増える差分は、
    /// 理由の妥当性をレビューで必ず確認すること</b>（§6 のエスケープハッチと同じ扱い。
    /// 「絞り込みを狭める」変更は差分にもテスト件数にも現れないが、
    /// 表への 1 行は必ず現れる）。</para>
    /// </remarks>
    private static readonly IReadOnlyDictionary<string, string> IntendedCacheControlWriters =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // 既定値（誰も書かなかった応答へ no-store を入れる）を書く唯一の場所
            [Path.Combine("Middleware", "SecurityHeadersMiddleware.cs")] =
                "キャッシュ抑止の既定値そのものを書く場所。ここが書かなければ既定は成立しない。",
            // 静的アセットが既定の対象から外れるための自己申告を書く場所
            ["Program.cs"] =
                "UseStaticFiles の OnPrepareResponse が静的アセット用の指示を名乗る。"
                    + "これが無いと css/js が no-store になり毎回再取得になる（§8）。",
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
            // 意図して書く場所は対象外(理由は許可表が持つ)
            if (IsIntendedWriter(sourcePath)) continue;
            // コメントを取り除いたうえで、ヘッダー名を含む行を探す
            foreach (var (lineNumber, text) in CodeLinesContaining(sourcePath, CacheControlTokens))
            {
                // リポジトリからの相対パスと行番号で名指しする
                violations.Add($"{Path.GetRelativePath(RepositoryPaths.Root, sourcePath)}:{lineNumber}: {text}");
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
        foreach (var (relativePath, reason) in IntendedCacheControlWriters)
        {
            // Web プロジェクトからの相対パスとして実在すること
            Assert.True(
                File.Exists(Path.Combine(RepositoryPaths.WebProject, relativePath)),
                $"許可表が実在しないファイルを指しています: {relativePath}。"
                    + "移動・改名したなら、この表も同じ変更セットで直してください"
                    + "(実在しないエントリは「除外したつもり」を作ります)。");
            // 理由が空でも空白だけでもないこと
            Assert.False(
                string.IsNullOrWhiteSpace(reason),
                $"許可表のエントリに理由がありません: {relativePath}。");
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
                AppControllerScan.Controllers(),
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

    // wwwroot の直下が、キャッシュ可能にしてよいと確認済みの入れ物だけであること。
    //
    // <b>なぜ要るのか。</b> 静的ファイル配信の OnPrepareResponse は wwwroot 配下の
    // <b>すべて</b>に public,max-age=3600 を名乗らせる。つまり wwwroot に新しい入れ物を
    // 足すと、その中身は<b>1 行のコードも書かずに</b>キャッシュ可能側へ入る ——
    // 添付画像やエクスポートした CSV を wwwroot/attachments や wwwroot/exports へ置くと、
    // 共有キャッシュと共用端末のディスクにログアウト後 1 時間残る。
    // 属性・MvcOptions・直接書き込みのどの検査にも現れない(Program.cs は許可表に載っている)。
    [Fact]
    public void StaticFileRoots_AreOnlyKnownPublicAssets()
    {
        // wwwroot の直下にある入れ物(ファイル・ディレクトリ)の名前を集める
        var entries = Directory
            .EnumerateFileSystemEntries(Path.Combine(RepositoryPaths.WebProject, "wwwroot"))
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrEmpty(name))
            .Select(name => name!)
            .ToList();

        // 1 つも読めないなら走査が壊れている(「見るべき対象ゼロ＝緑」を避ける)
        Assert.NotEmpty(entries);

        // 確認済みの入れ物に含まれないものを集める
        var unexpected = entries
            .Where(name => !PubliclyCacheableStaticRoots.ContainsKey(name))
            .ToList();

        // 想定外の入れ物が無いことを、名指しの一覧付きで確認する
        Assert.True(
            unexpected.Count == 0,
            "wwwroot に、キャッシュ可能にしてよいと確認していない入れ物があります: "
                + string.Join(", ", unexpected)
                + "。静的ファイル配信は wwwroot 配下のすべてに "
                + "public,max-age=3600 を名乗らせるため、ここへ置いたものは 1 行のコードも"
                + "書かずにキャッシュ可能になります(共用端末のディスクにログアウト後も残ります)。"
                + "PHI を含みうるもの(添付・エクスポート)は wwwroot の外に置き、"
                + "認可を通すアクションから返してください。"
                + "公開して問題ない資産なら、理由を添えて PubliclyCacheableStaticRoots へ登録します。");
    }

    /// <summary>
    /// <c>wwwroot</c> 直下に置いてよい（キャッシュ可能で問題ない）入れ物と、その理由。
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> PubliclyCacheableStaticRoots =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // アプリ自身のスタイルシート
            ["css"] = "アプリのスタイルシート。利用者ごとの内容を持たない。",
            // アプリ自身のスクリプト
            ["js"] = "アプリのスクリプト(TypeScript の出力)。利用者ごとの内容を持たない。",
            // 第三者ライブラリ
            ["lib"] = "第三者ライブラリ(jQuery 等)。版付き URL でないため期間を短く保つ。",
            // ブラウザのタブに出るアイコン
            ["favicon.ico"] = "ブラウザのアイコン。公開情報。",
        };

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
    // 日本語コメントで規則を説明する行は拾わない(§5 が求める書き方で赤くしない)
    [InlineData("    // エラーページ。Cache-Control は属性側で no-store を宣言する", false)]
    // XML ドキュメントコメントも同じ扱い
    [InlineData("    /// <c>Cache-Control</c> をここでは書かない。", false)]
    // Razor のコメントも同じ扱い
    [InlineData("    @* Cache-Control はミドルウェアの既定に任せる *@", false)]
    // <b>同じ行で閉じたコメントの後ろの実コードは拾う</b>(綴りを変えただけの抜け道にしない)
    [InlineData("    @* メモ *@ @{ Context.Response.Headers.CacheControl = \"public\"; }", true)]
    // C# のブロックコメントを閉じた後ろの実コードも同じく拾う
    [InlineData("    /* メモ */ Response.Headers.CacheControl = \"public\";", true)]
    // 行コメントの<b>前</b>に実コードがある行も拾う
    [InlineData("        Response.Headers.CacheControl = \"public\"; // 速くするため", true)]
    public void MentionsCacheControl_MatchesOnlyCacheControlWrites(string line, bool expected)
    {
        // 判定を実行して、期待どおりかを確認する
        Assert.Equal(expected, MentionsCacheControl(line));
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

        // 閉じていないコメントの中で終わっても、実コードを拾わない
        Assert.Empty(ScanLines(
            "/*",
            "  Response.Headers.CacheControl = \"public\";"));
    }

    /// <summary>
    /// 合成した複数行のソースを走査し、該当した行番号を返す(検査用の入り口)。
    /// </summary>
    /// <param name="lines">合成したソースの各行。</param>
    /// <returns>該当した行番号(1 始まり)。</returns>
    private static int[] ScanLines(params string[] lines)
    {
        // 使い捨ての作業場へ書き出して、本物と同じ経路で走査する
        var path = Path.Combine(Path.GetTempPath(), $"ii-scan-{Guid.NewGuid():N}.cshtml");
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

    /// <summary>
    /// そのファイルが、<c>Cache-Control</c> を意図して書いてよい場所かを返す。
    /// </summary>
    /// <param name="sourcePath">Web プロジェクト配下のソースファイルの絶対パス。</param>
    /// <returns>許可表に載っていれば true。</returns>
    private static bool IsIntendedWriter(string sourcePath) =>
        // Web プロジェクトからの相対パスで表と突き合わせる(絶対パスは実行機ごとに違うため)
        IntendedCacheControlWriters.ContainsKey(
            Path.GetRelativePath(RepositoryPaths.WebProject, sourcePath));

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
    /// </remarks>
    /// <param name="sourcePath">読み取るソースファイル。</param>
    /// <param name="tokens">探す綴り(いずれかを含めば該当)。</param>
    /// <returns>該当した行の番号(1 始まり)と、その行の内容。</returns>
    private static IEnumerable<(int LineNumber, string Text)> CodeLinesContaining(
        string sourcePath,
        IReadOnlyList<string> tokens)
    {
        // ファイルを 1 行ずつ読む(何行目かを失敗文言に載せるため)
        var lines = File.ReadAllLines(sourcePath);
        // ブロックコメントの途中なら、閉じるまでの綴りを持つ(外なら null)
        string? pendingCloser = null;
        // 該当した行を貯める
        var hits = new List<(int, string)>();

        // 先頭から順に、コメントの内外を持ち越しながら見る
        for (var i = 0; i < lines.Length; i++)
        {
            // この行からコメントを取り除き、次の行へ持ち越す状態を受け取る
            var (code, nextCloser) = StripComments(lines[i], pendingCloser);
            // 次の行の判定に使う状態を更新する
            pendingCloser = nextCloser;
            // 残った実コードが、探している綴りのいずれかを含むかを見る
            if (tokens.Any(t => code.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                // 行番号(1 始まり)と、読み手に見せる元の行を記録する
                hits.Add((i + 1, lines[i].Trim()));
            }
        }

        // 見つかった行を返す
        return hits;
    }

    /// <summary>
    /// 1 行からコメントを取り除き、次の行へ持ち越す状態を返す。
    /// </summary>
    /// <param name="line">対象の 1 行。</param>
    /// <param name="pendingCloser">
    /// 直前の行から持ち越したブロックコメントの閉じ綴り(コメントの外なら <c>null</c>)。
    /// </param>
    /// <returns>コメントを除いた実コードと、次の行へ持ち越す閉じ綴り。</returns>
    private static (string Code, string? PendingCloser) StripComments(string line, string? pendingCloser)
    {
        // 実コードだけを貯める入れ物
        var code = new System.Text.StringBuilder();
        // 読み取り位置
        var i = 0;

        // 行の終わりまで 1 文字ずつ進む
        while (i < line.Length)
        {
            // ブロックコメントの途中なら、閉じ綴りを探す
            if (pendingCloser is not null)
            {
                // この行に閉じ綴りがあるかを見る
                var close = line.IndexOf(pendingCloser, i, StringComparison.Ordinal);
                // 無ければ、この行はすべてコメント(状態は持ち越す)
                if (close < 0) return (code.ToString(), pendingCloser);
                // あれば、その直後から実コードとして読み直す
                i = close + pendingCloser.Length;
                // コメントの外へ戻る
                pendingCloser = null;
                // 続きを見る
                continue;
            }

            // 行コメントが始まったら、そこから先は読まない
            if (StartsWithAt(line, i, "//")) break;
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
        return (code.ToString(), pendingCloser);
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
        // コメントの外から読み始めて、この行の実コードを取り出す
        var (code, _) = StripComments(line, null);
        // 大文字小文字を無視して照合する(HTTP のヘッダー名は区別しないため)
        return CacheControlTokens.Any(t => code.Contains(t, StringComparison.OrdinalIgnoreCase));
    }


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
}
