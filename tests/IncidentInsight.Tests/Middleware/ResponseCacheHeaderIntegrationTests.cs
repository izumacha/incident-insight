// AllowedHosts の判定を、実測した扱いと突き合わせるために使う
using IncidentInsight.Web.Models.Validation;
// テスト対象のミドルウェア(キャッシュ抑止の値の定数)を使う
using IncidentInsight.Web.Middleware;
// WebApplicationFactory(実 HTTP パイプラインでの統合テスト)を使う
using Microsoft.AspNetCore.Mvc.Testing;
// 正規表現でアンチフォージェリトークンを取り出すために使う
using System.Text.RegularExpressions;
// 共有のフィクスチャとキャッシュ指示の判定を使う
using IncidentInsight.Tests.Helpers;
// ログインのレート制限の設定キー定数を使う
using IncidentInsight.Web.Models.RateLimiting;
// MvcOptions(グローバルフィルタ・キャッシュプロファイル)を読むために使う
using Microsoft.AspNetCore.Mvc;
// 起動済みアプリから設定を解決するために使う
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

// テストクラスの名前空間(既存の Middleware 配下テストと同じ場所)
namespace IncidentInsight.Tests.Middleware;

/// <summary>
/// PHI を含む応答がキャッシュ禁止で返り、静的アセットはキャッシュ可能なまま残ることを
/// 実 HTTP パイプラインで検証する統合テスト。
/// </summary>
/// <remarks>
/// <para><b>単体テストだけでは足りない理由。</b> キャッシュ抑止は応答開始直前の
/// <c>OnStarting</c> コールバックで効くが、<c>DefaultHttpContext</c> の既定の応答フィーチャーは
/// このコールバックを<b>発火しない</b>(既定実装が空)。そのため
/// 「登録そのものを削除する」「Program.cs から <c>UseMiddleware</c> を外す」変異は、
/// ミドルウェア単体のテストだけでは緑のまま通りうる。判定ロジック(純粋関数)は
/// <c>SecurityHeadersMiddlewareTests</c> が境界まで固定するので、ここは<b>配線</b>だけを見る。</para>
///
/// <para><b>検証に使う経路の選び方(ここが要点)。</b> このミドルウェアが入る前から
/// <c>Cache-Control: no-cache, no-store</c> が付いていた応答がある ——
/// アンチフォージェリ(<c>DefaultAntiforgery</c>)がトークンを描画する応答へ自分で
/// 書き込むためで、共通レイアウトのログアウト用 POST フォームがそれを踏むので
/// <b>ほとんどの画面は「たまたま」保護されていた</b>。したがって
/// <c>/Account/Login</c> のような<b>フォームのある画面で検証してはいけない</b> ——
/// ミドルウェアを丸ごと外しても緑のまま通る(実測で確認した)。
/// ここで見るのは、実測でキャッシュ指示が<b>1 つも付いていなかった</b>次の 2 経路:</para>
/// <list type="bullet">
///   <item><description><c>/Account/AccessDenied</c> …… フォームを持たない読み取り専用の画面。
///     「保護がページの内容に依存する」という fail-open をそのまま示す例。</description></item>
///   <item><description><c>/Analytics/*</c> の JSON …… 部署別・原因分類別の件数を返す。
///     アンチフォージェリを一切通らないため、共有キャッシュにも残りうる状態だった。</description></item>
/// </list>
///
/// <para><b>静的アセット側も同じファイルで見る。</b> 既定値が静的ファイルへ及ばないのは
/// 「静的ファイル配信が自分でキャッシュ指示を名乗る」からで、その配線
/// (<c>Program.cs</c> の <c>OnPrepareResponse</c>)が消えると css/js が毎回再取得される
/// (§8 配信の最適化)。付く側と付かない側を対で固定する。</para>
/// </remarks>
public class ResponseCacheHeaderIntegrationTests
    : IClassFixture<ResponseCacheHeaderIntegrationTests.AppFixture>
{
    // 認証が要る経路(/Analytics の JSON)を叩くためにシードするデモ管理者のメールアドレス。
    // appsettings.Development.json の既定値と同じ値を設定で上書きして使う
    private const string AdminEmail = "admin@hospital.local";

    // デモ管理者のパスワード。Development のポリシー(8 文字以上・大文字・数字)を満たす。
    //
    // <b>実行ごとに生成する(リテラルを置かない)。</b> CLAUDE.md §2 は
    // 「デモアカウントのパスワードはコミットしない」と定めている。使い道が
    // 使い捨ての一時 SQLite に限られていても、リポジトリへ綴りを置けば
    // 「統合テストではこう書く」という前例になり、次にログインが要るテストを書く人が
    // より広い場所を指すフィクスチャへ同じ形を写す。生成しておけば写しようがない。
    // 先頭の "A" が大文字、末尾の "a1" が小文字と数字の条件を満たし、間は毎回変わる。
    // <b>小文字を固定で足すのが要点</b>: Guid の "N" 書式は 16 進なので、8 文字がすべて
    // 数字になる確率が (10/16)^8 ≒ 2.3% ある。その回だけ RequireLowercase を満たさず、
    // IdentitySeeder は警告を出して管理者の作成を<b>黙ってスキップ</b>するため、
    // ログインが 302 ではなく 200 を返して認証が要るテストだけが落ちる
    // (実測: 小文字を含まない値を固定で与えると PasswordRequiresLower で再現する)
    private static readonly string AdminPassword = $"A{Guid.NewGuid():N}"[..9] + "a1";

    // ログインフォームからアンチフォージェリトークンを取り出す正規表現。
    // 入力は自分のアプリが返した HTML なので外部入力ではない(§9 の ReDoS 対象外)
    private static readonly Regex AntiforgeryTokenPattern = new(
        "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"",
        RegexOptions.Compiled);

    // アプリ全体を起動するテスト用ファクトリ(フィクスチャが 1 度だけ組み立てたものを借りる)
    private readonly WebApplicationFactory<Program> _factory;

    // クライアントの組み立て規則を持つフィクスチャ
    private readonly AppFixture _fixture;

    public ResponseCacheHeaderIntegrationTests(AppFixture fixture)
    {
        // クライアントの組み立てを任せるためフィクスチャ自体を保持する
        _fixture = fixture;
        // フィクスチャが保持している起動済みのファクトリを受け取る
        _factory = fixture.Factory;
    }

    /// <summary>
    /// このテストクラスが共有する、一時 DB を指して 1 度だけ起動したアプリ。
    /// </summary>
    /// <remarks>
    /// 起動を 1 回に保つ仕掛けと一時ファイルの後始末は
    /// <see cref="TempDatabaseAppFixture"/> が持つ(理由もそちらに書いてある)。
    /// ここはこのテストに固有の設定 ——認証が要る JSON を叩くためのデモ管理者—— だけを渡す。
    ///
    /// <para><b>ログインのレート制限も、このホストを使うテスト全体で共有される。</b>
    /// 制限の単位は <c>HttpContext.Connection.RemoteIpAddress</c> だが、<c>TestServer</c>
    /// 経由では <c>null</c> になり、fail-closed の設計どおり全員が共通の 1 バケツへ入る
    /// ——つまりテストごとに分けられない。既定は 60 秒あたり 10 回なので、
    /// <c>CreateSignedInClientAsync</c>(ログインを 1 回行う)を使うテストが増えると、
    /// あとに走ったものが 429 を受けて「ログインが失敗した」ように見える失敗をする。
    /// このクラスはレート制限を検証していないので、<b>枠を十分大きくして無関係にする</b>
    /// (レート制限そのものの検証は <c>LoginRateLimitIntegrationTests</c> が担当する)。</para>
    /// </remarks>
    public sealed class AppFixture() : TempDatabaseAppFixture(
        "ii-cacheheader",
        new Dictionary<string, string?>
        {
            // 認証が要る JSON を叩くため、デモ管理者のシードを有効にする
            ["SeedAccounts:AdminEmail"] = AdminEmail,
            // シードするデモ管理者のパスワード
            ["SeedAccounts:AdminPassword"] = AdminPassword,
            // ログインの枠を十分大きくして、このクラスの検証がレート制限に左右されないようにする
            [$"{LoginRateLimitOptions.SectionName}:PermitLimit"] = "1000",
        });

    // アプリの設定(MvcOptions)側からキャッシュ許可が入り込んでいないこと。
    //
    // <b>なぜ属性の走査だけでは足りないのか。</b> 指示は宣言した属性以外からも来る:
    // Program.cs で o.Filters.Add(new ResponseCacheAttribute { Duration = 300, Location = Any })
    // と書くと<b>全アクション</b>が public,max-age=300 を名乗り、SecurityHeadersMiddleware は
    // 「既に指示がある」ので触れない ——アプリ全体の PHI が共有キャッシュへ保存可能になる。
    // 属性のソースには 1 文字も現れないので ResponseCacheAttributePolicyTests は緑のまま通る。
    // 起動したアプリの設定を読むこの検査が、その口を塞ぐ(判定は同じ関数を使う)。
    [Fact]
    public void GlobalMvcFilters_DoNotPermitCaching()
    {
        // 起動済みのアプリから MVC の設定を取り出す
        var options = _factory.Services.GetRequiredService<IOptions<MvcOptions>>().Value;

        // グローバルに登録された [ResponseCache] のうち、保存を許しているものを集める
        var violations = options.Filters
            .OfType<ResponseCacheAttribute>()
            // 属性の走査と同じ基準で判定する(規則を 2 つ書かない)
            .Select(filter => ResponseCachePolicy.Judge(filter))
            // 保存を禁じていないものだけを残す
            .Where(verdict => !verdict.IsSuppressing)
            // 失敗文言に載せる理由を取り出す
            .Select(verdict => verdict.Reason)
            .ToList();

        // 違反が 1 件も無いことを、理由付きで確認する
        Assert.True(
            violations.Count == 0,
            "グローバルフィルタとして登録された [ResponseCache] が保存を許しています。"
                + "これはアプリの全アクションに効くため、PHI がまるごと共有キャッシュへ保存されます。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    // 設定として持つキャッシュプロファイルが、どれも保存を許していないこと。
    //
    // [ResponseCache(CacheProfileName = "...")] は実際の指示を MvcOptions 側に持つ。
    // 属性のフィールドからは読めないので、属性側の判定はプロファイル名の使用を
    // fail-closed で落としている。そのうえで<b>プロファイルの中身</b>もここで見る ——
    // 片方だけだと「プロファイルを定義したが誰も使っていない」状態を素通りさせ、
    // 使い始めた瞬間に穴になる。
    [Fact]
    public void CacheProfiles_DoNotPermitCaching()
    {
        // 起動済みのアプリから MVC の設定を取り出す
        var options = _factory.Services.GetRequiredService<IOptions<MvcOptions>>().Value;

        // 保存を許しているプロファイルを、名前付きで集める
        var violations = options.CacheProfiles
            // 各プロファイルを属性の走査と同じ基準で判定する
            .Select(entry => (entry.Key, verdict: ResponseCachePolicy.Judge(entry.Value)))
            // 保存を禁じていないものだけを残す
            .Where(pair => !pair.verdict.IsSuppressing)
            // 「どのプロファイルが、なぜ駄目か」を 1 行にまとめる
            .Select(pair => $"{pair.Key}: {pair.verdict.Reason}")
            .ToList();

        // 違反が 1 件も無いことを、名指しの一覧付きで確認する
        Assert.True(
            violations.Count == 0,
            "保存を許すキャッシュプロファイルが定義されています。"
                + "使われた時点で、その応答は共有キャッシュへ保存可能になります。"
                + Environment.NewLine
                + string.Join(Environment.NewLine, violations));
    }

    [Fact]
    public async Task HtmlPageWithoutAForm_IsReturnedWithNoStore()
    {
        // リダイレクトを追わない素の HTTP クライアントを作る(応答ヘッダをそのまま観測するため)
        var client = CreateClient();

        // フォームを持たない読み取り専用の画面を取得する。
        // この画面はアンチフォージェリを通らないため、以前はキャッシュ指示が付いていなかった
        var response = await client.GetAsync("/Account/AccessDenied");

        // 画面が実際に HTML として返っていることを確認する(前提が崩れたら以降の検証が無意味になる)
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);

        // 応答本文を読み出す(下の前提確認に使う)
        var body = await response.Content.ReadAsStringAsync();
        // <b>この画面がアンチフォージェリを通っていない</b>ことを機械的に確かめる。
        // クラスのコメントが説明しているとおり、トークンを描画した応答には
        // アンチフォージェリ自身が no-cache, no-store を書くので、フォームのある画面では
        // ミドルウェアを丸ごと外しても下の検証が緑のまま通る。その前提を<b>コメントではなく
        // 検証</b>で持たせておかないと、共通レイアウトに常時表示のフォームが 1 つ増えただけで
        // この検査は「緑だが何も見ていない」状態へ静かに変わる(差分にもテスト件数にも現れない)
        Assert.DoesNotContain("__RequestVerificationToken", body);

        // キャッシュ抑止が付いていることを確認する(共用端末の戻るボタン・ディスクキャッシュ対策)
        Assert.Contains(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            response.Headers.CacheControl?.ToString() ?? "");
    }

    [Fact]
    public async Task AnalyticsJson_IsReturnedWithNoStore()
    {
        // デモ管理者としてログイン済みのクライアントを用意する
        var client = await CreateSignedInClientAsync();

        // 集計 JSON(部署別・原因分類別の件数を含む)を取得する
        var response = await client.GetAsync("/Analytics/MonthlyTrend");

        // 認証が通って JSON が返っていることを確認する(302 のままなら以降の検証が無意味になる)
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        // 集計値にもキャッシュ抑止が付いていることを確認する
        Assert.Contains(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            response.Headers.CacheControl?.ToString() ?? "");
    }

    [Fact]
    public async Task StaticAsset_StaysCacheable()
    {
        // リダイレクトを追わないクライアントを作る
        var client = CreateClient();

        // 静的ファイル(アプリ本体のスタイルシート)を取得する
        var response = await client.GetAsync("/css/site.css");

        // 静的ファイルが実際に配信されていることを確認する(パスが変わったらここで気付ける)
        Assert.True(response.IsSuccessStatusCode);
        // 静的アセット用の指示がそのまま返ることを確認する。
        // これが「誰も指示していなければ no-store」の既定値を静的ファイルへ及ばせない唯一の仕組みで、
        // 指示が消えるとキャッシュが効かなくなる(§8)ことにこの検証で気付ける。
        // 比較は NonValidated(回線に載った生の値)で行う ——
        // 型付きの CacheControl は "public,max-age=3600" を "public, max-age=3600" へ
        // 正規化するため、定数とそのまま比べると空白の有無だけで落ちる
        Assert.Equal(
            SecurityHeadersMiddleware.StaticAssetCacheControl,
            response.Headers.NonValidated["Cache-Control"].ToString());
    }

    // <b>静的アセットにもセキュリティヘッダーが付くこと＝ミドルウェアが
    // UseStaticFiles より前にいることを固定する（issue #257）。</b>
    //
    // UseStaticFiles は一致したファイルに対して<b>終端</b>なので、
    // app.UseMiddleware&lt;SecurityHeadersMiddleware&gt;() がそれより後ろへ動くと、
    // wwwroot 配下のすべての資産が X-Content-Type-Options / X-Frame-Options /
    // Referrer-Policy を一斉に失う。実測でもその行を UseRouting の直前へ移すと
    // <b>全件緑のまま通り</b>、/css/site.css の応答から X-Content-Type-Options が消えた ——
    // つまりこの順序は<b>どの検査にも守られていなかった</b>。
    //
    // <b>行の位置ではなく、配信された応答のヘッダーを見る。</b> ソースの並びを見る検査は
    // 書き方に弱い（このリポジトリが繰り返し避けている形）。しかもこの行の周りには
    // 「もう 1 度登録する」「リダイレクトをこの行より後ろへ出す」といった
    // <b>この行を動かす案内</b>が並んでおり、動かす動機のある場所にあたる。
    //
    // <b>見るのは 1 つのヘッダーだけでよい。</b> 守りたいのは「ミドルウェアがこの応答を
    // 通ったか」であって、どのヘッダーを付けるかは SecurityHeadersMiddlewareTests の
    // 担当。3 つを並べると、ヘッダーの構成を意図して変えたときにこの検査が
    // <b>順序とは無関係な理由で</b>落ち、失敗文言が間違った場所を指す。
    [Fact]
    public async Task StaticAsset_StillGetsTheSecurityHeaders()
    {
        // リダイレクトを追わないクライアントを作る
        var client = CreateClient();

        // 静的ファイル(アプリ本体のスタイルシート)を取得する
        var response = await client.GetAsync("/css/site.css");

        // 静的ファイルが実際に配信されていることを確認する
        // (配信されていないと、ヘッダーの検査が「別の応答」を見て緑になる)
        Assert.True(response.IsSuccessStatusCode);

        // <b>本命。</b> セキュリティヘッダーが付いている＝この応答が
        // SecurityHeadersMiddleware を通っている
        Assert.Equal(
            "nosniff",
            response.Headers.NonValidated["X-Content-Type-Options"].ToString());
    }

    [Fact]
    public async Task HealthCheck_KeepsItsOwnCacheDirectives()
    {
        // リダイレクトを追わないクライアントを作る
        var client = CreateClient();

        // ヘルスチェックのエンドポイントを叩く(自分でキャッシュ指示を書き込む数少ない経路)
        var response = await client.GetAsync("/health");

        // ヘルスチェック自身が書いた指示(no-cache を含む)が残っていることを確認する。
        // 既定値で上書きしてしまうと "no-store" だけになり、この検証が落ちる
        Assert.Contains("no-cache", response.Headers.CacheControl?.ToString() ?? "");
    }

    /// <summary>
    /// リダイレクトを追わない素の HTTP クライアントを作る。
    /// </summary>
    /// <remarks>
    /// 組み立ての規則そのものは <see cref="TempDatabaseAppFixture.CreateNonRedirectingClient"/> が持つ
    /// (同じ組み立てが 3 箇所目になったので共通化した。§6)。
    /// </remarks>
    /// <returns>組み立てた HttpClient。</returns>
    private HttpClient CreateClient() => _fixture.CreateNonRedirectingClient();

    /// <summary>
    /// デモ管理者としてログインを済ませた HTTP クライアントを作る。
    /// </summary>
    /// <remarks>
    /// クッキーは <c>WebApplicationFactoryClientOptions.HandleCookies</c> の既定(有効)により
    /// このクライアント内で引き継がれるので、ログイン後はそのまま認証済みとして使える。
    /// </remarks>
    /// <returns>認証済みの HttpClient。</returns>
    private async Task<HttpClient> CreateSignedInClientAsync()
    {
        // クッキーを引き継ぐクライアントを用意する
        var client = CreateClient();
        // ログイン画面を開いてアンチフォージェリトークンとクッキーを受け取る
        var loginPage = await client.GetStringAsync("/Account/Login");
        // フォームに埋め込まれたトークンを取り出す
        var match = AntiforgeryTokenPattern.Match(loginPage);
        // トークンが見つからなければ、ログイン画面の構造が変わったことを明示して落とす
        Assert.True(match.Success, "ログイン画面からアンチフォージェリトークンを取得できませんでした。");
        // 資格情報とトークンをフォーム形式で組み立てる
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            // シードしたデモ管理者のメールアドレス
            ["Email"] = AdminEmail,
            // シードしたデモ管理者のパスワード
            ["Password"] = AdminPassword,
            // 取り出したアンチフォージェリトークン
            ["__RequestVerificationToken"] = match.Groups["token"].Value,
        });
        // ログインを実行する
        var response = await client.PostAsync("/Account/Login", form);
        // 認証成功はリダイレクト(302)で返る。200 のままならログイン失敗なので、ここで落とす
        Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        // 認証済みのクライアントを返す
        return client;
    }
}

/// <summary>
/// ホスト名の絞り込みで短絡した応答が<b>リクエスト由来の値を映し返さない</b>ことを固定する検査。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか。</b> <c>docs/security.md</c> と <c>Program.cs</c> は
/// 「<c>SecurityHeadersMiddleware</c> より手前で応答が完結する経路があり、そこには
/// <c>no-store</c> が付かないが実害は無い」と判断の根拠を書いている。その根拠を
/// 機械で確かめられる形にしたのがこの検査（文書に書いた理由を誰も検証していないと、
/// 静かに前提が崩れる）。</para>
///
/// <para><b>「本文が空」ではない。</b> 最初はそう書きかけたが、実測すると本文はある ——
/// フレームワークの定型ページ（<c>Bad Request - Invalid Hostname</c>、334 バイト）が返る。
/// <b>実害が無い理由は「空だから」ではなく「固定の定型文で、リクエスト由来の値も
/// このアプリのデータも 1 文字も含まないから」</b>。だからここで固定するのはその 2 点にする
/// （空であることを条件にすると、事実に合わない前提を検査として固めてしまう）。</para>
///
/// <para><b>この経路は並べ替えでは覆えない。</b> ホスト名を見るミドルウェアは汎用ホストが
/// <c>IStartupFilter</c> として登録するため、<c>Program.cs</c> のどこに何を書いても
/// 必ず手前にいる。実測では 400 が返り、<c>Cache-Control</c> は付かない。
/// <b>映し返しが無いことが要点</b>で、ここで要求元のホスト名が本文へ出ると、
/// キャッシュ抑止の効かない応答に攻撃者の入力が載る（共有キャッシュへの毒として使える）。</para>
///
/// <para><b>ヘッダーが付かないこと自体は固定しない。</b> それはフレームワークの実装の詳細で、
/// 将来付くようになったとしても安全側への変化でしかない。ここで守りたいのは
/// 「本文が空だから実害が無い」という<b>判断の前提</b>だけ。</para>
/// </remarks>
public class HostFilteringShortCircuitTests
    : IClassFixture<HostFilteringShortCircuitTests.NarrowedHostFixture>
{
    // ホスト名を絞ったアプリ(このクラスのためだけに 1 度だけ起動する)
    private readonly NarrowedHostFixture _fixture;

    /// <summary>xUnit が共有フィクスチャを渡してくる。</summary>
    /// <param name="fixture">ホスト名を絞って起動したアプリ。</param>
    public HostFilteringShortCircuitTests(NarrowedHostFixture fixture) => _fixture = fixture;

    // docs/security.md が運用者に指示している「実ホスト名へ絞った」状態を再現するホスト名
    private const string AllowedHost = "incident.example.test";

    // 許可リストに無いホスト名（本文へ映し返されていないことを確かめるために名前で持つ）
    private const string RejectedHost = "evil.example.test";

    // 複数指定を書いたときの 2 件目（「区切りのうしろの空白」を再現するために使う）
    private const string SecondHost = "www.example.test";

    // ホスト名として正規化できない綴り（途中にタブが紛れた形）
    private const string UnparsableHost = "0.0\t.0.0";

    /// <summary>
    /// <c>AllowedHosts</c> を実ホスト名へ絞ったアプリ。
    /// </summary>
    /// <remarks>
    /// 既定の <c>"*"</c> のままでは短絡そのものが起きないので、
    /// 文書が運用者に求めている設定を再現する必要がある。
    /// </remarks>
    public sealed class NarrowedHostFixture() : TempDatabaseAppFixture(
        "ii-hostfilter",
        new Dictionary<string, string?>
        {
            // 文書が指示するとおり、実ホスト名へ絞る(issue #64)
            ["AllowedHosts"] = AllowedHost,
        });

    // 一致しない Host ヘッダーの応答が、要求元のホスト名を映し返さないこと。
    //
    // <b>「本文を持たないこと」ではない。</b> 本文はある(フレームワークの定型ページ)。
    // 名前とコメントをそちらに寄せると、この変更が直したばかりの誤った不変条件を
    // テスト名として言い直すことになる。
    [Fact]
    public async Task MismatchedHost_IsShortCircuitedWithoutReflectingTheRequest()
    {
        // リダイレクトを追わないクライアントを共有ヘルパーから受け取る
        // (組み立てを書き写すと、ヘッダーやタイムアウトの既定を足したときに
        //  この 2 つのテストにだけ適用されない状態ができる)
        var client = _fixture.CreateNonRedirectingClient();

        // 許可していないホスト名で叩き、短絡した応答を受け取る
        var response = await SendWithHostAsync(client, RejectedHost);

        // 手前で弾かれていること(通ってしまうと、そもそも絞り込みが効いていない)
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
        // 短絡した応答の本文を読む
        var body = await response.Content.ReadAsStringAsync();

        // <b>要求してきたホスト名を映し返していないこと（ここが本命）。</b>
        // 本文はフレームワークの定型文で、キャッシュ抑止が効かないこの経路で
        // リクエスト由来の値を反射すると、共有キャッシュへ毒を仕込む足がかりになる
        Assert.DoesNotContain(RejectedHost, body, StringComparison.OrdinalIgnoreCase);
        // アプリの画面ではなく、フレームワークの定型文であること
        // （アプリの画面なら PHI を載せうるので、前提そのものが変わる）
        Assert.Contains("Invalid Hostname", body, StringComparison.Ordinal);
    }

    // 設定値ごとに「許可リストに無いホストが通るか」を実測で固定する。
    //
    // <b>なぜここで確かめるのか。</b> Program.cs の警告ログ(AllowedHostsPolicy.IsPermissive)は
    // 「この設定はどのホストでも受け付ける」という前提の上に立っている。その前提が実際の
    // HostFiltering の挙動と合っているかは、起動したアプリでしか確かめられない。
    //
    // <b>200 と 400 を同じ表で見る。</b> 「通ること」だけを並べると、判定を広げる変異
    // (全拒否になる設定まで permissive と呼ぶ形)を 1 つも捕まえられない。
    //
    // <b>実測した扱いを、そのまま判定側にも突き合わせる。</b> 各行は 2 つを見る:
    // (a) フレームワークが実際にどう扱うか、(b) AllowedHostsPolicy.IsPermissive が
    // それと同じ答えを出すか。<b>(b) が要点である</b> ——(a) だけだと「フレームワークの
    // 挙動」を確かめるだけで、判定側を壊しても落ちない。実測でも、ClassifyEntries から
    // 正規化(ToUriComponent)を外す変異は (a) だけの版では全件緑のまま通った
    // (フレームワークは自分で正規化するので 200 のまま)。(b) があれば、
    // 全角の行で「200 なのに判定は false」となって必ず落ちる。
    //
    // <b>覆っている範囲は正しく見積もること。</b> ここはアプリを 1 件につき 1 回起動する
    // (一時 DB を作り、マイグレーションを全部流す)ので、AllowedHostsPolicyTests の
    // ケースすべては写さない。選んでいるのは<b>フレームワーク側の前提が意外で、かつ
    // 判定がそれに依存している</b>綴りだけ ——ワイルドカード 3 綴り・既定値への
    // フォールバック・トリムしないこと・正規化。
    // <b>「両方の表が 1 対 1 に対応している」とは書かない</b> ——一致を機械的に守って
    // いるのはここに並べた行だけで、残りは AllowedHostsPolicyTests 側にしかない。
    //
    // 本文が 1 行も違わない写しを設定値の数だけ作らないため、[Theory] に畳んである
    // (CLAUDE.md §6 DRY)。
    [Theory]
    // --- 全許可: ワイルドカード 3 綴り。実ホスト名を併記しても許可リスト全体が無効になる ---
    // HTTP.sys のワイルドカード
    [InlineData("*;" + AllowedHost, 200, "* が 1 つでもあれば許可リスト全体が無効になる")]
    // Kestrel の IPv6 Any
    [InlineData("[::];" + AllowedHost, 200, "IPv6 Any も同じ扱い")]
    // IPv4 Any。ASPNETCORE_URLS=http://0.0.0.0:8080 を写すと自然に生まれる綴り
    [InlineData("0.0.0.0;" + AllowedHost, 200, "IPv4 Any も同じ扱い")]
    // --- 全許可: ワイルドカードとは別の経路(既定値へのフォールバック) ---
    // 空の項目を落とすと 1 件も残らず、フレームワークが既定の ["*"] を入れる
    // (規則と根拠は AllowedHostsPolicy.IsPermissive の docstring が正本)。
    // 手で書くよりテンプレート展開 AllowedHosts=${PRIMARY};${SECONDARY} で生まれやすい
    [InlineData(";", 200, "項目が 1 件も残らないので既定の [\"*\"] へ落ちる")]
    // --- 全拒否: 「空の項目は無害」なのは空でない項目が残る場合だけ ---
    // " ; " は項目が 2 件残るので既定へ落ちず、許可リストが [" ", " "] になる
    [InlineData(" ; ", 400, "空白は項目として残るので既定へ落ちない")]
    // <b>トリムされない。</b> 空白付きのワイルドカードは正規化しても綴りが一致しない。
    // (AllowedHost と併記した形は、同じ 1 つの仕組みしか確かめられないうえ
    //  アプリの起動が 1 回増えるので置いていない ——判定側は
    //  AllowedHostsPolicyTests が安く固定している)
    [InlineData("  *  ", 400, "前後の空白は落とされず \"*\" と一致しない")]
    // <b>ただし「空白を足せば必ず死ぬ」わけではない。</b> HostString.ToUriComponent() は
    // 角括弧の IPv6 リテラルで "]" より後ろを捨てるので、"[::] " は "[::]" へ戻り
    // <b>ワイルドカードとして効いてしまう</b>。空白付きの綴りを一律に「一致しない」と
    // 扱う判定（生の綴りを Trim() と比べる形）は、ここで全許可の設定を見逃す
    [InlineData("[::] ", 200, "角括弧 IPv6 は \"]\" の後ろが捨てられ [::] に戻る")]
    // --- 全許可: 正規化(IDNA / NFKC)を通してから突き合わせること ---
    // <b>この 1 件が正規化の検証を支えている。</b> 全角で書いた 0.0.0.0 は
    // 正規化で 0.0.0.0 になるので全許可になる ——ClassifyEntries から
    // ToUriComponent() を外す変異は、これが無いと全件緑のまま通る
    // (判定側も「全角は一致しない」で辻褄が合ってしまうため)
    [InlineData("０.０.０.０", 200, "全角数字は IDNA/NFKC で 0.0.0.0 に正規化される")]
    public async Task AllowedHostsValue_DecidesWhetherAnUnlistedHostGetsThrough(
        string allowedHosts, int expectedStatus, string why)
    {
        // その設定値でアプリを起動する
        using var fixture = new AllowedHostsFixture(allowedHosts);
        // リダイレクトを追わないクライアントを受け取る
        var client = fixture.CreateNonRedirectingClient();

        // 許可リストに「書かれていない」ホスト名で叩く
        var response = await SendWithHostAsync(client, RejectedHost);

        // (a) フレームワークが期待した扱いをしていること(落ちたときに理由が読めるよう根拠も出す)
        Assert.True(
            expectedStatus == (int)response.StatusCode,
            $"AllowedHosts=\"{allowedHosts}\" は {expectedStatus} になるはず({why})。" +
            $"実際は {(int)response.StatusCode}。" +
            "ここが変わったなら AllowedHostsPolicy の判定も同じだけ動かす必要がある");

        // 200 で通る＝どんな Host も受け付ける＝警告を出すべき設定、という対応を作る
        var shouldWarn = expectedStatus == 200;

        // (b) 判定側が実測と同じ答えを出していること(ここが判定の退行を落とす)
        Assert.True(
            shouldWarn == AllowedHostsPolicy.IsPermissive(allowedHosts),
            $"AllowedHosts=\"{allowedHosts}\" を、フレームワークは" +
            $"{(shouldWarn ? "素通りさせる" : "弾く")}のに " +
            $"IsPermissive は {AllowedHostsPolicy.IsPermissive(allowedHosts)} を返した({why})。" +
            "判定はフレームワークの挙動を写したものなので、食い違ったらどちらかが退行している");
    }

    // <b>この PR の中心にある実測を固定する。</b> 区切りのうしろに空白を入れた複数指定は、
    // 1 件目が生きたまま 2 件目だけが死ぬ ——「サイトは動いているのに特定のホスト名だけが
    // 落ちる」という、監視にもヘルスチェックにも出ない形。
    //
    // <b>この 1 件だけは、片方のホストを見るだけでは足りない。</b> 400 側だけを見ると
    // 「絞り込みが強すぎて全部落ちている」設定と区別が付かず、200 側だけを見ると
    // 「ふつうに動いている」としか読めない。<b>2 つ揃ってはじめて「部分的に死んでいる」</b>
    // という主張になる ——そしてその主張が NeverMatchingEntries を足した理由そのもので、
    // docs/security.md と CLAUDE.md と Program.cs のコメントが揃ってこれを根拠にしている。
    //
    // 固定していないと、将来フレームワークが項目をトリムし始めた（＝この綴りが正しく
    // 動くようになった）ときに、警告だけが「死んでいる」と言い続けるのに
    // <b>全件緑のまま</b>になる。
    [Fact]
    public async Task WhitespaceAfterASeparator_KillsOnlyThatEntry()
    {
        // 一覧を書くときに自然に入る形（区切りのうしろに空白）。
        // <b>1 つの定数にまとめる</b> ——起動する設定と、判定へ渡す設定が
        // 別々の綴りへずれると、HTTP 側と判定側で違う設定を語りながら緑のままになる
        const string allowedHosts = $"{AllowedHost}; {SecondHost}";

        // その設定でアプリを起動する
        using var fixture = new AllowedHostsFixture(allowedHosts);
        // リダイレクトを追わないクライアントを受け取る
        var client = fixture.CreateNonRedirectingClient();

        // 1 件目（空白が付いていない側）は、これまでどおり受け付けられること
        Assert.Equal(
            System.Net.HttpStatusCode.OK,
            (await SendWithHostAsync(client, AllowedHost)).StatusCode);

        // 2 件目（空白が付いた側）は、書いてあるのに弾かれること ——ここが本命
        Assert.Equal(
            System.Net.HttpStatusCode.BadRequest,
            (await SendWithHostAsync(client, SecondHost)).StatusCode);

        // 判定側もその 2 件目を「一致しえない項目」として名指しできること
        // （実測とコードの主張がここで結び付く）
        Assert.Equal(
            $" {SecondHost}",
            Assert.Single(AllowedHostsPolicy.NeverMatchingEntries(allowedHosts)));

        // 絞り込み自体は効いているので、1 本目の警告は出ない
        // （出ないことがそのまま「誤った安心」になる、というのが 2 本目を足した理由）
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    // <b>「一致しえない項目」のもう 1 つの形を、実際の HTTP で固定する（issue #256）。</b>
    // HostString.MatchesAny はリクエスト側の値から<b>ポートを落として</b>から許可リストの
    // 項目と<b>そのまま</b>比べるので、ポートを書いた項目はどの Host とも一致しない ——
    // <b>ポートを付けて送っても一致しない</b>のが要点で、ここを実測で押さえておかないと
    // 「ポート付きで送れば通るはず」という直感のまま判定を緩める差分が通ってしまう。
    //
    // 上の空白の検査と同じく、<b>片方のホストを見るだけでは足りない</b> ——
    // 200 側と 400 側が揃ってはじめて「サイトは生きたまま特定のホスト名だけが
    // 静かに落ちる」という主張になり、それが 2 本目の警告を足した理由そのもの。
    [Fact]
    public async Task PortInAnEntry_KillsOnlyThatEntry()
    {
        // ASPNETCORE_URLS からホスト名を写すと自然に生まれる形（2 件目にポートが付く）。
        // 起動する設定と判定へ渡す設定がずれないよう、1 つの定数にまとめる
        const string entryWithPort = $"{SecondHost}:8080";
        const string allowedHosts = $"{AllowedHost};{entryWithPort}";

        // その設定でアプリを起動する
        using var fixture = new AllowedHostsFixture(allowedHosts);
        // リダイレクトを追わないクライアントを受け取る
        var client = fixture.CreateNonRedirectingClient();

        // 1 件目（ポートの付いていない側）は、これまでどおり受け付けられること
        Assert.Equal(
            System.Net.HttpStatusCode.OK,
            (await SendWithHostAsync(client, AllowedHost)).StatusCode);

        // 2 件目は、ホスト名だけで送っても弾かれること（項目側にポートが残っているため）
        Assert.Equal(
            System.Net.HttpStatusCode.BadRequest,
            (await SendWithHostAsync(client, SecondHost)).StatusCode);

        // <b>本命。</b> 書いたとおりポートまで付けて送っても弾かれること ——
        // 突き合わせの前に Host 側のポートが落とされるので、項目とは決して等しくならない
        Assert.Equal(
            System.Net.HttpStatusCode.BadRequest,
            (await SendWithHostAsync(client, entryWithPort)).StatusCode);

        // 判定側もその項目を「一致しえない項目」として名指しできること
        // （実測とコードの主張がここで結び付く）
        Assert.Equal(
            entryWithPort,
            Assert.Single(AllowedHostsPolicy.NeverMatchingEntries(allowedHosts)));

        // 絞り込み自体は効いているので、1 本目の警告は出ない
        // （出ないことがそのまま「誤った安心」になる、というのが 2 本目を足した理由）
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    // <b>上の裏返しを固定する。</b> 「前後に空白がある項目は死んでいる」は
    // <b>綴りによらず成り立つ規則ではない</b> ——HostString.ToUriComponent() は
    // 角括弧の IPv6 リテラルで "]" より後ろを捨てるので、"[::1] " は "[::1]" へ戻り
    // <b>実際には一致する</b>（実測。同じ仕組みで "[::] " はワイルドカードに戻る）。
    //
    // 生の綴りを Trim() と比べていた頃は、この項目を「どの Host とも一致しない」と
    // 名指しし、削除してよいと案内していた ——従うと IPv6 のクライアントが一斉に
    // 400 になる。<b>警告が障害を作る側に回る</b>ので、見逃しより重い誤りだった。
    //
    // 判定側だけで固定すると、判定が写している相手（フレームワークの正規化）が
    // 変わったときに気づけないため、実際に 200 が返ることまで確かめる。
    [Fact]
    public async Task BracketedIpv6WithTrailingSpace_StillMatches_AndIsNotReportedAsDead()
    {
        // 角括弧の IPv6 リテラルに、うしろだけ空白が付いた形
        const string liveIpv6Entry = "[::1] ";
        // 実ホスト名と併記する（片方が生きている一覧という、いちばん紛らわしい形）
        const string allowedHosts = $"{AllowedHost};{liveIpv6Entry}";

        // その設定でアプリを起動する
        using var fixture = new AllowedHostsFixture(allowedHosts);
        // リダイレクトを追わないクライアントを受け取る
        var client = fixture.CreateNonRedirectingClient();

        // 空白付きで書いた IPv6 の項目が、実際には Host: [::1] を受け付けること
        Assert.Equal(
            System.Net.HttpStatusCode.OK,
            (await SendWithHostAsync(client, "[::1]")).StatusCode);

        // 絞り込み自体は効いている（この一覧に無いホストは弾かれる）こと ——
        // これが無いと「そもそも全許可だから 200 だった」と区別が付かない
        Assert.Equal(
            System.Net.HttpStatusCode.BadRequest,
            (await SendWithHostAsync(client, RejectedHost)).StatusCode);

        // <b>本命。</b> 生きている項目を「死んでいる」と名指ししないこと
        Assert.Empty(AllowedHostsPolicy.NeverMatchingEntries(allowedHosts));

        // 全許可でもないので、1 本目の警告も出ないこと（2 本とも黙るのが正しい設定）
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    /// <summary>指定した <c>Host</c> ヘッダーだけを差し替えて 1 回叩く。</summary>
    /// <param name="client">リダイレクトを追わないクライアント。</param>
    /// <param name="host">送る Host ヘッダーの値。</param>
    /// <returns>受け取った応答。</returns>
    private static Task<HttpResponseMessage> SendWithHostAsync(HttpClient client, string host)
    {
        // 検査対象の経路（認証不要で 200 が返る画面）へのリクエストを組み立てる
        var request = new HttpRequestMessage(HttpMethod.Get, "/Account/AccessDenied");
        // Host ヘッダーだけを指定された値にする
        request.Headers.Host = host;
        // 応答を返す（待つのは呼び出し側）
        return client.SendAsync(request);
    }

    // 正規化できない綴りは、フレームワーク自身が例外を投げること。
    //
    // <b>AllowedHostsPolicy が fail-closed で警告する根拠がこれ。</b> 200 でも 400 でもない
    // ——つまり「絞れている」とは言えないので、判定は警告する側へ倒してある。
    // この実測を固定しておかないと、docstring の主張を支えるものが何も無くなる。
    [Fact]
    public async Task AllowedHostsThatCannotBeNormalized_MakeTheFrameworkThrow()
    {
        // ホスト名として正規化できない綴り(末尾にタブ)でアプリを起動する
        using var fixture = new AllowedHostsFixture("0.0.0.0\t");
        // リダイレクトを追わないクライアントを受け取る
        var client = fixture.CreateNonRedirectingClient();

        // 許可リストの正規化そのものが失敗するので、応答に至らず例外になる
        var error = await Assert.ThrowsAsync<ArgumentException>(
            () => SendWithHostAsync(client, RejectedHost));

        // 失敗の出どころがホスト名の正規化であること(別の理由で落ちても緑にしない)
        Assert.Contains("IDN", error.Message, StringComparison.Ordinal);
    }

    // <b>フレームワークは項目を宣言順に正規化し、最初のワイルドカードで打ち切る。</b>
    // そのため正規化できない項目が「前」にあれば例外、「後ろ」なら評価されず全許可になる。
    //
    // <b>この 1 件が ClassifyDeadEntryDeletion の Unknown を支えている。</b>
    // 「消したら何が起きるか」を bool で答えると、どちらかの並びで必ず事実と逆の案内になる
    // ——だから断定をやめた、というのが 3 値にした理由。その前提が上流の実装ごと
    // 変わったら（例外を捕まえて読み飛ばすようになる等）Unknown は過剰になるので、
    // 判定側の表ではなく<b>実際のフレームワーク</b>に対して固定しておく必要がある
    // （CLAUDE.md: フレームワーク側の前提はこのクラスが、判定の境界は
    //   AllowedHostsPolicyTests が固定する）。
    [Fact]
    public async Task UnparsableEntry_ChangesTheOutcomeDependingOnItsPositionInTheList()
    {
        // 正規化できない項目が<b>ワイルドカードより前</b>にある並び
        using (var fixture = new AllowedHostsFixture($"{UnparsableHost};0.0.0.0"))
        {
            // 先に正規化されて失敗するので、応答に至らず例外になる
            var error = await Assert.ThrowsAsync<ArgumentException>(
                () => SendWithHostAsync(fixture.CreateNonRedirectingClient(), RejectedHost));

            // <b>出どころがホスト名の正規化であることまで見る。</b> 型だけだと、
            // 起動や設定バインドが別の理由で投げても緑になり、
            // 「並び順で変わる」という前提が崩れたことを見逃す
            Assert.Contains("IDN", error.Message, StringComparison.Ordinal);
        }

        // 同じ 2 項目を<b>入れ替えた</b>だけの並び
        using (var fixture = new AllowedHostsFixture($"0.0.0.0;{UnparsableHost}"))
        {
            // 先頭のワイルドカードで打ち切られるので、壊れた項目は評価されず全許可になる
            var response = await SendWithHostAsync(fixture.CreateNonRedirectingClient(), RejectedHost);

            // 許可リストに無いホスト名が素通りすること（＝並び順で答えが反転する）
            Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        }
    }

    /// <summary>指定した `AllowedHosts` で起動するアプリ。</summary>
    /// <remarks>
    /// 値だけが違う同じ本文を綴りの数だけ書き写さないために、設定値を受け取る形にしてある
    /// （CLAUDE.md §6 DRY）。
    /// </remarks>
    /// <param name="allowedHosts">そのアプリへ渡す `AllowedHosts` の値。</param>
    private sealed class AllowedHostsFixture(string allowedHosts) : TempDatabaseAppFixture(
        "ii-hostfilter-cfg",
        new Dictionary<string, string?>
        {
            // 検証したい許可リストをそのまま渡す
            ["AllowedHosts"] = allowedHosts,
        });

    // 許可したホスト名なら、これまでどおりミドルウェアが既定の no-store を入れること。
    //
    // 上の検査は「弾かれること」しか見ないので、絞り込みが強すぎて全リクエストが 400 に
    // なる設定ミスでも緑になる。対にしておけば、短絡が「一致しないときだけ」だと分かる。
    [Fact]
    public async Task MatchingHost_StillGetsTheNoStoreDefault()
    {
        // 上と同じ組み立てのクライアントを共有ヘルパーから受け取る
        var client = _fixture.CreateNonRedirectingClient();

        // 許可したホスト名で叩き、通常どおり処理された応答を受け取る
        var response = await SendWithHostAsync(client, AllowedHost);

        // 手前で弾かれていないこと
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        // ミドルウェアの既定(no-store)が入っていること
        Assert.Equal(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            response.Headers.CacheControl?.ToString());
    }
}
