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

    // 一致しない Host ヘッダーの応答が、本文を持たないこと。
    [Fact]
    public async Task MismatchedHost_IsShortCircuitedWithoutABody()
    {
        // リダイレクトを追わない素のクライアントを使う(短絡した応答そのものを見たい)
        var client = _fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 追うと短絡した応答が観測できなくなる
            AllowAutoRedirect = false,
        });
        // 許可していないホスト名でリクエストを組み立てる
        var request = new HttpRequestMessage(HttpMethod.Get, "/Account/AccessDenied");
        // Host ヘッダーだけを許可リスト外の値にする
        request.Headers.Host = RejectedHost;

        // 短絡した応答を受け取る
        var response = await client.SendAsync(request);

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

    // 許可したホスト名なら、これまでどおりミドルウェアが既定の no-store を入れること。
    //
    // 上の検査は「弾かれること」しか見ないので、絞り込みが強すぎて全リクエストが 400 に
    // なる設定ミスでも緑になる。対にしておけば、短絡が「一致しないときだけ」だと分かる。
    [Fact]
    public async Task MatchingHost_StillGetsTheNoStoreDefault()
    {
        // 同じ条件のクライアントを使う
        var client = _fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 比較条件をそろえる
            AllowAutoRedirect = false,
        });
        // 許可したホスト名でリクエストを組み立てる
        var request = new HttpRequestMessage(HttpMethod.Get, "/Account/AccessDenied");
        // Host ヘッダーを許可リストの値にする
        request.Headers.Host = AllowedHost;

        // 通常どおり処理された応答を受け取る
        var response = await client.SendAsync(request);

        // 手前で弾かれていないこと
        Assert.Equal(System.Net.HttpStatusCode.OK, response.StatusCode);
        // ミドルウェアの既定(no-store)が入っていること
        Assert.Equal(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            response.Headers.CacheControl?.ToString());
    }
}
