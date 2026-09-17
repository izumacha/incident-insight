// テスト対象のミドルウェア(キャッシュ抑止の値の定数)を使う
using IncidentInsight.Web.Middleware;
// WebApplicationFactory(実 HTTP パイプラインでの統合テスト)を使う
using Microsoft.AspNetCore.Mvc.Testing;
// テスト用の設定上書きに使う
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
// 正規表現でアンチフォージェリトークンを取り出すために使う
using System.Text.RegularExpressions;

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
public class ResponseCacheHeaderIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    // 認証が要る経路(/Analytics の JSON)を叩くためにシードするデモ管理者のメールアドレス。
    // appsettings.Development.json の既定値と同じ値を設定で上書きして使う
    private const string AdminEmail = "admin@hospital.local";

    // デモ管理者のパスワード。Development のポリシー(8 文字以上・大文字・数字)を満たす値。
    // テスト専用の値で、リポジトリの実行時設定には入らない(下の ConfigureAppConfiguration 参照)
    private const string AdminPassword = "AdminPass1";

    // ログインフォームからアンチフォージェリトークンを取り出す正規表現。
    // 入力は自分のアプリが返した HTML なので外部入力ではない(§9 の ReDoS 対象外)
    private static readonly Regex AntiforgeryTokenPattern = new(
        "name=\"__RequestVerificationToken\"[^>]*value=\"(?<token>[^\"]+)\"",
        RegexOptions.Compiled);

    // アプリ全体を起動するテスト用ファクトリ
    private readonly WebApplicationFactory<Program> _factory;

    public ResponseCacheHeaderIntegrationTests(WebApplicationFactory<Program> factory)
    {
        // 実運用設定を汚さないよう、テスト専用の設定でアプリを起動する
        _factory = factory.WithWebHostBuilder(builder =>
        {
            // シード・パスワードポリシーが緩い Development 環境として起動する
            builder.UseEnvironment("Development");
            // 設定値をテスト用に上書きする
            builder.ConfigureAppConfiguration((_, config) =>
            {
                // メモリ上の設定ソースを最後に追加して既存設定を上書きする
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    // DB はテスト専用の一時ファイルへ向ける(リポジトリ内に DB を作らない)
                    ["ConnectionStrings:DefaultConnection"] =
                        $"Data Source={Path.Combine(Path.GetTempPath(), $"ii-cacheheader-{Guid.NewGuid():N}.db")}",
                    // 認証が要る JSON を叩くため、デモ管理者のシードを有効にする
                    ["SeedAccounts:AdminEmail"] = AdminEmail,
                    ["SeedAccounts:AdminPassword"] = AdminPassword,
                });
            });
        });
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
    /// 自動追跡を切るのは、302 を追った先の応答ヘッダを見てしまうと
    /// 「どの応答を検証しているか」が分からなくなるため。
    /// </remarks>
    /// <returns>組み立てた HttpClient。</returns>
    private HttpClient CreateClient() =>
        _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 302 等を自動で追跡しない
            AllowAutoRedirect = false,
        });

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
