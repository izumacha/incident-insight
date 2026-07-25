// レート制限の設定キー定数を使う
using IncidentInsight.Web.Models.RateLimiting;
// WebApplicationFactory(実 HTTP パイプラインでの統合テスト)を使う
using Microsoft.AspNetCore.Mvc.Testing;
// テスト用の設定上書きに使う
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
// HTTP ステータスコード列挙を使う
using System.Net;

// テストクラスの名前空間(既存の Controllers 配下テストと同じ場所)
namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// POST /Account/Login のレート制限が「実際に」効くことを検証する統合テスト。
/// 属性・定数の単体テストだけでは Program.cs から AddRateLimiter / UseRateLimiter の
/// 配線を丸ごと削除しても検知できない(属性は登録が無ければ黙って無視される)ため、
/// 実 HTTP パイプラインで 429 が返る回帰テストを 1 本持つ。
/// </summary>
public class LoginRateLimitIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    // テスト用に緩和した許可回数(この回数を超えた POST が 429 になる)
    private const int TestPermitLimit = 2;

    // アプリ全体を起動するテスト用ファクトリ
    private readonly WebApplicationFactory<Program> _factory;

    public LoginRateLimitIntegrationTests(WebApplicationFactory<Program> factory)
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
                        $"Data Source={Path.Combine(Path.GetTempPath(), $"ii-ratelimit-{Guid.NewGuid():N}.db")}",
                    // 許可回数を小さくしてテストを速くする
                    [$"{LoginRateLimitOptions.SectionName}:PermitLimit"] = TestPermitLimit.ToString(),
                    // ウィンドウを長くしてテスト中に枠がリセットされないようにする
                    [$"{LoginRateLimitOptions.SectionName}:WindowSeconds"] = "3600",
                });
            });
        });
    }

    [Fact]
    public async Task LoginPost_OverLimit_Returns429WithSafeMessage()
    {
        // リダイレクトを追わない素の HTTP クライアントを作る(429 をそのまま観測するため)
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 302 等を自動で追跡しない
            AllowAutoRedirect = false,
        });
        // アンチフォージェリトークンを付けない空のフォームを用意する
        // (レート制限はアンチフォージェリ検証より手前のミドルウェアで数えるため、
        //  トークン無しの 400 応答でも試行としてカウントされる)
        using var emptyForm = new FormUrlEncodedContent(new Dictionary<string, string>());

        // 許可回数ぶんの POST は 429 以外(この構成ではアンチフォージェリ拒否の 400)になるはず
        for (var i = 0; i < TestPermitLimit; i++)
        {
            // 許可枠内の POST を送信する
            var allowed = await client.PostAsync("/Account/Login", emptyForm);
            // まだ制限に達していないので 429 ではないことを確認する
            Assert.NotEqual(HttpStatusCode.TooManyRequests, allowed.StatusCode);
        }

        // 許可回数を超えた次の POST を送信する
        var rejected = await client.PostAsync("/Account/Login", emptyForm);

        // 制限超過が 429 Too Many Requests で拒否されることを確認する
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        // 応答本文を読み取る
        var body = await rejected.Content.ReadAsStringAsync();
        // 内部情報を含まない日本語の案内文が返ることを確認する
        Assert.Contains("ログイン試行回数が多すぎます", body);
    }

    [Fact]
    public async Task LoginGet_IsNotRateLimited()
    {
        // リダイレクトを追わないクライアントを作る
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 302 等を自動で追跡しない
            AllowAutoRedirect = false,
        });

        // 許可回数を大きく超える回数だけログイン画面(GET)を開く
        for (var i = 0; i < TestPermitLimit + 3; i++)
        {
            // ログイン画面の表示リクエストを送信する
            var response = await client.GetAsync("/Account/Login");
            // 画面表示(GET)は制限対象外なので 429 にならないことを確認する
            Assert.NotEqual(HttpStatusCode.TooManyRequests, response.StatusCode);
        }
    }
}
