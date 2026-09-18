// レート制限の設定キー定数を使う
using IncidentInsight.Web.Models.RateLimiting;
// HTTP ステータスコード列挙を使う
using System.Net;
// 共有のフィクスチャを使う
using IncidentInsight.Tests.Helpers;

// テストクラスの名前空間(既存の Controllers 配下テストと同じ場所)
namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// POST /Account/Login のレート制限が「実際に」効くことを検証する統合テスト。
/// 属性・定数の単体テストだけでは Program.cs から AddRateLimiter / UseRateLimiter の
/// 配線を丸ごと削除しても検知できない(属性は登録が無ければ黙って無視される)ため、
/// 実 HTTP パイプラインで 429 が返る回帰テストを 1 本持つ。
/// </summary>
public class LoginRateLimitIntegrationTests : IClassFixture<LoginRateLimitIntegrationTests.AppFixture>
{
    // テスト用に緩和した許可回数(この回数を超えた POST が 429 になる)
    private const int TestPermitLimit = 2;

    // クライアントの組み立て規則を持つフィクスチャ(アプリは 1 度だけ起動されている)
    private readonly AppFixture _fixture;

    public LoginRateLimitIntegrationTests(AppFixture fixture)
    {
        // クライアントの組み立てを任せるためフィクスチャ自体を保持する
        _fixture = fixture;
    }

    /// <summary>
    /// このテストクラスが共有する、一時 DB を指して 1 度だけ起動したアプリ。
    /// </summary>
    /// <remarks>
    /// 以前はコンストラクタで <c>WithWebHostBuilder</c> を呼んでいたため、xUnit が
    /// テストメソッドごとにテストクラスを作り直すのに合わせてアプリが起動し直され、
    /// そのたびに別名の一時 DB が残っていた(誰も消さないので溜まり続ける)。
    /// 起動を 1 回に保つ仕掛けと後始末は <see cref="TempDatabaseAppFixture"/> が持つ。
    /// ここはこのテストに固有の設定 ——レート制限の枠—— だけを渡す。
    ///
    /// <para><b>このクラスにテストを足すときの注意(共有される状態がある)。</b>
    /// ホストを 1 つに共有した結果、<b>レート制限の枠もクラス全体で共有される</b>。
    /// しかもウィンドウを 3600 秒にしてあるので、実行中に枠が回復することはない。
    /// つまり <c>POST /Account/Login</c> を叩くテストを 2 つ目に足すと、
    /// <b>後に走ったほうは 1 回目のリクエストから 429 を受ける</b>。
    /// 失敗文言はレート制限を指すので、原因がテスト間の汚染だと気付きにくい。</para>
    ///
    /// <para><b>なぜテストごとに分けないのか。</b> 分ける方法が無い。制限の単位は
    /// <c>ClientIpPartition.GetPartitionKey(HttpContext.Connection.RemoteIpAddress)</c> で、
    /// <c>TestServer</c> 経由のリクエストでは <c>RemoteIpAddress</c> が <c>null</c> になり、
    /// fail-closed の設計どおり全員が共通の 1 バケツへ入る。ヘッダー
    /// (<c>X-Forwarded-For</c>)で変えるには転送ヘッダーの信頼設定が要るが、
    /// それも <c>KnownProxies</c> が接続元 IP と一致することを前提にしており
    /// <c>null</c> では成立しない。テスト専用のミドルウェアを差し込んで
    /// <c>RemoteIpAddress</c> を作る手もあるが、<b>検証したい当の経路</b>に
    /// テスト専用の分岐を入れることになるので採らない。</para>
    ///
    /// <para><b>したがって、追加するときは枠を共有する前提で書く</b>: 許可される回と
    /// 拒否される回を<b>1 つのテストの中で</b>順に確かめる(いまの
    /// <c>LoginPost_OverLimit_Returns429WithSafeMessage</c> がその形)。
    /// どうしても別テストに分けたいなら、そのときはテストごとにホストを分ける代わりに
    /// 一時 DB の後始末も一緒に持たせること(<see cref="TempDatabaseAppFixture"/> を
    /// テストごとに使う形にする)。</para>
    /// </remarks>
    public sealed class AppFixture() : TempDatabaseAppFixture(
        "ii-ratelimit",
        new Dictionary<string, string?>
        {
            // 許可回数を小さくしてテストを速くする
            [$"{LoginRateLimitOptions.SectionName}:PermitLimit"] = TestPermitLimit.ToString(),
            // ウィンドウを長くしてテスト中に枠がリセットされないようにする
            [$"{LoginRateLimitOptions.SectionName}:WindowSeconds"] = "3600",
        });

    [Fact]
    public async Task LoginPost_OverLimit_Returns429WithSafeMessage()
    {
        // リダイレクトを追わない素の HTTP クライアントを作る(429 をそのまま観測するため)
        var client = _fixture.CreateNonRedirectingClient();
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
        var client = _fixture.CreateNonRedirectingClient();

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
