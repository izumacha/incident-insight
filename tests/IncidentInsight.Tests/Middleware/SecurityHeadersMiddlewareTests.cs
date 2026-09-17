// テスト対象のミドルウェアを使う
using IncidentInsight.Web.Middleware;
// HttpContext のテスト用実装(DefaultHttpContext)を使う
using Microsoft.AspNetCore.Http;
// 応答フィーチャー(IHttpResponseFeature / HttpResponseFeature)を差し替えるために使う
using Microsoft.AspNetCore.Http.Features;

// このテストクラスの名前空間(置き場所)を宣言している
namespace IncidentInsight.Tests.Middleware;

// SecurityHeadersMiddleware がレスポンスへ想定通りのヘッダーを付与し、
// かつパイプラインの次の処理を必ず呼び出す(短絡させない)ことを検証する
public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_AddsExpectedSecurityHeaders()
    {
        // 次のミドルウェアが呼ばれたかどうかを記録するフラグ
        var nextCalled = false;
        // 「次の処理」役のダミーデリゲート(呼ばれたことを記録するだけ)
        RequestDelegate next = _ =>
        {
            // 呼び出されたことを記録する
            nextCalled = true;
            // 完了済みタスクを返す(実際の処理は不要)
            return Task.CompletedTask;
        };
        // テスト対象のミドルウェアインスタンスを組み立てる
        var middleware = new SecurityHeadersMiddleware(next);
        // テスト用の HttpContext(実際の HTTP 接続なしで動作する)
        var context = new DefaultHttpContext();

        // ミドルウェアを実行する
        await middleware.InvokeAsync(context);

        // MIME スニッフィング防止ヘッダーが付与されていることを確認
        Assert.Equal("nosniff", context.Response.Headers["X-Content-Type-Options"]);
        // クリックジャッキング防止ヘッダーが付与されていることを確認
        Assert.Equal("DENY", context.Response.Headers["X-Frame-Options"]);
        // Referrer 漏洩防止ヘッダーが付与されていることを確認
        Assert.Equal("strict-origin-when-cross-origin", context.Response.Headers["Referrer-Policy"]);
        // 次のミドルウェアが短絡されずに呼び出されたことを確認
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_SetsHeaders_BeforeCallingNext()
    {
        // next() が呼ばれた時点で既にヘッダーが設定済みであることを検証する。
        // 後続ミドルウェアがこのヘッダーを参照・上書き判断できるようにするための順序保証。
        string? headerValueSeenByNext = null;
        // 「次の処理」内でヘッダーの値を読み取って記録する
        RequestDelegate next = ctx =>
        {
            // next() 実行時点でのヘッダー値を保存する
            headerValueSeenByNext = ctx.Response.Headers["X-Frame-Options"];
            return Task.CompletedTask;
        };
        // テスト対象を構築
        var middleware = new SecurityHeadersMiddleware(next);
        // テスト用 HttpContext
        var context = new DefaultHttpContext();

        // ミドルウェアを実行
        await middleware.InvokeAsync(context);

        // next() 実行時点で既にヘッダーが設定済みだったことを確認する
        Assert.Equal("DENY", headerValueSeenByNext);
    }

    // ── キャッシュ抑止の既定値 ────────────────────────────────────────────
    //
    // 規則は「誰もキャッシュ指示を書かなかった応答にだけ no-store を入れる」の 1 つだけ
    // (応答の種類で振り分けない理由はミドルウェア側の docstring が正本)。
    // 判定は応答開始直前の OnStarting コールバックで走るが、そのコールバックは
    // DefaultHttpContext の既定の応答フィーチャーでは発火しない(既定実装が空)ため、
    // 発火させられるテスト用フィーチャーへ差し替えて観測する。

    [Fact]
    public async Task InvokeAsync_OnStarting_AddsNoStore_WhenNobodyDeclaredCaching()
    {
        // OnStarting に登録されたコールバックを取り出せるテスト用の応答フィーチャーを用意する
        var responseFeature = new CapturingResponseFeature();
        // リクエスト・レスポンスのフィーチャーだけを持つ最小構成の HttpContext を組み立てる
        var context = BuildContextWith(responseFeature);
        // 「次の処理」役として、画面(HTML)を返すアクションを模して Content-Type だけ設定する
        RequestDelegate next = ctx =>
        {
            // MVC がビューを描画したときと同じ種別を設定する(キャッシュ指示は書かない)
            ctx.Response.ContentType = "text/html; charset=utf-8";
            return Task.CompletedTask;
        };
        // テスト対象を構築する
        var middleware = new SecurityHeadersMiddleware(next);

        // ミドルウェアを実行する(この時点ではまだ応答は開始していない)
        await middleware.InvokeAsync(context);
        // 応答開始のタイミングを模して、登録済みコールバックを実行する
        await responseFeature.FireOnStartingAsync();

        // 誰も指示していない応答にキャッシュ抑止が入っていることを確認する
        Assert.Equal(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            context.Response.Headers.CacheControl.ToString());
    }

    [Theory]
    // 静的ファイル配信(Program.cs の OnPrepareResponse)が名乗る指示。
    // これを尊重することが「静的アセットを no-store にしない」唯一の仕組み
    [InlineData(SecurityHeadersMiddleware.StaticAssetCacheControl)]
    // HomeController.Error の [ResponseCache(NoStore = true, Location = None)] が書く値
    [InlineData("no-store,no-cache")]
    // MapHealthChecks が自分で書く値
    [InlineData("no-store, no-cache")]
    // 制限の緩い指示であっても上書きしないこと。これは<b>静的アセットのため</b>にある挙動で
    // (上の StaticAssetCacheControl と同じ形)、MVC のアクションがこの形を名乗ってよいという
    // 意味ではない —— PHI を返すアクションへキャッシュ可能な [ResponseCache] を足す道は
    // ResponseCacheAttributePolicyTests が宣言の形で塞いでいる。
    // ここで見ているのは「ミドルウェアは他人の指示を書き換えない」という 1 点だけ
    [InlineData("public, max-age=600")]
    public async Task InvokeAsync_OnStarting_LeavesDeclaredCacheControlUntouched(string declared)
    {
        // OnStarting のコールバックを捕まえるテスト用フィーチャーを用意する
        var responseFeature = new CapturingResponseFeature();
        // 最小構成の HttpContext を組み立てる
        var context = BuildContextWith(responseFeature);
        // 「次の処理」役として、自分でキャッシュ指示を書く応答を模す
        RequestDelegate next = ctx =>
        {
            // 応答の種別を設定する(種別では振り分けないので、ここは何でもよい)
            ctx.Response.ContentType = "text/html; charset=utf-8";
            // 書き手(静的ファイル配信・[ResponseCache]・ヘルスチェック等)の意図を書き込む
            ctx.Response.Headers.CacheControl = declared;
            return Task.CompletedTask;
        };
        // テスト対象を構築する
        var middleware = new SecurityHeadersMiddleware(next);

        // ミドルウェアを実行する
        await middleware.InvokeAsync(context);
        // 応答開始のタイミングを模してコールバックを実行する
        await responseFeature.FireOnStartingAsync();

        // 書き手が明示した値がそのまま残っていることを確認する
        Assert.Equal(declared, context.Response.Headers.CacheControl.ToString());
    }

    // 静的アセット用の指示が、docstring が述べている不変条件を実際に満たしていること。
    //
    // <b>なぜ要るのか。</b> 統合テストは「配信された値が定数と一致するか」しか見ないので、
    // <b>定数の値そのものに対しては恒真</b>になる ——実測でも、定数を
    // "public,max-age=31536000,immutable" に書き換えると 878 件すべて緑のまま通った。
    // ところが StaticAssetCacheControl の docstring は「期間を短く保ち immutable を付けない」
    // ことを明確な理由付きで要求している: _Layout.cshtml と _ValidationScriptsPartial.cshtml が
    // wwwroot/lib 配下(jQuery 等)を asp-append-version なしで参照しているため、長期・immutable に
    // すると脆弱性修正後も古いファイルが利用者のキャッシュに残り、消す手段が無くなる。
    // 文章だけの不変条件は破っても誰も気付かないので、ここで機械的に固定する。
    [Fact]
    public void StaticAssetCacheControl_StaysShortLivedAndRevalidatable()
    {
        // 定数を解析して、指示ごとの値を取り出す
        var directives = SecurityHeadersMiddleware.StaticAssetCacheControl
            // カンマ区切りの各指示へ分ける
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        // immutable を付けていないこと(付けると再取得の手段が無くなる)
        Assert.DoesNotContain(
            directives,
            d => d.Equals("immutable", StringComparison.OrdinalIgnoreCase));

        // max-age の指示を取り出す(無ければキャッシュ期間の意図が読めないので落とす)
        var maxAge = directives
            .FirstOrDefault(d => d.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase));
        Assert.True(
            maxAge is not null,
            $"静的アセットの指示に max-age がありません: {SecurityHeadersMiddleware.StaticAssetCacheControl}");

        // 秒数として読めること(読めない綴りを「上限内」と扱わない ——fail-closed)
        Assert.True(
            int.TryParse(maxAge!["max-age=".Length..], out var seconds),
            $"max-age の値を秒数として読み取れません: {maxAge}");

        // 上限は 1 日。版付きでない lib/ の更新が利用者へ届くまでの最長時間がこの値になる。
        // 引き上げたいときは、まず lib/ 配下も版付き URL で参照する形へ変えること
        Assert.True(
            seconds <= 24 * 60 * 60,
            $"静的アセットの max-age が長すぎます({seconds} 秒)。"
                + "wwwroot/lib 配下は版を付けずに参照されているため、長くすると"
                + "ライブラリの脆弱性修正後も古いファイルが利用者のキャッシュに残り続けます。");
    }

    /// <summary>
    /// 指定した応答フィーチャーだけを持つ最小構成の <see cref="HttpContext"/> を作る。
    /// </summary>
    /// <remarks>
    /// <c>DefaultHttpContext</c> の既定の応答フィーチャーは <c>OnStarting</c> が空実装で、
    /// 登録したコールバックが永久に発火しない。そのままではキャッシュ抑止の配線を
    /// 単体テストで観測できないため、コールバックを保持して任意に発火できる差し替えを使う。
    /// </remarks>
    /// <param name="responseFeature">差し替える応答フィーチャー。</param>
    /// <returns>組み立てた HttpContext。</returns>
    private static HttpContext BuildContextWith(IHttpResponseFeature responseFeature)
    {
        // フィーチャーの入れ物を作る
        var features = new FeatureCollection();
        // リクエスト側は既定実装で足りる(このテストはリクエストを読まない)
        features.Set<IHttpRequestFeature>(new HttpRequestFeature());
        // 応答側だけテスト用の差し替えを登録する
        features.Set(responseFeature);
        // そのフィーチャー集合で HttpContext を組み立てて返す
        return new DefaultHttpContext(features);
    }

    /// <summary>
    /// <c>OnStarting</c> に登録されたコールバックを保持し、テストから発火できる応答フィーチャー。
    /// </summary>
    private sealed class CapturingResponseFeature : HttpResponseFeature
    {
        // 登録されたコールバックとその状態オブジェクトを登録順に貯めるリスト
        private readonly List<(Func<object, Task> Callback, object State)> _callbacks = new();

        // ASP.NET Core の実装と同じシグネチャで登録を受け取り、発火せずに控えておく
        public override void OnStarting(Func<object, Task> callback, object state)
        {
            // 後で発火できるようコールバックと状態を保存する
            _callbacks.Add((callback, state));
        }

        /// <summary>
        /// 応答開始のタイミングを模して、控えておいたコールバックを実行する。
        /// </summary>
        /// <remarks>
        /// 実行順は ASP.NET Core と同じ後入れ先出し(逆順)にする。順序をそろえないと
        /// 「内側が書いた Cache-Control を上書きしない」という性質を正しく検証できない。
        /// </remarks>
        public async Task FireOnStartingAsync()
        {
            // 登録の逆順に走査する(最後に登録されたものから実行する)
            for (var i = _callbacks.Count - 1; i >= 0; i--)
            {
                // 保存しておいたコールバックを、保存しておいた状態で実行する
                await _callbacks[i].Callback(_callbacks[i].State);
            }
        }
    }
}
