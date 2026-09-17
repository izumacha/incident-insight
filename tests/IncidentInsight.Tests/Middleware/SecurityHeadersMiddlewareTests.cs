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

    // ── キャッシュ抑止の判定(ShouldPreventCaching) ────────────────────────
    //
    // 判定を純粋関数として切り出している理由はミドルウェア側の docstring が正本
    // (実際の呼び出し口である OnStarting は DefaultHttpContext では発火しないため、
    //  境界をここで固定しないと統合テスト 1 本だけが頼りになる)。

    [Theory]
    // 画面(HTML)はインシデント本文・報告者氏名を含むため抑止する
    [InlineData("text/html")]
    // charset 付きの実際の応答も同じく抑止する(前方一致で拾えることの確認)
    [InlineData("text/html; charset=utf-8")]
    // 種別名の大文字小文字は問わない(HTTP ヘッダーの種別は case-insensitive)
    [InlineData("TEXT/HTML; charset=utf-8")]
    // 集計 JSON(/Analytics/...)も部署別件数などを含むため抑止する
    [InlineData("application/json; charset=utf-8")]
    // 将来のエクスポート(CSV)は除外表に載っていないので自動的に抑止される側へ入る
    [InlineData("text/csv")]
    // ファイルダウンロードが名乗る汎用の種別も抑止される(いちばん守りたい応答)
    [InlineData("application/octet-stream")]
    public void ShouldPreventCaching_ReturnsTrue_ForDynamicResponses(string contentType)
    {
        // 誰もキャッシュ指示を書いていない状態で判定する(既定値を入れる場面)
        var result = SecurityHeadersMiddleware.ShouldPreventCaching(contentType, existingCacheControl: null);

        // 動的な応答と判断され、キャッシュ抑止が付くことを確認する
        Assert.True(result);
    }

    [Theory]
    // スタイルシートは版付き URL で配信される静的アセットなので抑止しない
    [InlineData("text/css")]
    // スクリプトも同様(wwwroot/js は Scripts/*.ts のコンパイル結果)
    [InlineData("text/javascript; charset=utf-8")]
    // 実行環境によってはスクリプトが application/javascript を名乗る
    [InlineData("application/javascript")]
    // 画像(favicon・ドキュメント用スクリーンショット)
    [InlineData("image/png")]
    // 自己ホストする Web フォント
    [InlineData("font/woff2")]
    // 除外の比較も大文字小文字を問わない(片方だけ case-sensitive だと答えが割れる)
    [InlineData("Text/CSS")]
    public void ShouldPreventCaching_ReturnsFalse_ForStaticAssets(string contentType)
    {
        // 静的アセットの応答として判定する
        var result = SecurityHeadersMiddleware.ShouldPreventCaching(contentType, existingCacheControl: null);

        // キャッシュを効かせたままにする(§8 配信の最適化)ことを確認する
        Assert.False(result);
    }

    [Theory]
    // Content-Type が未設定(302 リダイレクト・204 など本文を持たない応答)
    [InlineData(null)]
    // 空文字も同じ扱い
    [InlineData("")]
    // 空白のみも「未設定」として扱う
    [InlineData("   ")]
    public void ShouldPreventCaching_ReturnsFalse_WhenContentTypeIsMissing(string? contentType)
    {
        // 本文の種別が分からない応答として判定する
        var result = SecurityHeadersMiddleware.ShouldPreventCaching(contentType, existingCacheControl: null);

        // 保存される中身が無いので何もしないことを確認する
        Assert.False(result);
    }

    [Theory]
    // HomeController.Error の [ResponseCache(NoStore = true, Location = None)] が書く値
    [InlineData("no-store,no-cache")]
    // MapHealthChecks が自分で書く値
    [InlineData("no-store, no-cache")]
    // 明示的にキャッシュを許可している応答(将来そういう画面を作った場合)も尊重する
    [InlineData("public, max-age=3600")]
    public void ShouldPreventCaching_ReturnsFalse_WhenCacheControlAlreadySet(string existing)
    {
        // 動的な応答(HTML)でも、すでにキャッシュ指示があれば触らないことを確認する
        var result = SecurityHeadersMiddleware.ShouldPreventCaching("text/html; charset=utf-8", existing);

        // アクション側で明示した意図が既定値に上書きされないことを確認する
        Assert.False(result);
    }

    [Fact]
    public async Task InvokeAsync_RegistersOnStarting_ThatAddsNoStoreToHtmlResponses()
    {
        // OnStarting に登録されたコールバックを取り出せるテスト用の応答フィーチャーを用意する
        var responseFeature = new CapturingResponseFeature();
        // リクエスト・レスポンスのフィーチャーだけを持つ最小構成の HttpContext を組み立てる
        var context = BuildContextWith(responseFeature);
        // 「次の処理」役として、画面(HTML)を返すアクションを模して Content-Type だけ設定する
        RequestDelegate next = ctx =>
        {
            // MVC がビューを描画したときと同じ種別を設定する
            ctx.Response.ContentType = "text/html; charset=utf-8";
            return Task.CompletedTask;
        };
        // テスト対象を構築する
        var middleware = new SecurityHeadersMiddleware(next);

        // ミドルウェアを実行する(この時点ではまだ応答は開始していない)
        await middleware.InvokeAsync(context);
        // 応答開始のタイミングを模して、登録済みコールバックを実行する
        await responseFeature.FireOnStartingAsync();

        // 動的な応答(HTML)にキャッシュ抑止が入っていることを確認する
        Assert.Equal(
            SecurityHeadersMiddleware.NoStoreCacheControl,
            context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task InvokeAsync_OnStarting_LeavesStaticAssetResponsesCacheable()
    {
        // OnStarting のコールバックを捕まえるテスト用フィーチャーを用意する
        var responseFeature = new CapturingResponseFeature();
        // 最小構成の HttpContext を組み立てる
        var context = BuildContextWith(responseFeature);
        // 「次の処理」役として、静的ファイル配信を模して css の種別を設定する
        RequestDelegate next = ctx =>
        {
            // StaticFileMiddleware が site.css を返したときと同じ種別を設定する
            ctx.Response.ContentType = "text/css";
            return Task.CompletedTask;
        };
        // テスト対象を構築する
        var middleware = new SecurityHeadersMiddleware(next);

        // ミドルウェアを実行する
        await middleware.InvokeAsync(context);
        // 応答開始のタイミングを模してコールバックを実行する
        await responseFeature.FireOnStartingAsync();

        // 静的アセットにはキャッシュ抑止が入らない(版付き URL のキャッシュが効き続ける)
        Assert.True(string.IsNullOrEmpty(context.Response.Headers.CacheControl.ToString()));
    }

    [Fact]
    public async Task InvokeAsync_OnStarting_DoesNotOverwriteCacheControlSetByTheAction()
    {
        // OnStarting のコールバックを捕まえるテスト用フィーチャーを用意する
        var responseFeature = new CapturingResponseFeature();
        // 最小構成の HttpContext を組み立てる
        var context = BuildContextWith(responseFeature);
        // アクション側が明示したキャッシュ指示(HomeController.Error の [ResponseCache] 相当)
        const string explicitDirective = "no-store,no-cache";
        // 「次の処理」役として、種別と明示的な Cache-Control の両方を設定する
        RequestDelegate next = ctx =>
        {
            // エラーページも HTML を返す
            ctx.Response.ContentType = "text/html; charset=utf-8";
            // アクション側の意図を書き込む
            ctx.Response.Headers.CacheControl = explicitDirective;
            return Task.CompletedTask;
        };
        // テスト対象を構築する
        var middleware = new SecurityHeadersMiddleware(next);

        // ミドルウェアを実行する
        await middleware.InvokeAsync(context);
        // 応答開始のタイミングを模してコールバックを実行する
        await responseFeature.FireOnStartingAsync();

        // アクション側が書いた値がそのまま残っていることを確認する
        Assert.Equal(explicitDirective, context.Response.Headers.CacheControl.ToString());
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
