// ASP.NET Core のミドルウェア基盤(HttpContext / RequestDelegate)を使う
using Microsoft.AspNetCore.Http;

// このミドルウェアの名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Middleware;

/// <summary>
/// 全レスポンスに最小限のセキュリティ関連 HTTP ヘッダーを付与するミドルウェア。
///
/// 追加するヘッダー:
///   - X-Content-Type-Options: nosniff
///     ブラウザによる Content-Type の推測(MIME スニッフィング)を止め、
///     アップロード/自由記述欄経由の想定外コンテンツ種別解釈を防ぐ。
///   - X-Frame-Options: DENY
///     本アプリを他サイトの &lt;iframe&gt; に埋め込めなくし、クリックジャッキング
///     (見えないフレーム越しに認証済みユーザーへ操作を誤クリックさせる攻撃)を防ぐ。
///   - Referrer-Policy: strict-origin-when-cross-origin
///     他サイトへ遷移する際に、インシデント ID 等を含みうる完全な URL パスを
///     Referer ヘッダーで漏らさないようにする(オリジンのみ許可)。
///
/// Content-Security-Policy は意図的に付与しない: 本アプリは Views/Home/Index.cshtml の
/// ダッシュボード用データ埋め込みや Shared/_Layout.cshtml のテーマ復元スクリプトなど、
/// nonce を持たないインライン &lt;script&gt; を複数箇所で使用しており、'unsafe-inline' なしの
/// CSP を安全に適用するには大掛かりなリファクタが必要になる(このミドルウェアの最小スコープを
/// 超えるため別 PR で扱う)。
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    // パイプラインの次のミドルウェアを呼び出すためのデリゲート
    private readonly RequestDelegate _next;

    // コンストラクタ: ASP.NET Core のミドルウェアパイプライン構築時に自動注入される
    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        // 次のミドルウェアを保持しておく
        _next = next;
    }

    // 各リクエストで呼ばれる本処理
    public Task InvokeAsync(HttpContext context)
    {
        // このミドルウェアは Program.cs でパイプラインの先頭付近(UseExceptionHandler より後、
        // UseStaticFiles/UseRouting より前)に登録される。例外発生時は ExceptionHandlerMiddleware が
        // レスポンスをクリアしてこのミドルウェアより後段のパイプラインを再実行するため、
        // エラーページの応答時にもこのメソッドが再度呼ばれてヘッダーが付与される。
        // まだ何も書き込まれていない(HasStarted=false)このタイミングで直接設定してよい。
        // MIME スニッフィング防止(想定外の Content-Type 解釈を止める)
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        // クリックジャッキング防止(他サイトの iframe への埋め込みを禁止)
        context.Response.Headers["X-Frame-Options"] = "DENY";
        // クロスオリジン遷移時に URL パス(インシデント ID 等を含みうる)を漏らさない
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // パイプラインの次の処理へ進む
        return _next(context);
    }
}
