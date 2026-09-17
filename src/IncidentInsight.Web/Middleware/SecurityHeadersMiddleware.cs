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
///   - Cache-Control: no-store(動的な応答だけ。判定は <see cref="ShouldPreventCaching"/>)
///     画面・JSON はインシデント本文・報告者氏名・監査証跡といった PHI を含む。
///     指示が無いと共有キャッシュもブラウザも<b>ヒューリスティックに保存してよい</b>ため、
///     共用端末の戻るボタンやディスクキャッシュからログアウト後に PHI が読めてしまう
///     (§9「機密情報・PII をログやエラー応答に漏らさない」と同じ趣旨をキャッシュへ広げる)。
///
/// <para><b>キャッシュ抑止を足した理由(実測)。</b> これを入れる前の状態を実際に配備して測ると、
/// 画面の大半には <c>Cache-Control: no-cache, no-store</c> が<b>既に付いていた</b> ——
/// ただしそれはアンチフォージェリ(<c>DefaultAntiforgery</c>)がトークンを描画した応答へ
/// 自分で書き込むからで、共通レイアウトのログアウト用 POST フォームがそれを踏んでいた。
/// つまり<b>保護がページの内容に依存していた</b>: 実測では
/// <c>/Account/AccessDenied</c>(フォームを持たない読み取り専用の画面)と
/// <c>/Analytics/*</c> の JSON(部署別・原因分類別の件数)には<b>キャッシュ指示が 1 つも無かった</b>。
/// フォームを持たない参照画面や JSON を足すたびに黙って保護が外れる形(fail-open)なので、
/// パイプラインの性質として既定値を入れる。挙動は
/// <c>ResponseCacheHeaderIntegrationTests</c> がこの 2 経路で固定する
/// (フォームのある画面で検証すると、このミドルウェアを外しても緑のまま通る)。</para>
///
/// <para><b>キャッシュ抑止だけ付け方が違う理由。</b> 他の 3 つは値が応答内容に依存しないので
/// <c>_next</c> の前にそのまま設定できる。一方キャッシュ抑止は「その応答が動的か」で決めるため、
/// 判断材料の <c>Content-Type</c> が確定する<b>応答開始の直前</b>(<c>OnStarting</c>)まで待つ。
/// 先に設定してしまうと静的アセット(css/js/画像)まで <c>no-store</c> になり、
/// <c>asp-append-version</c> で版付けしたファイルが毎回再取得される(§8 配信の最適化に反する)。</para>
///
/// <para><b>判定は fail-closed(不明なら no-store)。</b> 除外するのは「静的アセットしか名乗らない
/// Content-Type」だけで、それ以外はすべてキャッシュ禁止にする。逆向き(HTML と JSON だけを
/// 禁止する許可リスト)にすると、将来 CSV・PDF のエクスポート —— つまり<b>いちばん
/// キャッシュされたくない PHI の塊</b> —— を足した人が何もしなくても素通りする。
/// 除外表の取りこぼしは「キャッシュが効かない」(§8 の性能)で済み、
/// 取りこぼしても PHI が漏れる側には倒れない。</para>
///
/// <para><b>すでに Cache-Control が設定されている応答は触らない。</b>
/// <c>HomeController.Error</c> の <c>[ResponseCache]</c> やヘルスチェックの
/// <c>MapHealthChecks</c> は自分でキャッシュ指示を書き込む。上書きすると
/// 「アクションに明示した意図」より既定値が勝ってしまうため、既定値はあくまで
/// <b>誰も指示しなかったときだけ</b>入れる。</para>
///
/// Content-Security-Policy は意図的に付与しない: 本アプリはまだ nonce を持たないインライン
/// &lt;script&gt; を使用している画面が残っており、'unsafe-inline' なしの CSP を安全に適用するには
/// 大掛かりなリファクタが必要になる(このミドルウェアの最小スコープを超えるため別 PR で扱う)。
/// 残っているインライン &lt;script&gt;(2026-08 時点):
///   - Shared/_Layout.cshtml のテーマ復元スクリプト(CSS 適用前に走る必要があり外部化しにくい)
///   - Incidents/Create.cshtml の対策行の追加・削除・添字振り直し
///   - Incidents/Details.cshtml
/// なお Home/Index.cshtml と Analytics/Index.cshtml は
/// 「&lt;script type="application/json"&gt; のデータ島 + 外部 js(Scripts/*.ts のコンパイル結果)」構成へ
/// 移行済みで、実行されるインライン &lt;script&gt; は持たない(データ島は実行されないため CSP の対象外)。
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    /// <summary>
    /// 動的な応答へ付けるキャッシュ抑止の指示。
    /// </summary>
    /// <remarks>
    /// <c>no-cache</c> / <c>Pragma</c> / <c>Expires</c> を併記しないのは、HTTP/1.1 のキャッシュには
    /// <c>no-store</c> だけで「保存するな」が伝わり(RFC 9111)、併記しても意味が増えないため。
    /// 既に <c>[ResponseCache]</c> が <c>no-store,no-cache</c> を書いている応答はそのまま残すので、
    /// 値をそろえるために既存の書き込みを上書きしたりはしない(上のクラス解説を参照)。
    /// </remarks>
    public const string NoStoreCacheControl = "no-store";

    /// <summary>
    /// キャッシュ抑止の対象から外す Content-Type(前方一致・大文字小文字は無視)。
    /// </summary>
    /// <remarks>
    /// <b>ここに載せてよいのは「静的アセットしか名乗らない種別」だけ。</b>
    /// 版付き URL(<c>asp-append-version</c>)で配信され、内容に PHI を含みえないものに限る。
    /// <c>application/octet-stream</c> のような汎用の種別を載せてはいけない ——
    /// 将来のファイルダウンロード(PHI を含む書き出し)が同じ種別を名乗るため、
    /// 載せた瞬間にいちばん守りたい応答が除外側へ回る。
    /// </remarks>
    private static readonly string[] StaticAssetContentTypePrefixes =
    {
        // スタイルシート(wwwroot/css/site.css / lib 配下の css)
        "text/css",
        // スクリプト(wwwroot/js は Scripts/*.ts のコンパイル結果、lib 配下は jQuery 等)
        "text/javascript",
        // 上と同じスクリプトを別表記で返す環境向け(拡張子 → 種別の対応は実行環境に依存する)
        "application/javascript",
        // 画像全般(favicon / ドキュメント用のスクリーンショット等)
        "image/",
        // 自己ホストする Web フォント(現在は Google Fonts から読むが将来の同梱に備える)
        "font/",
    };

    // パイプラインの次のミドルウェアを呼び出すためのデリゲート
    private readonly RequestDelegate _next;

    // コンストラクタ: ASP.NET Core のミドルウェアパイプライン構築時に自動注入される
    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        // 次のミドルウェアを保持しておく
        _next = next;
    }

    /// <summary>
    /// その応答にキャッシュ抑止(<see cref="NoStoreCacheControl"/>)を付けるべきかを決める。
    /// </summary>
    /// <remarks>
    /// <b>判定を純粋関数として公開している理由。</b> 実際に呼ばれるのは応答開始直前の
    /// <c>OnStarting</c> コールバックの中で、そのコールバックは <c>DefaultHttpContext</c> の
    /// 既定の応答フィーチャーでは<b>そもそも発火しない</b>(既定実装が空)。
    /// 判定をここに出しておかないと、境界(種別の大文字小文字・charset 付き・既存指示あり)を
    /// 単体テストで固定できず、実 HTTP を起動する統合テスト 1 本だけが頼りになる。
    /// 配線が効いていること自体は統合テスト(<c>ResponseCacheHeaderIntegrationTests</c>)が見る。
    /// </remarks>
    /// <param name="contentType">応答の <c>Content-Type</c>(未設定なら <c>null</c>)。</param>
    /// <param name="existingCacheControl">
    /// すでに書き込まれている <c>Cache-Control</c>(無ければ <c>null</c> か空文字)。
    /// </param>
    /// <returns>キャッシュ抑止を付けるなら <c>true</c>。</returns>
    public static bool ShouldPreventCaching(string? contentType, string? existingCacheControl)
    {
        // 誰かが明示的にキャッシュ指示を書いているなら、その意図を尊重して触らない
        if (!string.IsNullOrWhiteSpace(existingCacheControl))
            return false;

        // Content-Type が無い応答(302 リダイレクト・204 など本文を持たないもの)は
        // 保存される中身が無いので何もしない。キャッシュの有無で PHI が漏れることもない
        if (string.IsNullOrWhiteSpace(contentType))
            return false;

        // 静的アセットしか名乗らない種別を除外する(それ以外は動的扱い = 抑止する)
        foreach (var prefix in StaticAssetContentTypePrefixes)
        {
            // "text/css; charset=utf-8" のようにパラメータが付く形も拾えるよう前方一致で比べる
            if (contentType.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        // 除外に当たらなかった応答は動的(画面・JSON・将来のエクスポート)として抑止する
        return true;
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

        // キャッシュ抑止だけは応答開始の直前まで待って決める(Content-Type が要るため)。
        // 登録は _next より前に行う: 後段のミドルウェアが応答を開始し切ってしまってから
        // 登録しようとしても手遅れになる。コールバックは後入れ先出しで走るので、
        // ここで登録したものは最後に動き、内側が書いた Cache-Control を上書きしない
        context.Response.OnStarting(() =>
        {
            // このリクエストの応答オブジェクトを取り出す
            var response = context.Response;
            // 動的な応答で、まだ誰もキャッシュ指示を書いていないときだけ既定値を入れる
            if (ShouldPreventCaching(response.ContentType, response.Headers.CacheControl.ToString()))
            {
                // 共有キャッシュ・ブラウザの双方に「保存するな」を伝える
                response.Headers.CacheControl = NoStoreCacheControl;
            }
            // OnStarting は Task を返す契約なので、同期処理だけのこのコールバックは完了済みを返す
            return Task.CompletedTask;
        });

        // パイプラインの次の処理へ進む
        return _next(context);
    }
}
