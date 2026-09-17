// ASP.NET Core のミドルウェア基盤(HttpContext / RequestDelegate)を使う
using Microsoft.AspNetCore.Http;
// ヘッダー値が空かどうかの判定(StringValues.IsNullOrEmpty)に使う
using Microsoft.Extensions.Primitives;

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
///   - Cache-Control: no-store(<b>誰もキャッシュ指示を書かなかった応答だけ</b>)
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
/// <para><b>規則は 1 つだけ: 誰も指示していなければ <c>no-store</c>。</b>
/// 応答の種類で振り分けない ——「HTML と JSON だけ」のような許可リストにすると、
/// 将来 CSV・PDF・添付画像のエクスポート(いちばんキャッシュされたくない PHI の塊)を
/// 足した人が何もしなくても素通りする。逆に「静的アセットの Content-Type だけ除外する」
/// 形も採らない: 除外表がフレームワークの拡張子→種別の対応表を写す必要があり、
/// 実測すると <c>.woff</c> は <c>application/font-woff</c>、<c>.ttf</c> は
/// <c>application/x-font-ttf</c> で <c>font/</c> に一致しない一方、
/// <c>image/</c> のような広い前置詞は将来の添付画像(PHI)まで除外側へ回してしまう。
/// <b>静的アセットは「自分のキャッシュ指示を自分で名乗る」ことで対象から外れる</b> ——
/// <c>Program.cs</c> の <c>UseStaticFiles</c> が <see cref="StaticAssetCacheControl"/> を
/// 書き込むので、下の「既に指示がある応答は触らない」判定がそのまま効く。
/// これで維持するのは「静的/動的の区別が実際にある場所」1 か所だけになる。</para>
///
/// <para><b>付け方だけ他の 3 つと違う。</b> 他は値が応答内容に依存しないので <c>_next</c> の前に
/// そのまま設定できるが、キャッシュ抑止は「誰かが書いたか」で決めるため、書き込みが終わる
/// <b>応答開始の直前</b>(<c>OnStarting</c>)まで待つ。コールバックは後入れ先出しで走るので、
/// ここで登録したものは最後に動き、内側が書いた指示を上書きしない。</para>
///
/// <para><b>すでに Cache-Control が設定されている応答は触らない。</b>
/// <c>HomeController.Error</c> の <c>[ResponseCache]</c>、ヘルスチェックの
/// <c>MapHealthChecks</c>、アンチフォージェリ、静的ファイル配信はいずれも自分で指示を書く。
/// 上書きすると「明示した意図」より既定値が勝ってしまうため、既定値はあくまで
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
    /// 誰もキャッシュ指示を書かなかった応答へ入れる既定値。
    /// </summary>
    /// <remarks>
    /// <c>no-cache</c> / <c>Pragma</c> / <c>Expires</c> を併記しないのは、HTTP/1.1 のキャッシュには
    /// <c>no-store</c> だけで「保存するな」が伝わり(RFC 9111)、併記しても意味が増えないため。
    /// 既に <c>[ResponseCache]</c> が <c>no-store,no-cache</c> を書いている応答はそのまま残すので、
    /// 値をそろえるために既存の書き込みを上書きしたりはしない(上のクラス解説を参照)。
    /// </remarks>
    public const string NoStoreCacheControl = "no-store";

    /// <summary>
    /// 静的アセット(<c>wwwroot</c> 配下)が名乗るキャッシュ指示。<c>Program.cs</c> の
    /// <c>UseStaticFiles</c> が <c>OnPrepareResponse</c> でこの値を書き込む。
    /// </summary>
    /// <remarks>
    /// <para><b>この 2 つの定数は対になっている</b>ので同じ場所に置いている ——
    /// 静的アセットが自分で指示を名乗ることが、上の「誰も指示していなければ <c>no-store</c>」を
    /// 静的ファイルへ及ばせないための唯一の仕組み。片方だけを別の場所へ動かすと、
    /// 次に読む人が「なぜ静的ファイルが <c>no-store</c> にならないのか」を辿れなくなる。</para>
    ///
    /// <para><b>期間を 1 時間に留めて <c>immutable</c> を付けない理由。</b>
    /// <c>site.css</c> / <c>site.js</c> は <c>asp-append-version</c> で版付きの URL になるが、
    /// <c>lib/</c> 配下(jQuery 等)は <c>_Layout.cshtml</c> が版を付けずに参照している。
    /// 長期・<c>immutable</c> にすると、脆弱性修正を含むライブラリ更新後も
    /// 利用者のキャッシュに古いファイルが残り続ける。短い期間なら、
    /// 従来の(<c>Last-Modified</c> からブラウザが勝手に推定していた)保存期間より
    /// 予測可能で、かつ再訪時のキャッシュは効く。
    /// 版付き URL の資産だけを長期キャッシュしたくなったら、版の有無で分ける判断を
    /// そのときに足す(いま先回りで分けると、根拠の無い分岐が増えるだけ。§6)。</para>
    /// </remarks>
    public const string StaticAssetCacheControl = "public,max-age=3600";

    /// <summary>
    /// 応答開始の直前に、キャッシュ指示が無い応答へ既定値を入れるコールバック。
    /// </summary>
    /// <remarks>
    /// リクエストごとにラムダを作らずに済むよう、状態(<see cref="HttpResponse"/>)を引数で
    /// 受け取る形の <c>static</c> なデリゲートとして 1 つだけ作って使い回す
    /// (ASP.NET Core 自身が <c>ExceptionHandlerMiddleware</c> のキャッシュヘッダー処理で
    /// 使っているのと同じ形)。全リクエストが通る経路なので、毎回の割り当てを避ける。
    /// </remarks>
    private static readonly Func<object, Task> ApplyDefaultCacheControl = state =>
    {
        // 状態として渡した応答オブジェクトを取り出す
        var response = (HttpResponse)state;
        // 誰かが明示的にキャッシュ指示を書いているなら、その意図を尊重して触らない
        if (StringValues.IsNullOrEmpty(response.Headers.CacheControl))
        {
            // 共有キャッシュ・ブラウザの双方に「保存するな」を伝える
            response.Headers.CacheControl = NoStoreCacheControl;
        }
        // OnStarting は Task を返す契約なので、同期処理だけのこのコールバックは完了済みを返す
        return Task.CompletedTask;
    };

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

        // キャッシュ抑止の既定値は応答開始の直前に入れる(誰かが書いたかを見るため)。
        // 登録を _next より前に行うのは、後段が応答を開始し切ってからでは手遅れになるため
        context.Response.OnStarting(ApplyDefaultCacheControl, context.Response);

        // パイプラインの次の処理へ進む
        return _next(context);
    }
}
