// テスト対象のミドルウェアを使う
using IncidentInsight.Web.Middleware;
// HttpContext のテスト用実装(DefaultHttpContext)を使う
using Microsoft.AspNetCore.Http;
// 応答フィーチャー(IHttpResponseFeature / HttpResponseFeature)を差し替えるために使う
using Microsoft.AspNetCore.Http.Features;
// リポジトリのパス(docs/security.md を読むため)を使う
using IncidentInsight.Tests.Helpers;
// ドキュメントから指示を取り出すために使う
using System.Text.RegularExpressions;

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

    // 静的アセット用の指示が、docstring と docs/security.md が述べている内容と実際に一致すること。
    //
    // <b>なぜ要るのか。</b> 統合テストは「配信された値が定数と一致するか」しか見ないので、
    // <b>定数の値そのものに対しては恒真</b>になる ——実測でも、定数を
    // "public,max-age=31536000,immutable" や "private,max-age=1800" に書き換えると
    // 897 件すべて緑のまま通った。ところが定数には文章で約束した内容がある:
    //   (a) SecurityHeadersMiddleware の docstring —— 期間を短く保ち immutable を付けない。
    //       _Layout.cshtml と _ValidationScriptsPartial.cshtml が wwwroot/lib 配下を
    //       asp-append-version なしで参照しているため、長期・immutable にすると
    //       脆弱性修正後も古いファイルが利用者のキャッシュに残り、消す手段が無くなる。
    //   (b) docs/security.md —— 運用者へ「この指示を名乗る」と具体的な値で説明している。
    //
    // <b>上限を手で書き写さない。</b> 「1 時間以下」とテストに書く形も試したが、それは
    // docs/security.md の値の写しでしかなく、private へ狭める・public を落とすといった
    // 変更を 1 つも捕まえられなかった(実測)。<b>文書から読み取って突き合わせる</b>ことで、
    // 定数か文書のどちらかだけを動かす差分が必ず落ちる。
    [Fact]
    public void StaticAssetCacheControl_MatchesTheDocumentedDirective()
    {
        // 運用者向けドキュメントを読む
        var securityDoc = File.ReadAllText(Path.Combine(RepositoryPaths.Root, "docs", "security.md"));

        // <b>静的アセットを説明している箇条書きだけを切り出してから読む(issue #265)。</b>
        // ドキュメント全体を対象にすると、キャッシュ指示を述べた文が<b>すでに 2 つ</b>ある
        // (既定の no-store と、静的アセットの public,max-age=3600)。
        var bullet = StaticAssetCachingBullet(securityDoc);

        // その箇条書きが名乗ると説明している指示を<b>すべて</b>取り出す(`Cache-Control: <値>` の形)
        var documented = Regex.Matches(bullet, @"`Cache-Control:\s*(?<value>[^`]+)`\s*を名乗");

        // <b>ちょうど 1 件であること。</b> 最初の一致で済ませると、次の 2 方向どちらにも壊れる:
        //   (a) 同じ形の文が手前に増えると、そちらを拾って比較が失敗する ——
        //       <b>何も壊れていないのに赤くなる</b>ので、いずれ検査ごと緩められる。
        //   (b) 先に当たる文の値がたまたま定数と同じなら、<b>本命の文が誰にも照合されないまま
        //       drift する</b>(検査が無いのと同じ)。
        // (a) は上の切り出しが防ぐ。(b) は「どの文を守るのか決まっていない」ことが原因なので、
        // 件数を固定して決められない状態そのものを落とす(fail-closed)
        Assert.True(
            documented.Count == 1,
            // 失敗文言が「何件見つかったか」と「次に何をすればよいか」を示す
            $"docs/security.md の静的アセットの箇条書きから Cache-Control を"
                + $"ちょうど 1 件読み取れませんでした(見つかった件数: {documented.Count})。"
                + "0 件なら書き方を変えた側と同じ変更セットでこの照合も直してください"
                + "(読めないまま緑にすると、文書と実装のずれが誰にも見えなくなります)。"
                + "2 件以上なら、どの文を守るのかを決めて読む範囲をさらに絞ってください"
                + "(最初の一致で済ませると、守るべき記述が黙って入れ替わります)。");

        // ドキュメントの値と定数が一字一句一致すること
        // (期待値は定数、実測値はドキュメント側。失敗文言が「文書が何を名乗っているか」を示す)
        Assert.Equal(
            SecurityHeadersMiddleware.StaticAssetCacheControl,
            documented[0].Groups["value"].Value.Trim());
    }

    // 静的アセットへキャッシュ指示を名乗らせている仕組みの名前。
    //
    // <b>切り出しの目印を「文言」ではなく「コードの識別子」にしてある。</b> 見出しや
    // 「静的アセット」といった日本語を目印にすると、文章を整えただけで切り出しが外れる
    // (そのとき 0 件になって落ちるので気づけはするが、赤くなる理由が毎回ドキュメントの
    // 言い回しになり、検査そのものが煩わしがられる)。OnPrepareResponse は
    // Program.cs 側の実体そのもので、この 2 つは対で動く(CLAUDE.md が明記している)。
    private const string StaticAssetCachingMechanism = "OnPrepareResponse";

    /// <summary>
    /// <c>docs/security.md</c> から、静的アセットのキャッシュ指示を説明している箇条書きを切り出す。
    /// </summary>
    /// <remarks>
    /// <b>見つからなければ落とす(fail-closed)。</b> 切り出せないまま全体を返すと、
    /// 呼び出し側の「ちょうど 1 件」が<b>別の文</b>に当たって緑になりうる ——
    /// それは守るべき記述が入れ替わった状態そのもの(issue #265)。
    /// </remarks>
    /// <param name="doc">ドキュメント全体。</param>
    /// <returns>仕組みを説明している箇条書き 1 つ分の文字列。</returns>
    private static string StaticAssetCachingBullet(string doc)
    {
        // 行単位で見る(箇条書きの境目は行頭の "- " で決まる)
        var lines = doc.Split('\n');

        // 仕組みの名前が書かれている行を<b>すべて</b>探す。
        //
        // <b>ここで「最初の 1 件」を採ってはいけない(レビュー指摘)。</b> それをやると、
        // 塞いだはずの穴が<b>1 段上（切り出しの側）へそのまま移る</b> ——実測で、
        // 2 つ目の配信ルート(CLAUDE.md が現実的な例として挙げている /attachments 用の
        // UseStaticFiles)を説明する箇条書きを手前へ足し、同時に本命の文を
        // public,max-age=31536000,immutable へ書き換えると、切り出しが囮の箇条書きへ
        // 当たって「ちょうど 1 件」も値の一致も成立し、<b>1157 件すべて緑のまま通った</b>。
        // そのとき docs/security.md は、この 2 本の検査が守っているはずの不変条件
        // （長期にしない・immutable を付けない）と正面から矛盾する内容を名乗っていた。
        var anchors = lines
            // 仕組みの名前を含む行の位置だけを残す
            .Select((line, index) => (Line: line, Index: index))
            .Where(entry => entry.Line.Contains(StaticAssetCachingMechanism, StringComparison.Ordinal))
            .ToList();

        // ちょうど 1 件であること ——0 件なら目印が読めておらず、2 件以上ならどの箇条書きを
        // 守るのか決められない。どちらも「守るべき記述が分からない」状態なので落とす(fail-closed)
        Assert.True(
            anchors.Count == 1,
            $"docs/security.md に {StaticAssetCachingMechanism} の説明がちょうど 1 件ありませんでした"
                + $"(見つかった件数: {anchors.Count})。"
                + "静的アセットのキャッシュ指示を説明している箇所の目印なので、"
                + "0 件なら書き方を変えた側と同じ変更セットでこの切り出しも直してください。"
                + "2 件以上（配信ルートが増えた等）なら、どの箇条書きを守るのかを決めて"
                + "目印をより細かくしてください"
                + "(最初の一致で済ませると、守るべき記述が黙って入れ替わります)。");

        // ちょうど 1 件と分かったので、その行の位置を取り出す
        var anchor = anchors[0].Index;

        // その行から上へたどって、その箇条書きの先頭(行頭の "- ")を見つける
        var start = anchor;
        // 先頭に当たるまで 1 行ずつ戻る
        while (start >= 0 && !lines[start].StartsWith("- ", StringComparison.Ordinal)) start--;
        // 箇条書きの中に無い(＝地の文に書かれている)なら、範囲を決められないので落とす
        Assert.True(
            start >= 0,
            $"docs/security.md の {StaticAssetCachingMechanism} の説明が箇条書きの中にありません。"
                + "切り出しは行頭の \"- \" を境目にしているので、書き方を変えたなら"
                + "この切り出しも同じ変更セットで直してください。");

        // 次の箇条書きの手前(または文書の末尾)までがこの箇条書き
        var end = start + 1;
        // 次の "- " に当たるまで 1 行ずつ進む
        while (end < lines.Length && !lines[end].StartsWith("- ", StringComparison.Ordinal)) end++;

        // 切り出した範囲を 1 本の文字列に戻して返す
        return string.Join('\n', lines[start..end]);
    }

    // 定数が、docstring の述べている不変条件(短い期間・immutable なし)を満たしていること。
    //
    // 上の照合は「定数と文書が一致すること」しか見ないので、<b>両方を同時に</b>
    // 長期・immutable へ書き換える差分は通ってしまう。ここは文書と独立に、
    // 値そのものの性質を見る(手がかりを変えるのが要点)。
    // 保存できる時間を延ばす向きに効く指示の接頭辞。
    // max-age だけを見ると、共有キャッシュへは s-maxage が優先されるため素通りする
    private static readonly string[] MaxAgeFamilyPrefixes =
        ["max-age=", "s-maxage=", "stale-while-revalidate=", "stale-if-error="];

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

        // 保存できる時間を表す指示を<b>すべて</b>取り出す。
        // <b>max-age だけを見てはいけない</b>: s-maxage は共有キャッシュに対して max-age を
        // 上書きするので、"public,s-maxage=31536000,max-age=3600" と書けば
        // プロキシは 1 年保存するのに max-age だけを見る検査は 3600 しか見ない
        // (実測でこの形が全件緑のまま通った)。stale-* も配信を延ばす向きに効く
        var lifetimeDirectives = directives
            .Where(d => MaxAgeFamilyPrefixes.Any(p => d.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        // 期間の指示が 1 つも無ければ、キャッシュ期間の意図が読めないので落とす
        Assert.NotEmpty(lifetimeDirectives);

        // 取り出した指示を 1 つずつ確かめる
        foreach (var directive in lifetimeDirectives)
        {
            // 値の部分(= の後ろ)を取り出す
            var value = directive[(directive.IndexOf('=') + 1)..];
            // 秒数として読めること(読めない綴りを「上限内」と扱わない ——fail-closed)
            Assert.True(
                int.TryParse(value, out var seconds),
                $"キャッシュ期間の値を秒数として読み取れません: {directive}");

            // 上限は 1 日。版付きでない lib/ の更新が利用者へ届くまでの最長時間がこの値になる。
            // 引き上げたいときは、まず lib/ 配下も版付き URL で参照する形へ変えること
            Assert.True(
                seconds <= 24 * 60 * 60,
                $"静的アセットのキャッシュ期間が長すぎます({directive})。"
                    + "wwwroot/lib 配下は版を付けずに参照されているため、長くすると"
                    + "ライブラリの脆弱性修正後も古いファイルが利用者のキャッシュに残り続けます。"
                    + "どうしても延ばすなら、lib/ を版付き URL で参照する形へ変えたうえで、"
                    + "docs/security.md の記載も同じ変更セットで直してください。");
        }
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
