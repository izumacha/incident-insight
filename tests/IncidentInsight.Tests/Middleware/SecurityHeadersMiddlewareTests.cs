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
        var securityDoc = ReadSecurityDoc();

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

    // 付けてはいけない指示の綴り。
    // <b>2 つの走査が同じ綴りを見ていることを、構造で保証するために定数にしてある</b> ——
    // 囲みのある名乗り（指示ごとの完全一致）と、囲みの無い地の文（カンマ隣接）で
    // 見る形が違うので、綴りを書き写すと片方だけを直した変更が素通りの窓口になる（§6 DRY）
    private const string ForbiddenDirective = "immutable";

    // キャッシュ期間の上限（1 日）。版付きでない lib/ の更新が利用者へ届くまでの最長時間。
    // <b>定数にしてあるのは、見る対象が 2 つあるから</b>（定数側の検査と、文書の走査）
    private const long MaxCacheLifetimeSeconds = 24 * 60 * 60;

    // 囲みの無い地の文から期間の指示を拾う綴り。
    // <b>名前は MaxAgeFamilyPrefixes から導く</b>（末尾の "=" を外して並べる）——
    // 書き下すと、定数へ指示を足したときにこちらだけが古くなる
    private static readonly string LifetimeDirectivePattern =
        $"(?<name>{string.Join('|', MaxAgeFamilyPrefixes.Select(p => Regex.Escape(p.TrimEnd('='))))})"
        + @"\s*=\s*(?<seconds>\d+)";

    [Fact]
    public void StaticAssetCacheControl_StaysShortLivedAndRevalidatable()
    {
        // 定数を解析して、指示ごとの値を取り出す
        var directives = SplitDirectives(SecurityHeadersMiddleware.StaticAssetCacheControl);

        // 期間の指示を取り出す
        var lifetimeDirectives = LifetimeDirectives(directives);

        // 期間の指示が 1 つも無ければ、キャッシュ期間の意図が読めないので落とす。
        // <b>これは静的アセットの定数にだけ求める</b> ——no-store のように
        // 期間を持たない指示は正当なので、下の文書全体の検査では求めない
        Assert.NotEmpty(lifetimeDirectives);

        // 長期・immutable でないことを確かめる（規則の本体は共有のヘルパーが持つ）
        AssertNotLongLived(directives, "SecurityHeadersMiddleware.StaticAssetCacheControl");
    }

    // <b>文書が名乗るキャッシュ指示は、1 つ残らず同じ不変条件を満たすこと。</b>
    //
    // 上の 2 つは「静的アセットの箇条書き 1 つ」と「定数そのもの」しか見ないので、
    // <b>別の箇条書きが長期・immutable を名乗っても止められない</b> ——実測で、
    // OnPrepareResponse という語を含まない囮の箇条書き
    // （"/attachments 配信は public,max-age=31536000,immutable を名乗ります"）を
    // 手前へ足すと 1168 件すべて緑のまま通った。目印を持たないので切り出しの件数も
    // 変わらず、本命の文も定数も動いていないためどの検査にも掛からない。
    // つまり issue #265 で塞いだ穴が「目印を持つ囮」から「目印を持たない囮」へ
    // 移っただけだった（レビュー指摘）。
    //
    // <b>運用者が読むのは文書全体</b>なので、どの箇条書きであれ
    // 「長期・immutable を名乗る」記述が載っていること自体が守りたい状態に反する。
    [Fact]
    public void EveryDocumentedCacheDirective_IsNeverLongLived()
    {
        // 運用者向けドキュメントを読む
        var securityDoc = ReadSecurityDoc();

        // 具体的な値を伴うキャッシュ指示を<b>すべて</b>取り出す。
        // 「を名乗」等の言い回しで絞らない ——絞ると、言い回しを変えた囮が素通りする
        var documented = Regex.Matches(securityDoc, @"`Cache-Control:\s*(?<value>[^`]+)`");

        // 1 つも読み取れないのは、書き方が変わったか検査が壊れたか ——どちらも落とす
        Assert.NotEmpty(documented);

        // 1 件ずつ確かめる
        foreach (Match match in documented)
        {
            // その指示を分解する
            var directives = SplitDirectives(match.Groups["value"].Value.Trim());

            // 長期・immutable でないこと（期間を持たない no-store 等はそのまま通る）
            AssertNotLongLived(directives, $"docs/security.md の `{match.Value}`");
        }

        // <b>整った書き方だけを見ていては足りない（レビュー指摘）。</b> 上の走査は
        // バッククォートで囲まれた指示しか拾わないので、囲まずに書いた囮
        // （"添付ファイル配信は public,max-age=31536000,immutable を名乗ります。"）は
        // 素通りする ——実測で 10 件すべて緑のまま通った。守りたいのは
        // 「文書が長期・immutable を名乗らないこと」であって、<b>書式ではない</b>。
        //
        // そこで<b>禁じている綴りそのもの</b>を、囲みの有無を問わず走査する。
        // 期間の値は、囲まれていてもいなくても同じ形で現れる
        // <b>指示の名前は MaxAgeFamilyPrefixes から導く（レビュー指摘）。</b> ここへ
        // 書き下すと、定数へ 5 つ目を足した人が<b>囲みのある名乗りでは拾えるのに
        // 囲みの無い地の文では拾えない</b>状態を作る（実測で、"surrogate-control=" を
        // 足して囲みなしで名乗らせると 10 件すべて緑のまま通った）——
        // 「規則を 2 度書くと片方が素通りの窓口になる」形そのもの
        foreach (Match lifetime in Regex.Matches(securityDoc, LifetimeDirectivePattern, RegexOptions.IgnoreCase))
        {
            // 秒数として読み取る。<b>int ではなく long で受ける（レビュー指摘）。</b>
            // 走査が当たるのは数字だけだが、桁数までは保証していないので
            // int だと OverflowException になり、失敗文言が案内ではなく生の例外になる
            // ——定数側（TryParse ＋ 明示の失敗文言）と挙動をそろえる
            Assert.True(
                long.TryParse(lifetime.Groups["seconds"].Value, out var seconds),
                $"docs/security.md のキャッシュ期間を秒数として読み取れません: {lifetime.Value}");

            // 上限は定数側と同じ 1 日（規則の値を 2 か所へ書き写さないため定数を使う）
            Assert.True(
                seconds <= MaxCacheLifetimeSeconds,
                $"docs/security.md が長すぎるキャッシュ期間を載せています({lifetime.Value})。"
                    + "囲みの有無にかかわらず、文書は長期のキャッシュ指示を名乗りません"
                    + "(wwwroot/lib 配下は版を付けずに参照されているため)。");
        }

        // immutable が<b>指示の並びの一部として</b>現れていないこと。
        //
        // <b>語そのものを禁じてはいけない。</b> この文書は「長期・`immutable` にはしません」と
        // 説明のために正しく使っており、一律に禁じると<b>正しい記述で赤くなる</b>
        // （そういう検出網はいずれ緩められる）。
        //
        // <b>空白を挟まないカンマ隣接だけを見る（レビュー指摘）。</b> 以前は空白も
        // 許していたため、「public, immutable などの指示は…」という<b>散文の列挙</b>でも
        // 赤くなった ——直そうとしている失敗モードを自分で踏んでいた。
        // 指示の値は空白を挟まずに書かれる（"public,max-age=3600"）ので、
        // 隣接だけに絞れば実際の名乗りは拾え、散文は巻き込まない。
        //
        // <b>残っている境界</b>: "public, immutable" と空白付きで名乗る囮は拾えない。
        // ただし immutable は<b>単体では効かない</b>（RFC 8246。新鮮さの指示を
        // 修飾するものなので、害のある名乗りには必ず max-age 系が伴う）ため、
        // その場合は上の期間の走査が囲みの有無を問わず拾う。
        Assert.False(
            Regex.IsMatch(
                securityDoc,
                // 綴りは定数から組み立てる（上の完全一致の検査と同じものを見る）
                $"[A-Za-z0-9-],{Regex.Escape(ForbiddenDirective)}|{Regex.Escape(ForbiddenDirective)},[A-Za-z0-9-]",
                RegexOptions.IgnoreCase),
            "docs/security.md が immutable を含むキャッシュ指示を載せています。"
                + "版付きでない wwwroot/lib 配下を参照しているため、immutable を名乗ると"
                + "脆弱性修正後も古いファイルを消す手段が無くなります。");
    }

    /// <summary>キャッシュ指示の文字列を、指示ごとに分ける。</summary>
    /// <param name="cacheControl"><c>Cache-Control</c> の値。</param>
    /// <returns>前後の空白を落とした指示の一覧。</returns>
    private static List<string> SplitDirectives(string cacheControl) =>
        // カンマ区切りの各指示へ分ける
        [.. cacheControl.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    /// <summary>保存できる時間を延ばす向きに効く指示だけを取り出す。</summary>
    /// <param name="directives">分解済みの指示。</param>
    /// <returns>期間を表す指示の一覧。</returns>
    private static List<string> LifetimeDirectives(IEnumerable<string> directives) =>
        // 接頭辞の一覧に当たるものだけを残す
        [.. directives.Where(d => MaxAgeFamilyPrefixes.Any(p => d.StartsWith(p, StringComparison.OrdinalIgnoreCase)))];

    /// <summary>
    /// その指示が「長期でも immutable でもない」ことを確かめる。
    /// </summary>
    /// <remarks>
    /// <b>規則の本体を 1 か所に置くのは、見る対象が 2 つあるから</b>（定数そのものと、
    /// 文書が名乗るすべての指示）。書き写すと片方にだけ上限を足す変更が通り、
    /// そのとき<b>もう片方が素通りの窓口になる</b>（§6 DRY）。
    /// </remarks>
    /// <param name="directives">分解済みの指示。</param>
    /// <param name="source">失敗文言に出す出所（どこの指示の話かを示す）。</param>
    private static void AssertNotLongLived(IReadOnlyList<string> directives, string source)
    {
        // immutable を付けていないこと(付けると再取得の手段が無くなる)
        Assert.DoesNotContain(
            directives,
            d => d.Equals(ForbiddenDirective, StringComparison.OrdinalIgnoreCase));

        // 保存できる時間を表す指示を<b>すべて</b>取り出す。
        // <b>max-age だけを見てはいけない</b>: s-maxage は共有キャッシュに対して max-age を
        // 上書きするので、"public,s-maxage=31536000,max-age=3600" と書けば
        // プロキシは 1 年保存するのに max-age だけを見る検査は 3600 しか見ない
        // (実測でこの形が全件緑のまま通った)。stale-* も配信を延ばす向きに効く
        foreach (var directive in LifetimeDirectives(directives))
        {
            // 値の部分(= の後ろ)を取り出す
            var value = directive[(directive.IndexOf('=') + 1)..];
            // 秒数として読めること(読めない綴りを「上限内」と扱わない ——fail-closed)。
            // <b>long で受ける（レビュー指摘）。</b> int だと 1 桁多い値で TryParse が
            // false になり、「長すぎます」ではなく「読み取れません」と案内してしまう ——
            // 実際には読める値なので、直す人を誤った方向へ送る
            Assert.True(
                long.TryParse(value, out var seconds),
                $"キャッシュ期間の値を秒数として読み取れません: {directive}（{source}）");

            // 上限は 1 日。版付きでない lib/ の更新が利用者へ届くまでの最長時間がこの値になる。
            // 引き上げたいときは、まず lib/ 配下も版付き URL で参照する形へ変えること
            Assert.True(
                seconds <= MaxCacheLifetimeSeconds,
                $"キャッシュ期間が長すぎます({directive}／{source})。"
                    + "wwwroot/lib 配下は版を付けずに参照されているため、長くすると"
                    + "ライブラリの脆弱性修正後も古いファイルが利用者のキャッシュに残り続けます。"
                    + "どうしても延ばすなら、lib/ を版付き URL で参照する形へ変えたうえで、"
                    + "docs/security.md の記載も同じ変更セットで直してください。");
        }
    }


    /// <summary>運用者向けのセキュリティ文書を読む。</summary>
    /// <remarks>
    /// <b>読み取りを 1 か所に寄せてある（レビュー指摘）。</b> パスを 2 か所へ書き写すと、
    /// 文書を改名・分割したときに片方だけが直り、もう片方は見つからないか
    /// <b>古いファイルを読み続ける</b>（§6「パスは名前付き定数にし単一の参照元に置く」）。
    /// </remarks>
    /// <returns>文書全体。</returns>
    private static string ReadSecurityDoc() =>
        // リポジトリ直下からの相対位置で読む
        // 何段の相対パスでもそのまま読めるよう、要素を展開して組み立てる ——
        // 位置で取り出すと、段数が増えたときに<b>定数だけが直って読み手が取り残される</b>
        // （この関数の存在理由そのものと矛盾する）
        File.ReadAllText(Path.Combine([RepositoryPaths.Root, .. SecurityDocRelativePath]));

    /// <summary>セキュリティ文書のリポジトリ内での位置。</summary>
    private static readonly string[] SecurityDocRelativePath = ["docs", "security.md"];

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
