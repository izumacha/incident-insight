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
        // <b>目印で拾う（言い回しに依存しない）。</b> 以前は「を名乗」という綴りを
        // 手がかりにしていたが、文章を整えるだけで外れる ——文書側に置いた
        // 機械可読な目印なら、書き方を変えても壊れない
        var documented = Regex.Matches(
            bullet, @"`Cache-Control:\s*(?<value>[^`]+)`" + Regex.Escape(ClaimTag));

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
        var anchors = Regex.Matches(doc, Regex.Escape(StaticAssetCachingMechanism))
            // 文字位置だけを残す（行番号ではなく、BulletBounds が受け取れる形）
            .Select(match => match.Index)
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

        // <b>箇条書きの境目は BulletBounds が持つ（レビュー指摘）。</b> 同じ規則を
        // ここへ書き写すと、文書が別の記号の箇条書きへ変わったときに片方だけが直り、
        // もう片方は無関係な範囲を見たまま静かに誤分類する（§6 DRY）
        var (start, end) = MarkdownSource.BulletBounds(doc, anchors[0]);

        // 箇条書きの中にあること（地の文に書かれていると範囲を決められない）
        Assert.True(
            MarkdownSource.IsBulletStart(doc, start),
            $"docs/security.md の {StaticAssetCachingMechanism} の説明が箇条書きの中にありません。"
                + "切り出しは行頭の \"- \" を境目にしているので、書き方を変えたなら"
                + "この切り出しも同じ変更セットで直してください。");

        // 切り出した範囲を返す
        return doc[start..end];
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
    // 書き下すと、定数へ指示を足したときにこちらだけが古くなる。
    //
    // <b>フィールドではなく、その都度組み立てるプロパティにしてある（レビュー指摘）。</b>
    // フィールドにすると同じクラスの静的フィールドの<b>宣言順</b>に依存し、
    // 見た目を整えるだけの並べ替えで MaxAgeFamilyPrefixes がまだ null のまま評価され、
    // クラス全体のテストが「どこが悪いのか分からない TypeInitializationException」で赤くなる
    private static string LifetimeDirectivePattern =>
        // 直前が英数字やハイフンなら別の指示の一部（"surrogate-max-age=" 等）なので拾わない
        @"(?<![A-Za-z0-9-])"
        + $"(?<name>{string.Join('|', MaxAgeFamilyPrefixes.Select(p => Regex.Escape(p.TrimEnd('='))))})"
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

    // <b>文書が名乗るキャッシュ指示は、1 つ残らず長期でも immutable でもないこと。</b>
    //
    // 上の 2 つは「静的アセットの箇条書き 1 つ」と「定数そのもの」しか見ないので、
    // 別の箇条書きが長期・immutable を名乗っても止められない（実測で、
    // 目印を持たない囮を手前へ足すと全件緑のまま通った）。
    // 運用者が読むのは文書全体なので、どの箇条書きであれ
    // 「長期・immutable を名乗る」記述が載っていること自体が守りたい状態に反する。
    //
    // <b>「名乗りか反例か」は文章から推し量らず、文書側の目印で決める。</b>
    // 肯定・否定の綴りから判定する近似は、この PR の中だけで 4 度踏み直し、
    // そのたびに<b>正しい文書で赤くなる</b>か<b>囮が黙って通る</b>かを行き来した。
    //
    // <b>検査は 2 本立てにする（レビュー指摘）。</b>
    //   (a) <b>目印を起点に、その指示の並び全体</b>を確かめる ——
    //       期間の指示だけを渡していたため、同じ並びの immutable が
    //       <b>一度も見られていなかった</b>（実測で、
    //       "public, max-age=3600, immutable" が全件緑で通った）。
    //   (b) <b>キャッシュの指示を書いたら必ず目印を付ける</b>ことを要求する ——
    //       (a) だけだと、目印を付けない囮が最初から視界に入らない。
    [Fact]
    public void EveryDocumentedCacheDirective_IsNeverLongLived()
    {
        // 運用者向けドキュメントを読む
        var securityDoc = ReadSecurityDoc();

        // <b>囲いが閉じていない文書はその場で落とす（fail-closed。レビュー指摘）。</b>
        // 囲いの数が奇数だと、それ以降が丸ごと「ブロックの中」になって
        // <b>目印の要求が黙って外れる</b>。しかも下の空振り検出は囲いより手前の
        // 指示 1 件で満たされてしまうので、この穴を拾えない（実測で全件緑）
        // <b>囲いを 1 つも見ていない状態も落とす（レビュー指摘）。</b> 判定とは
        // <b>独立な手がかり</b>（本文に囲いの綴りがあるか）と突き合わせる ——
        // 実測で、字下げの上限を置いた版はこの文書の囲い（5 桁字下げ）を 1 つも数えられず、
        // ブロックを逃す処理も偶奇の検査も<b>両方とも黙って死んでいた</b>
        Assert.True(
            !securityDoc.Contains("```", StringComparison.Ordinal)
                || MarkdownSource.FenceLineCount(securityDoc) > 0,
            "docs/security.md にコードブロックの綴りがあるのに、囲いの行を 1 つも数えられていません。"
                + "このままだと、設定例を逃す処理も囲いの偶奇の検査も黙って効かなくなります。");

        Assert.True(
            MarkdownSource.FencesAreBalanced(securityDoc),
            "docs/security.md のコードブロックの囲い（```）が閉じていません。"
                + "閉じないままだと、それ以降のキャッシュ指示がすべて"
                + "「設定例の中」と見なされ、黙って検査から外れます。");

        // (a) 実際に確かめた指示の並びを控えておく（空振りの照合に使う）
        var examined = new List<string>();

        // 「実際に名乗る」の目印を 1 つずつたどる
        foreach (Match tag in Regex.Matches(securityDoc, Regex.Escape(ClaimTag)))
        {
            // <b>囲みの中に置かれた目印は「約束ごとの言及」で、名乗りではない。</b>
            // 文書はこの約束自体を説明するために目印をコードの囲みで掲げるので、
            // それを名乗りと取り違えると<b>正しい文書で赤くなる</b>。名乗りは必ず囲みの外へ置く決まりなので、
            // 囲みの中にある目印を逃しても、目印を囲みへ退避させる囮は (b) が落とす
            if (MarkdownSource.IsInsideCodeSpan(securityDoc, tag.Index)) continue;

            // その目印が指している指示の並び（同じ行の、直前にある綴り）
            var claimed = DirectiveListBefore(securityDoc, tag.Index);

            // 並びが読めなければ、何を確かめればよいか決められないので落とす
            Assert.False(
                string.IsNullOrWhiteSpace(claimed),
                $"{ClaimTag} の直前にキャッシュ指示が見つかりません（docs/security.md）。"
                    + "目印は指示の値の直後（同じ行）へ置いてください。");

            // 確かめた 1 件として控える
            examined.Add(claimed);

            // 長期・immutable でないこと（期間を持たない no-store 等はそのまま通る）
            AssertNotLongLived(SplitDirectives(claimed), $"docs/security.md の「{claimed}」");
        }

        // <b>「1 件も確かめていない」状態を落とす。</b> 目印の読み取りが何かの拍子に
        // すべてを弾くと、この検査は<b>何も assert しないまま緑になる</b>。
        // 手がかりを変えて、<b>兄弟の検査が固定している静的アセットの指示</b>が
        // 確かめた中にあることを見る ——この 1 件は文書に必ず載っている。
        Assert.Contains(SecurityHeadersMiddleware.StaticAssetCacheControl, examined);

        // (b) 目印を要求した件数（空振りの照合に使う）
        var required = 0;

        // 長期化につながる指示を、囲みの有無を問わず走査する
        foreach (Match directive in Regex.Matches(securityDoc, MarkerRequiredDirectivePattern, RegexOptions.IgnoreCase))
        {
            // <b>コードブロック（``` で囲んだ設定例）の中は見ない（レビュー指摘）。</b>
            // あそこでは HTML コメントが<b>そのまま表示される</b>ので、目印を要求すると
            // 「正しい短期の nginx 設定例を足しただけで CI が赤くなり、
            // 案内される直し方に従うと運用者がコピペする設定へコメントが混ざる」
            // ——この repo が繰り返し避けている<b>実行不能な指示</b>になる（実測で赤くなった）。
            // 代償（ブロックの中の長期指定は検査が黙る）は CLAUDE.md §3 の「残る境界」が正本
            if (MarkdownSource.IsInsideFencedBlock(securityDoc, directive.Index)) continue;

            // キャッシュの名乗りとして書かれているものだけを見る（HSTS や地の文を巻き込まない）
            if (!RequiresMarker(securityDoc, directive)) continue;

            // 目印を 1 件要求したことを控える
            required++;

            // 目印が無ければ落ちる（付いていれば名乗り／反例のどちらかに決まっている）
            AssertMarkerPresent(securityDoc, directive.Index + directive.Length, directive.Value);
        }

        // <b>この枝も「1 件も見ていない」状態を落とす。</b>
        // 実測で、文脈の判定を常に false にしても全件緑のまま通り、
        // その状態では目印を付けない囮が素通りした。
        Assert.True(
            required > 0,
            "キャッシュ指示に目印を要求する走査が 1 件も見ていません。"
                + "docs/security.md には期間の指示が少なくとも 1 つあるはずなので、"
                + "走査の条件（綴り・文脈の判定）が狭すぎないか確かめてください"
                + "（このまま緑にすると、目印を付けない囮が素通りします）。");
    }

    /// <summary>目印を要求する綴り（期間の指示と <c>immutable</c>）。</summary>
    /// <remarks>
    /// <b><c>immutable</c> も走査する（レビュー指摘）。</b> 期間の指示だけを走査していたころは、
    /// <c>public,immutable</c>（RFC 8246 上、<c>max-age</c> 無しでも成立する）を名乗る文が
    /// 目印を 1 つも要求されず、判定にも渡されなかった（実測で全件緑）。
    /// </remarks>
    private static string MarkerRequiredDirectivePattern =>
        // 期間の指示か、単語としての immutable
        LifetimeDirectivePattern
            + $"|(?<![A-Za-z0-9-]){Regex.Escape(ForbiddenDirective)}(?![A-Za-z0-9-])";

    /// <summary>その指示が、目印を要求すべき「キャッシュの名乗り」かを見る。</summary>
    /// <remarks>
    /// <b>綴りの種類で判定を分ける。</b> 両方に同じ規則を当てると、どちらかの穴が必ず残る:
    /// <list type="bullet">
    /// <item><b>期間の指示</b>は値付き（<c>max-age=3600</c>）なので地の文にはまず現れない。
    /// だから<b>他のヘッダーを名乗っていない限り</b>名乗りとして扱う。
    /// 行内の <c>Cache-Control</c> やカンマ隣接だけを見る形だと、
    /// ヘッダー名が<b>折り返しで前の行へ回った名乗り</b>が目印を要求されない
    /// （実測で全件緑。この文書は折り返しが多いので現実的な形）。
    /// HSTS は <c>Strict-Transport-Security:</c> と名乗るのでこの規則で外れる。</item>
    /// <item><b><c>immutable</c></b> は単語なので地の文にも現れる
    /// （この文書は「長期・<c>immutable</c> にはしません」と正しく使っている）。
    /// 同じ規則を当てると<b>正しい文書で赤くなる</b>ので、名乗りの手がかり
    /// （他の指示とカンマでつながる／同じ行で <c>Cache-Control</c> を名指す）があるときだけ見る。</item>
    /// </list>
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="match">指示への一致。</param>
    /// <returns>目印を要求すべきなら <c>true</c>。</returns>
    private static bool RequiresMarker(string doc, Match match) =>
        // 期間の指示なら、他のヘッダーを名乗っていない限り名乗りとして扱う
        Regex.IsMatch(match.Value, LifetimeDirectivePattern, RegexOptions.IgnoreCase)
            ? !NamesAnotherHeader(doc, match)
            // immutable は地の文にも現れるので、名乗りの手がかりがあるときだけ見る
            : MarkdownSource.LineAt(doc, match.Index).Contains(CacheControlHeaderName, StringComparison.OrdinalIgnoreCase)
                || IsCommaAdjacent(doc, match);

    /// <summary>その指示の手前で、<c>Cache-Control</c> 以外のヘッダー名を名乗っているかを見る。</summary>
    /// <remarks>
    /// HSTS（<c>Strict-Transport-Security: max-age=31536000; includeSubDomains</c>）のように、
    /// キャッシュと無関係なヘッダーが同じ綴りの期間を持つことがある。
    /// <b>行内に <c>Cache-Control</c> が無いことを除外の根拠にしない</b>のが要点で、
    /// それだとヘッダー名が前の行へ回った名乗りまで除外してしまう。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="match">指示への一致。</param>
    /// <returns>他のヘッダー名を名乗っているなら <c>true</c>。</returns>
    private static bool NamesAnotherHeader(string doc, Match match)
    {
        // その指示の直前にある、同じ行の綴り
        var before = DirectiveRunBefore(doc, match.Index);

        // <b>一番近いヘッダー名を見る（レビュー指摘）。</b> 先頭から探すと、
        // 同じ綴りの手前に別のヘッダー名があるだけで（`Vary: …, Cache-Control: …`）
        // <b>名乗りが丸ごと除外される</b> ——実測で 1 年のキャッシュが全件緑のまま通った
        var header = Regex.Match(
            before, "(?<name>[A-Za-z][A-Za-z0-9-]*)[ \t]*:", RegexOptions.RightToLeft);

        // 見つかり、かつ Cache-Control 以外なら真
        return header.Success
            && !header.Groups["name"].Value.Equals(CacheControlHeaderName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>ヘッダー名（文脈の判定に使う）。</summary>
    private const string CacheControlHeaderName = "Cache-Control";

    /// <summary>目印の直前にある、指示の並びを切り出す。</summary>
    /// <remarks>
    /// <b>目印を起点にするのが要点（レビュー指摘）。</b> 期間の指示を起点に
    /// その 1 つだけを渡していたため、同じ並びの <c>immutable</c> が
    /// 一度も見られていなかった。目印から遡って並び全体を取れば、
    /// 期間も <c>immutable</c> も同じ 1 回の判定に載る。
    /// <b>行をまたがない</b> ——またぐと、次の行の指示まで巻き込む。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="tagIndex">目印の開始位置。</param>
    /// <returns>指示の並び（囲みとヘッダー名を取り除いたもの）。</returns>
    private static string DirectiveListBefore(string doc, int tagIndex) =>
        // 切り出した綴りから、囲みとヘッダー名を取り除く
        StripDirectiveDecoration(DirectiveRunBefore(doc, tagIndex));

    /// <summary>その位置の直前にある、同じ行の指示の綴りをそのまま切り出す。</summary>
    /// <remarks>目印から並びを取る側と、ヘッダー名を見る側が同じ遡り方を共有する（§6 DRY）。</remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">遡り始める位置。</param>
    /// <returns>切り出した綴り（囲み・ヘッダー名を含む）。</returns>
    private static string DirectiveRunBefore(string doc, int index)
    {
        // 同じ行の中だけを遡る（行の切り出しの規則は共有側が正本。§6 DRY）
        var lineStart = MarkdownSource.LineStart(doc, index);

        // 指示の並びを構成しうる文字の間だけ遡る
        var at = index;
        // 行の先頭に着くまで
        while (at > lineStart && IsDirectiveListCharacter(doc[at - 1])) at--;

        // 遡った分をそのまま返す
        return doc[at..index];
    }

    /// <summary>切り出した綴りから、囲み（バッククォート）とヘッダー名を取り除く。</summary>
    /// <param name="text">切り出した綴り。</param>
    /// <returns>指示の並びだけ。</returns>
    private static string StripDirectiveDecoration(string text)
    {
        // 囲みと前後の空白を落とす
        var trimmed = text.Trim().Trim('`').Trim();

        // ヘッダー名が前に付いていれば落とす
        var header = trimmed.IndexOf(':');
        // "Cache-Control:" の形だけを落とす（値の中の "=" は触らない）
        if (header >= 0
            && trimmed[..header].Trim().Equals(CacheControlHeaderName, StringComparison.OrdinalIgnoreCase))
        {
            // ヘッダー名とコロンより後ろだけを残す
            trimmed = trimmed[(header + 1)..].Trim();
        }

        // 指示の並びを返す
        return trimmed;
    }

    /// <summary>実際に名乗っていることを示す目印（HTML コメントなので表示に出ない）。</summary>
    private const string ClaimTag = "<!--cache-claim-->";

    /// <summary>してはいけない例であることを示す目印。</summary>
    private const string CounterExampleTag = "<!--cache-counter-example-->";

    /// <summary>
    /// 指示の直後に、扱いを示す目印（名乗り／反例）が置かれていることを確かめる。
    /// </summary>
    /// <remarks>
    /// <b>目印が無ければ落とす（fail-closed）。</b> 「たぶん反例だろう」と読み飛ばすと、
    /// 新しく書かれた名乗りが黙って検査を外れる。目印を要求すれば、書いた人は
    /// <b>名乗りなのか反例なのかを必ず一度決める</b>ことになり、
    /// 囮を仕込むには「これは反例です」と差分に書き残す必要がある。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="after">指示の直後の位置。</param>
    /// <param name="directive">失敗文言に出す、その指示の綴り。</param>
    private static void AssertMarkerPresent(string doc, int after, string directive)
    {
        // 目印は<b>指示の並び全体の後ろ</b>に置く決まり。1 件の期間の指示に当たったときは
        // 同じ並びの残り（",immutable" など）と閉じのバッククォートが手前に挟まるので、
        // <b>指示の並びを構成しうる文字と空白だけ</b>を読み飛ばしてから目印を探す。
        // 日本語の文字に当たった時点で止まるので、地の文の名乗り
        // （"public, max-age=… を名乗ります"）を目印付きと取り違えることはない
        var at = after;

        // <b>行はまたがない（レビュー指摘）。</b> またぐと、次の行に置かれた
        // 別の指示の目印を借りてしまい、<b>目印の無い指示が反例として見逃される</b>
        // （実測: "public, max-age=31536000" の次の行に反例の目印を置くと全件緑だった）。
        while (at < doc.Length && doc[at] != '\n' && IsDirectiveListCharacter(doc[at])) at++;

        // 読み飛ばした先から、目印 1 つ分だけを見る
        var window = doc[at..Math.Min(at + TagWindow, doc.Length)];

        // <b>囲みの外にある目印だけを認める。</b> 囲みの中の目印は約束への言及なので、
        // 認めると「指示を囲みで閉じ、目印を別の囲みへ入れる」形で囮を逃がせられる
        var tagged = !MarkdownSource.IsInsideCodeSpan(doc, at);

        // 「名乗る」の目印があれば、ここではこれ以上見ない
        // （値そのものは、目印を起点に並び全体を読む (a) の枝が確かめる）
        if (tagged && window.StartsWith(ClaimTag, StringComparison.Ordinal)) return;

        // 「反例」の目印があれば、この指示は文書が名乗っていないので通す
        if (tagged && window.StartsWith(CounterExampleTag, StringComparison.Ordinal)) return;

        // どちらも無ければ、どう扱うべきか決められないので落とす
        Assert.Fail(
            $"docs/security.md のキャッシュ指示に目印がありません: {directive}。"
                + $"実際に名乗るなら値の直後へ {ClaimTag} を、"
                + $"してはいけない例として挙げるなら {CounterExampleTag} を付けてください"
                + "（どちらも HTML コメントなので表示には出ません）。"
                + "文章の言い回しから推し量る形は、書き方を変えるたびに"
                + "誤って赤くなるか黙って緑になるかのどちらかになるため採りません。");
    }

    /// <summary>指示の並び（<c>public,max-age=3600</c> 等）を構成しうる文字かを見る。</summary>
    /// <remarks>
    /// 目印を探す前に読み飛ばす範囲と、目印から遡って指示の並びを切り出す範囲を
    /// 決めるためのもの。閉じのバッククォート・ヘッダー名のコロン・空白も含める。
    /// <b>日本語の文字は含めない</b> ——含めると、地の文の名乗りを目印付きと取り違える。
    /// 改行はここでは弾かず、<b>呼ぶ側が行をまたぎそうな位置で止める</b>
    /// （空白の判定と行の境界は別の関心で、混ぜると片方を直したときにもう片方が壊れる）。
    /// </remarks>
    /// <param name="ch">判定する 1 文字。</param>
    /// <returns>指示の並びを構成しうるなら <c>true</c>。</returns>
    private static bool IsDirectiveListCharacter(char ch) =>
        // 指示の綴りに使う文字か、区切り・囲み・コロン・空白なら真
        char.IsAsciiLetterOrDigit(ch) || ch is '=' or ',' or '-' or '`' or ':' || char.IsWhiteSpace(ch);

    /// <summary>目印を探す幅（指示の直後に置く決まりなので、長い目印 1 つ分あれば足りる）。</summary>
    private static readonly int TagWindow = Math.Max(ClaimTag.Length, CounterExampleTag.Length);

    /// <summary>キャッシュ指示の文字列を、指示ごとに分ける。</summary>
    /// <param name="cacheControl"><c>Cache-Control</c> の値。</param>
    /// <returns>前後の空白を落とした指示の一覧。</returns>
    private static List<string> SplitDirectives(string cacheControl) =>
        // カンマ区切りの各指示へ分け、"=" の前後の空白も落とす
        [.. cacheControl
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormalizeDirective)];

    /// <summary>指示 1 つを、名前と値のあいだの空白を落とした形へそろえる。</summary>
    /// <remarks>
    /// <b>そろえないと、空白の入った書き方が「指示 0 件」として素通りする（レビュー指摘）。</b>
    /// 走査側は <c>\s*=\s*</c> で空白を許しているのに、期間かどうかの判定は
    /// <c>"max-age="</c> で始まるかを見ていたため、<c>public, max-age = 31536000</c> と
    /// 書いた囮は<b>期間の指示が 1 つも無い</b>とみなされ、上限の検査が
    /// 1 つも走らないまま緑になっていた（実測）。
    /// </remarks>
    /// <param name="directive">指示 1 つ。</param>
    /// <returns>"名前=値" の形（値を持たない指示はそのまま）。</returns>
    private static string NormalizeDirective(string directive)
    {
        // 値を持つ指示かどうかを見る
        var separator = directive.IndexOf('=');
        // 持たないならそのまま返す（no-store など）
        if (separator < 0) return directive;

        // 名前と値それぞれの前後の空白を落としてつなぎ直す
        return directive[..separator].TrimEnd() + "=" + directive[(separator + 1)..].TrimStart();
    }

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
        // immutable を付けていないこと(付けると再取得の手段が無くなる)。
        // <b>出所を失敗文言へ出す（レビュー指摘）。</b> 呼び出し口は 3 つ（定数・
        // 囲みのある名乗り・地の文）あるので、出所が無いと「どこの指示の話か」が読めない
        Assert.False(
            directives.Any(d => d.Equals(ForbiddenDirective, StringComparison.OrdinalIgnoreCase)),
            $"{ForbiddenDirective} を含むキャッシュ指示です（{source}）。"
                + "版付きでない wwwroot/lib 配下を参照しているため、"
                + $"{ForbiddenDirective} を名乗ると脆弱性修正後も古いファイルを消す手段が無くなります。");

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

    /// <summary>その一致が、カンマで他の指示とつながっているかを見る。</summary>
    /// <remarks>
    /// キャッシュ指示の値はカンマ区切りで書かれる（<c>public,max-age=3600</c>）。
    /// 期間の綴りを使う別のヘッダー（HSTS はセミコロン区切り）と見分けるための手がかり。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="match">期間の指示への一致。</param>
    /// <returns>前か後ろがカンマなら <c>true</c>。</returns>
    private static bool IsCommaAdjacent(string doc, Match match) =>
        // 前へ空白を読み飛ばしてカンマに当たるか
        HasCommaBefore(doc, match.Index)
        // 後ろへ空白を読み飛ばしてカンマに当たるか
        || HasCommaAfter(doc, match.Index + match.Length);

    /// <summary>指定位置の手前が（空白を挟んで）カンマかを見る。</summary>
    /// <remarks>
    /// <b>空白を読み飛ばすのが要点（レビュー指摘）。</b> 隣接だけを見ていたため、
    /// ごく普通の空け方で書いた囮（"public, max-age=31536000 を名乗ります"）が
    /// 素通りした（実測）。セミコロン区切りの HSTS は巻き込まないまま、
    /// カンマ区切りの名乗りだけを拾える。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">見はじめる位置（この 1 つ手前から遡る）。</param>
    /// <returns>カンマに当たれば <c>true</c>。</returns>
    private static bool HasCommaBefore(string doc, int index)
    {
        // 空白のあいだは遡り続ける
        var at = index - 1;
        // 文書の先頭に着くまで
        while (at >= 0 && char.IsWhiteSpace(doc[at])) at--;
        // 空白でない最初の文字がカンマかどうか
        return at >= 0 && doc[at] == ',';
    }

    /// <summary>指定位置の直後が（空白を挟んで）カンマかを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">見はじめる位置。</param>
    /// <returns>カンマに当たれば <c>true</c>。</returns>
    private static bool HasCommaAfter(string doc, int index)
    {
        // 空白のあいだは進み続ける
        var at = index;
        // 文書の末尾に着くまで
        while (at < doc.Length && char.IsWhiteSpace(doc[at])) at++;
        // 空白でない最初の文字がカンマかどうか
        return at < doc.Length && doc[at] == ',';
    }

    /// <summary>運用者向けのセキュリティ文書を読む。</summary>
    /// <remarks>
    /// パスの正本は <see cref="RepositoryPaths.SecurityDoc"/>、読み方の正本は
    /// <see cref="MarkdownSource.Read"/>（改行を LF へそろえる）。
    /// <b>パスだけを共有して読み方を各自で書かない（レビュー指摘）</b> ——
    /// 正規化を足した側だけが直り、もう片方は Windows のチェックアウトでだけ壊れる。
    /// </remarks>
    /// <returns>文書全体。</returns>
    private static string ReadSecurityDoc() =>
        // 共有の読み口を通す
        MarkdownSource.Read(RepositoryPaths.SecurityDoc);

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
