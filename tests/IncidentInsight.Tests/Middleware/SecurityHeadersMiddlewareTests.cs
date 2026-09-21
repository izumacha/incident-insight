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
        var (start, end) = BulletBounds(doc, anchors[0]);

        // 箇条書きの中にあること（地の文に書かれていると範囲を決められない）
        Assert.True(
            IsBulletStart(doc, start),
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

    // 「そうしない」と述べていることの目印。
    //
    // <b>肯定の目印だけでは足りない（レビュー指摘）。</b> 「を名乗」は
    // 「を名乗<b>りません</b>」の一部でもあるので、否定形で書いた反例が
    // 肯定的な名乗りに見えていた（実測で、正しい反例が落ちた）——
    // 直したはずの「反例を書くと赤くなる」形が、別の言い回しで残っていた。
    //
    // <b>行に 1 つでもあれば反例として扱う（見逃す側へ倒す）。</b> 否定は文の
    // どこにでも置けるので、肯定の目印との位置関係で判定しようとすると
    // 綴りを足し続けることになる。取りこぼす側の代償は、囲みのある名乗りを
    // 箇条書き単位で照合する検査（StaticAssetCacheControl_MatchesTheDocumentedDirective）と
    // 定数側の検査が別の手がかりで押さえているぶん小さい。
    //
    // <b>残っている境界</b>: 肯定的に名乗る行がたまたま否定語を含む場合
    //（"…を名乗ります（キャッシュしないため）" 等）は見逃す。

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
    // 目印を持たない囮を手前へ足すと 1168 件すべて緑のまま通った）。
    // 運用者が読むのは文書全体なので、どの箇条書きであれ
    // 「長期・immutable を名乗る」記述が載っていること自体が守りたい状態に反する。
    //
    // <b>「名乗りか反例か」を文章から推し量らない（レビュー指摘）。</b> 以前は
    // 「を名乗」「ません」等の綴りから判定していたが、それは CLAUDE.md が
    // <b>繰り返し失敗として記録している近似の走査</b>そのものだった ——実際この PR の中だけでも
    // 「6 文字では足りない」「『なく』『ず』が抜けている」「括弧内の否定を拾う」と
    // 3 度踏み直し、そのたびに<b>正しい文書で赤くなる</b>か<b>囮が黙って通る</b>かを
    // 行き来した。文書側に<b>機械可読な目印</b>（HTML コメント）を置けば推測が要らなくなる。
    //
    // <b>目印が無い指示は落とす（fail-closed）。</b> 新しく指示を書いた人は、
    // 名乗りなのか反例なのかを<b>必ず一度決める</b>ことになる ——
    // 囮を仕込むには「これは反例です」と差分に書き残す必要があり、レビューに現れる。
    [Fact]
    public void EveryDocumentedCacheDirective_IsNeverLongLived()
    {
        // 運用者向けドキュメントを読む
        var securityDoc = ReadSecurityDoc();

        // 具体的な値を伴うキャッシュ指示を<b>すべて</b>取り出す
        var documented = Regex.Matches(securityDoc, @"`Cache-Control:\s*(?<value>[^`]+)`");

        // 1 つも読み取れないのは、書き方が変わったか検査が壊れたか ——どちらも落とす
        Assert.NotEmpty(documented);

        // 実際に確かめた指示を控えておく（下の「空振りしていないか」の照合に使う）
        var examined = new List<string>();

        // 1 件ずつ確かめる
        foreach (Match match in documented)
        {
            // その指示に付いている目印を読む（無ければ落ちる）
            if (ClaimKindAfter(securityDoc, match.Index + match.Length, match.Value) != ClaimKind.Claim) continue;

            // 確かめた 1 件として控える
            examined.Add(match.Groups["value"].Value.Trim());

            // その指示を分解する
            var directives = SplitDirectives(match.Groups["value"].Value.Trim());

            // 長期・immutable でないこと（期間を持たない no-store 等はそのまま通る）
            AssertNotLongLived(directives, $"docs/security.md の `{match.Value}`");
        }

        // <b>「1 件も確かめていない」状態を落とす。</b> 目印の読み取りが何かの拍子に
        // すべてを弾くと、この検査は<b>何も assert しないまま緑になる</b>。
        // 手がかりを変えて、<b>兄弟の検査が固定している静的アセットの指示</b>が
        // 確かめた中にあることを見る ——この 1 件は文書に必ず載っている。
        Assert.Contains(SecurityHeadersMiddleware.StaticAssetCacheControl, examined);

        // <b>整った書き方だけを見ていては足りない。</b> 上の走査はバッククォートで
        // 囲まれた指示しか拾わないので、囲まずに書いた囮は素通りする（実測）。
        // 守りたいのは「文書が長期・immutable を名乗らないこと」であって<b>書式ではない</b>。
        //
        // 地の文の枝が実際に見た件数（空振りしていないかの照合に使う）
        var scannedInProse = 0;

        // 禁じている綴り自体を、囲みの有無を問わず走査する
        foreach (Match lifetime in Regex.Matches(securityDoc, LifetimeDirectivePattern, RegexOptions.IgnoreCase))
        {
            // <b>カンマで他の指示とつながっている形だけを見る。</b>
            // 期間の綴りはキャッシュ以外の指示にも現れる ——この文書には HSTS の節があり、
            // "Strict-Transport-Security: max-age=…; includeSubDomains" という
            // <b>正しい記述</b>で赤くなっていた（実測）。Cache-Control の値はカンマ区切り、
            // HSTS はセミコロン区切りなので、カンマ隣接に絞れば巻き込まない。
            if (!IsCommaAdjacent(securityDoc, lifetime)) continue;

            // 囲みのある名乗りと同じく、目印で「名乗りか反例か」を決める
            if (ClaimKindAfter(securityDoc, lifetime.Index + lifetime.Length, lifetime.Value) != ClaimKind.Claim) continue;

            // この枝も 1 件は実際に見たことを控える
            scannedInProse++;

            // <b>上限の判定は共有のヘルパーへ通す。</b> ここで読み取りと比較を
            // 書き下すと、上限や扱いを変えた人が片方だけを直し、
            // <b>囲みの有無で答えが食い違う</b>状態になる
            AssertNotLongLived(
                [$"{lifetime.Groups["name"].Value}={lifetime.Groups["seconds"].Value}"],
                $"docs/security.md の「{lifetime.Value}」");
        }

        // <b>地の文の枝も「1 件も見ていない」状態を落とす。</b>
        // 実測で、IsCommaAdjacent を常に false にしても全件緑のまま通り、
        // その状態では囲みなしの囮が素通りした。この文書には静的アセットの名乗り
        // （`public,max-age=3600`）があり、その max-age はカンマ隣接なので必ず 1 件は数えられる。
        Assert.True(
            scannedInProse > 0,
            "囲みの無い地の文の走査が 1 件も見ていません。"
                + "docs/security.md にはカンマでつながった期間の指示が少なくとも 1 つあるはずなので、"
                + "走査の条件（綴り・カンマ隣接・目印）が狭すぎないか確かめてください"
                + "（このまま緑にすると、囲みの無い囮が素通りします）。");
    }

    /// <summary>文書が指示をどう扱っているか（実際に名乗るのか、反例なのか）。</summary>
    private enum ClaimKind
    {
        /// <summary>実際にその指示を名乗る。</summary>
        Claim,

        /// <summary>してはいけない例として挙げている。</summary>
        CounterExample,
    }

    /// <summary>実際に名乗っていることを示す目印（HTML コメントなので表示に出ない）。</summary>
    private const string ClaimTag = "<!--cache-claim-->";

    /// <summary>してはいけない例であることを示す目印。</summary>
    private const string CounterExampleTag = "<!--cache-counter-example-->";

    /// <summary>
    /// 指示の直後に置かれた目印を読み、文書がその指示をどう扱っているかを返す。
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
    /// <returns>文書がその指示をどう扱っているか。</returns>
    private static ClaimKind ClaimKindAfter(string doc, int after, string directive)
    {
        // 目印は<b>指示の並び全体の後ろ</b>に置く決まり。1 件の期間の指示に当たったときは
        // 同じ並びの残り（",immutable" など）と閉じのバッククォートが手前に挟まるので、
        // <b>指示の並びを構成しうる文字と空白だけ</b>を読み飛ばしてから目印を探す。
        // 日本語の文字に当たった時点で止まるので、地の文の名乗り
        // （"public, max-age=… を名乗ります"）を目印付きと取り違えることはない
        var at = after;
        // 指示の並びの続き・閉じのバッククォート・空白の間は進める
        while (at < doc.Length && IsDirectiveListCharacter(doc[at])) at++;

        // 読み飛ばした先から、目印 1 つ分だけを見る
        var window = doc[at..Math.Min(at + TagWindow, doc.Length)];

        // 「名乗る」の目印があればそれ
        if (window.StartsWith(ClaimTag, StringComparison.Ordinal)) return ClaimKind.Claim;

        // 「反例」の目印があればそれ
        if (window.StartsWith(CounterExampleTag, StringComparison.Ordinal)) return ClaimKind.CounterExample;

        // どちらも無ければ、どう扱うべきか決められないので落とす
        Assert.Fail(
            $"docs/security.md のキャッシュ指示に目印がありません: {directive}。"
                + $"実際に名乗るなら値の直後へ {ClaimTag} を、"
                + $"してはいけない例として挙げるなら {CounterExampleTag} を付けてください"
                + "（どちらも HTML コメントなので表示には出ません）。"
                + "文章の言い回しから推し量る形は、書き方を変えるたびに"
                + "誤って赤くなるか黙って緑になるかのどちらかになるため採りません。");

        // Assert.Fail は必ず投げるので、ここには来ない
        return ClaimKind.CounterExample;
    }


    /// <summary>指示の並び（<c>public,max-age=3600</c> 等）を構成しうる文字かを見る。</summary>
    /// <remarks>
    /// 目印を探す前に読み飛ばす範囲を決めるためのもの。閉じのバッククォートと空白も含める。
    /// <b>日本語の文字は含めない</b> ——含めると、地の文の名乗りを目印付きと取り違える。
    /// </remarks>
    /// <param name="ch">判定する 1 文字。</param>
    /// <returns>読み飛ばしてよいなら <c>true</c>。</returns>
    private static bool IsDirectiveListCharacter(char ch) =>
        // 指示の綴りに使う文字か、区切り・囲み・空白なら読み飛ばす
        char.IsAsciiLetterOrDigit(ch) || ch is '=' or ',' or '-' or '`' || char.IsWhiteSpace(ch);

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

    /// <summary>指定位置を含む箇条書きの範囲（開始・終了の文字位置）を求める。</summary>
    /// <remarks>
    /// <b>箇条書きの境目の規則はここ 1 か所に置く（レビュー指摘）。</b> 同じ規則
    /// （行頭の <c>"- "</c> で区切る）を 2 か所へ書き写すと、文書が別の記号の
    /// 箇条書きへ変わったときに片方だけが直り、もう片方は<b>無関係な範囲</b>を
    /// 見たまま静かに誤分類する（§6 DRY）。
    /// 箇条書きの外（地の文）にある位置は、その行だけを範囲として返す。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">含めたい位置。</param>
    /// <returns>箇条書きの開始位置と、終了位置（終端は含まない）。</returns>
    private static (int Start, int End) BulletBounds(string doc, int index)
    {
        // その位置を含む行の先頭を探す
        var lineStart = doc.LastIndexOf('\n', Math.Max(index - 1, 0)) + 1;

        // <b>上へたどってよいのは「継続行」の間だけ（レビュー指摘）。</b>
        // 条件を付けずに直前の "- " まで遡ると、<b>箇条書きの外にある地の文</b>が
        // 手前の箇条書きの一部として扱われ、「箇条書きの中にあること」の検査が
        // <b>原理的に落ちなくなる</b> ——実測で、静的アセットの説明を地の文へ移し、
        // 手前に別の箇条書きを置くと、<b>無関係な箇条書きの指示</b>が
        // 静的アセットの名乗りとして照合され、全件緑のまま通った。
        // 継続行（行頭が空白）でたどれば、その位置を実際に含む箇条書きだけに着く。
        var start = lineStart;
        // 箇条書きの先頭に当たるまで、継続行の間だけ遡る
        while (start > 1 && !IsBulletStart(doc, start) && IsContinuationLine(doc, start))
        {
            // 1 つ前の行の先頭へ
            start = doc.LastIndexOf('\n', start - 2) + 1;
        }

        // 箇条書きの外（地の文）なら、その行だけを範囲にする
        if (!IsBulletStart(doc, start)) start = lineStart;

        // 次の行から順に、箇条書きの続きでなくなるところまで進める
        var end = doc.IndexOf('\n', index);
        // 継続行の間は同じ箇条書き（次の "- " も、字下げの無い地の文もここで止まる）
        while (end >= 0 && end + 1 < doc.Length && IsContinuationLine(doc, end + 1))
        {
            // さらに次の改行へ
            end = doc.IndexOf('\n', end + 1);
        }

        // 改行が見つからなければ文書の末尾まで
        return (start, end < 0 ? doc.Length : end);
    }

    /// <summary>その行が、直前の箇条書きの続き（字下げされた行）かを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">行の先頭位置。</param>
    /// <returns>継続行なら <c>true</c>。</returns>
    private static bool IsContinuationLine(string doc, int index) =>
        // 行頭が空白（かつ改行ではない）なら、前の行の続き
        index < doc.Length && doc[index] != '\n' && char.IsWhiteSpace(doc[index]);

    /// <summary>その位置が箇条書きの先頭（行頭の <c>"- "</c>）かを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">行の先頭位置。</param>
    /// <returns>箇条書きの先頭なら <c>true</c>。</returns>
    private static bool IsBulletStart(string doc, int index) =>
        // 行頭が "- " で始まっているか
        index + 1 < doc.Length && doc[index] == '-' && doc[index + 1] == ' ';

    /// <summary>運用者向けのセキュリティ文書を読む。</summary>
    /// <remarks>パスの正本は <see cref="RepositoryPaths.SecurityDoc"/>（読み手が 2 つあるため）。</remarks>
    /// <returns>文書全体。</returns>
    private static string ReadSecurityDoc() =>
        // 共有のパスから読む
        File.ReadAllText(RepositoryPaths.SecurityDoc);

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
