// 正規表現で View / TypeScript ソースを走査するために取り込む
using System.Text.RegularExpressions;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Views;

// Guard-rail test: 分析ページ(Views/Analytics/Index.cshtml)の JavaScript が
// TypeScript 側(Scripts/analytics.ts)へ切り出された構成を維持していることを検査する。
//
// 背景: 以前この画面には約 330 行の inline <script> が直接書かれており、
//   - tsc の型チェック(tsconfig.json の strict)が一切かからない
//   - Views/Home/Index.cshtml(dashboard.ts)だけが「JSON データ島 + 外部 js」構成という不統一
//   - Content-Security-Policy を導入するときの障害(Middleware/SecurityHeadersMiddleware の
//     コメントが「nonce を持たない inline script があるため CSP は別 PR」と明記している)
// という 3 つの問題があった。inline script へ戻す変更を CI で検出できるよう、
// ChartAccessibilityTests / RoleGatedNavigationTests と同じくソースを直接走査して固定する。
public class AnalyticsScriptContractTests
{
    // <script ...> の開始タグを属性ごと抜き出す正規表現
    private static readonly Regex ScriptTagRegex =
        new(@"<script\b(?<attrs>[^>]*)>", RegexOptions.Singleline);

    // 外部ファイル読み込み(src 属性つき)かどうかを判定する正規表現
    private static readonly Regex ScriptSrcRegex =
        new(@"src\s*=\s*""[^""]+""", RegexOptions.None);

    // データ島(実行されない application/json ブロック)かどうかを判定する正規表現
    private static readonly Regex ScriptJsonTypeRegex =
        new(@"type\s*=\s*""application/json""", RegexOptions.None);

    // Razor(値の入る要素)と TypeScript(値を書き込む側)の双方に存在していなければならない
    // DOM 要素の id 一覧。分析サマリー欄と再発統計欄は、Razor 側に静的マークアップを置き
    // analytics.ts が textContent だけを差し替える契約になっている。
    // 片側だけ改名すると画面は「-」のまま無言で壊れる(例外もコンソールエラーも出ない)ため、
    // 両側に同じ id が現れることをここで固定する
    private static readonly string[] SummaryElementIds =
    {
        "topDept",              // 最多発生部署
        "topType",              // 最多インシデント種別
        "completionRate",       // 対策完了率
        "failedMeasures",       // 再発確認対策数
        "overdueMeasures",      // 期限超過対策数
        "recurrencePrevented",  // 再発なし(対策有効)件数
        "recurrenceRecurred"    // 再発あり(要追加対策)件数
    };

    [Fact]
    public void AnalyticsView_HasNoExecutableInlineScript()
    {
        // 分析ページのソースを読み込む
        var source = File.ReadAllText(AnalyticsViewPath());

        // 実行される inline script(src も application/json も無い <script>)を集める
        var violations = new List<string>();
        // 検査対象の <script> 数(0 件なら検出パターンの劣化を疑う)
        var totalScripts = 0;

        // このファイル内の <script> 開始タグをすべて列挙する
        foreach (Match match in ScriptTagRegex.Matches(source))
        {
            totalScripts++;
            // 属性部分だけを取り出す
            var attrs = match.Groups["attrs"].Value;
            // 外部ファイル読み込み、またはデータ島であれば合格
            if (ScriptSrcRegex.IsMatch(attrs) || ScriptJsonTypeRegex.IsMatch(attrs)) continue;
            // どちらでもなければ実行される inline script なので違反として記録する
            violations.Add($"<script{attrs}>");
        }

        // <script> が 1 個も見つからないのは想定外(データ島と外部 js の 2 個があるはず)
        Assert.True(totalScripts > 0,
            "Views/Analytics/Index.cshtml に <script> が 1 つも見つかりませんでした。検出パターンが変更された可能性があります。");
        // 違反ゼロであること(あればどのタグかをメッセージで示す)
        Assert.True(violations.Count == 0,
            "分析ページの JavaScript は Scripts/analytics.ts に置き、Razor からは "
            + "<script type=\"application/json\"> のデータ島と <script src=\"~/js/analytics.js\"> だけを出力してください "
            + "(inline script は tsc の型チェックを受けられず、CSP 導入の障害にもなります):\n"
            + string.Join("\n", violations));
    }

    [Fact]
    public void AnalyticsView_EmbedsDataIslandAndLoadsCompiledScript()
    {
        // 分析ページのソースを読み込む
        var source = File.ReadAllText(AnalyticsViewPath());

        // analytics.ts が読み取るデータ島の id が存在すること
        // (この id が無いと analytics.ts は初期化を諦めて何も描画しない)
        Assert.Contains("id=\"analytics-data\"", source, StringComparison.Ordinal);
        // コンパイル済みの analytics.js を読み込んでいること
        Assert.Contains("~/js/analytics.js", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SummaryElementIds_ExistInBothViewAndScript()
    {
        // 分析ページのソースを読み込む
        var viewSource = File.ReadAllText(AnalyticsViewPath());
        // 切り出し済みの TypeScript ソースを読み込む
        var scriptSource = File.ReadAllText(AnalyticsScriptPath());

        // 片側にしか現れない id を違反として集める
        var violations = new List<string>();

        // 契約対象の id を 1 件ずつ確認する
        foreach (var id in SummaryElementIds)
        {
            // Razor 側に id="..." として存在するか
            var inView = viewSource.Contains($"id=\"{id}\"", StringComparison.Ordinal);
            // TypeScript 側に文字列として現れるか(SUMMARY_FIELDS の値、または直接の引数)
            var inScript = scriptSource.Contains($"'{id}'", StringComparison.Ordinal);
            // 両方に存在すれば合格
            if (inView && inScript) continue;
            // 欠けている側を明示して違反として記録する
            violations.Add($"{id}: Razor={(inView ? "有" : "無")} / TypeScript={(inScript ? "有" : "無")}");
        }

        // 違反ゼロであること(あればどの id がどちら側で欠けているかを示す)
        Assert.True(violations.Count == 0,
            "分析サマリー欄の id は Views/Analytics/Index.cshtml と Scripts/analytics.ts の両方に存在する必要があります "
            + "(片側だけ改名すると値が「-」のまま無言で壊れます):\n"
            + string.Join("\n", violations));
    }

    // 分析ページ(Razor)の絶対パスを組み立てて、存在を確認したうえで返す
    private static string AnalyticsViewPath()
    {
        // Views ディレクトリ配下の Analytics/Index.cshtml を指す
        var path = Path.Combine(RepositoryPaths.Views, "Analytics", "Index.cshtml");
        // 移動・改名を検知できるよう存在を確認する
        Assert.True(File.Exists(path), $"{path} が見つかりません。");
        return path;
    }

    // 分析ページ用 TypeScript の絶対パスを組み立てて、存在を確認したうえで返す
    private static string AnalyticsScriptPath()
    {
        // Scripts ディレクトリ配下の analytics.ts を指す
        var path = Path.Combine(RepositoryPaths.WebProject, "Scripts", "analytics.ts");
        // inline script へ戻された場合はここで失敗する(ファイルごと消えるため)
        Assert.True(File.Exists(path), $"{path} が見つかりません。");
        return path;
    }
}
