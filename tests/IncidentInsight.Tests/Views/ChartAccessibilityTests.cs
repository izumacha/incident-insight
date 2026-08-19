// 正規表現で View ソースを走査するために取り込む
using System.Text.RegularExpressions;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Views;

// Guard-rail test: Chart.js の描画先である <canvas> に、支援技術向けの名前
// (role="img" + 空でない aria-label)が付いていることを検査する。
//
// 過去の回帰: 分析ページ(Views/Analytics/Index.cshtml)の 7 個とダッシュボード
// (Views/Home/Index.cshtml)の 1 個、合わせて 8 個すべての <canvas> が裸で置かれていた。
// canvas の中身はビットマップなので、スクリーンリーダー利用者にはグラフが「存在しない」のと
// 同じ状態になり、分析ページはページ全体がほぼ無内容になっていた
// (CLAUDE.md §7「スクリーンリーダーに情報を伝える」違反)。
//
// コントローラ単体テストでは View 側のマークアップ欠落を検出できないため、
// RoleGatedNavigationTests / ConcurrencyTokenFormTests と同じく View ソースを直接走査して固定する。
public class ChartAccessibilityTests
{
    // <canvas ...> の開始タグを属性ごと抜き出す正規表現(自己完結タグは使わない前提)
    private static readonly Regex CanvasTagRegex =
        new(@"<canvas\b(?<attrs>[^>]*)>", RegexOptions.Singleline);

    // 開始タグの属性列に role="img" が含まれているかを判定する正規表現
    private static readonly Regex RoleImgRegex =
        new(@"role\s*=\s*""img""", RegexOptions.None);

    // 開始タグの属性列に「空でない」aria-label が含まれているかを判定する正規表現。
    // aria-label="" のような空文字は名前を与えないため不合格にする
    private static readonly Regex NonEmptyAriaLabelRegex =
        new(@"aria-label\s*=\s*""[^""]+""", RegexOptions.None);

    // aria-label の中身(属性値)だけを取り出す正規表現
    private static readonly Regex AriaLabelValueRegex =
        new(@"aria-label\s*=\s*""(?<value>[^""]*)""", RegexOptions.None);

    // 分析ページの canvas が初期 aria-label の末尾に必ず付ける「読み込み中」サフィックス。
    // Scripts/analytics.ts の CHART_LOADING_SUFFIX と同じ文字列
    // (以前は Views/Analytics/Index.cshtml の inline script 内にあったが TypeScript へ切り出した)
    private const string ChartLoadingSuffix = "（データ読み込み中）";

    [Fact]
    public void AnalyticsChartCanvases_HaveLoadingSuffix_SoScriptCanDeriveChartName()
    {
        // 分析ページの JS は「初期 aria-label から読み込み中サフィックスを取り除いた残り」を
        // グラフ名として退避し、取得成功時は数値入りラベル、失敗時はエラーラベルに組み立て直す。
        // つまりサフィックスが Razor と JS をつなぐ契約になっている。
        // サフィックスを外した(あるいは表記を変えた)まま JS を直し忘れると、
        // 「…（データ読み込み中）。外来 3件」のような二重表記のラベルが読み上げられてしまうため、
        // ここで Razor 側の書式を固定する。
        var analyticsView = Path.Combine(RepositoryPaths.Views, "Analytics", "Index.cshtml");
        // 対象ファイルが存在すること(移動・改名の検知)
        Assert.True(File.Exists(analyticsView), $"{analyticsView} が見つかりません。");

        // ビューのソースを読み込む
        var source = File.ReadAllText(analyticsView);
        // サフィックスで終わっていない aria-label を違反として集める
        var violations = new List<string>();
        // 検査対象の canvas 数(0 件なら検出パターンの劣化を疑う)
        var totalCanvases = 0;

        // このファイル内の <canvas> 開始タグをすべて列挙する
        foreach (Match match in CanvasTagRegex.Matches(source))
        {
            totalCanvases++;
            // 属性列から aria-label の値を取り出す
            var value = AriaLabelValueRegex.Match(match.Groups["attrs"].Value).Groups["value"].Value;
            // 末尾が規定のサフィックスなら合格
            if (value.EndsWith(ChartLoadingSuffix, StringComparison.Ordinal)) continue;
            // そうでなければ違反として記録する
            violations.Add(value);
        }

        // canvas が 1 個も見つからないのは想定外(検出パターンが壊れた可能性がある)
        Assert.True(totalCanvases > 0,
            "Views/Analytics/Index.cshtml に <canvas> が 1 つも見つかりませんでした。検出パターンが変更された可能性があります。");
        // 違反ゼロであること(あればどのラベルかをメッセージで示す)
        Assert.True(violations.Count == 0,
            $"分析ページの canvas の初期 aria-label は \"{ChartLoadingSuffix}\" で終わる必要があります " +
            "(JS がこのサフィックスを外してグラフ名を取り出すため):\n" +
            string.Join("\n", violations));
    }

    [Fact]
    public void EveryChartCanvas_AcrossAllViews_HasAccessibleName()
    {
        // 検出した違反(ファイル名とタグ内容)を集める
        var violations = new List<string>();
        // 検査対象の canvas が 1 個も無ければ検出パターンの劣化を疑う
        var totalCanvases = 0;

        // Views 配下のすべての .cshtml を走査する(特定ファイル固定だと将来の追加を見逃すため)
        foreach (var file in RepositoryPaths.EnumerateViewFiles())
        {
            // ビューのソースを読み込む
            var source = File.ReadAllText(file);
            // このファイル内の <canvas> 開始タグをすべて列挙する
            foreach (Match match in CanvasTagRegex.Matches(source))
            {
                totalCanvases++;
                // 属性部分だけを取り出す
                var attrs = match.Groups["attrs"].Value;
                // role="img" と空でない aria-label の両方が揃っていれば合格
                if (RoleImgRegex.IsMatch(attrs) && NonEmptyAriaLabelRegex.IsMatch(attrs)) continue;
                // 揃っていなければ違反として記録する
                violations.Add($"{Path.GetFileName(file)}: <canvas{attrs}>");
            }
        }

        // canvas が 1 個も見つからないのは想定外(検出パターンが壊れた可能性がある)
        Assert.True(totalCanvases > 0,
            "Views 配下に <canvas> が 1 つも見つかりませんでした。検出パターンが変更された可能性があります。");
        // 違反ゼロであること(あればどのファイル・どのタグかをメッセージで示す)
        Assert.True(violations.Count == 0,
            "role=\"img\" と空でない aria-label が付いていない <canvas> があります " +
            "(canvas の中身は支援技術に伝わらないため、グラフに名前を付ける必要があります):\n" +
            string.Join("\n", violations));
    }
}
