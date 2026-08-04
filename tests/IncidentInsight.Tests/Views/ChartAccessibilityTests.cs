// 正規表現で View ソースを走査するために取り込む
using System.Text.RegularExpressions;

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

    [Fact]
    public void EveryChartCanvas_AcrossAllViews_HasAccessibleName()
    {
        // 検出した違反(ファイル名とタグ内容)を集める
        var violations = new List<string>();
        // 検査対象の canvas が 1 個も無ければ検出パターンの劣化を疑う
        var totalCanvases = 0;

        // Views 配下のすべての .cshtml を走査する(特定ファイル固定だと将来の追加を見逃すため)
        foreach (var file in Directory.EnumerateFiles(FindViewsDirectory(), "*.cshtml", SearchOption.AllDirectories))
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

    // テスト実行ディレクトリから上へ辿り src/IncidentInsight.Web/Views を見つける
    // (RoleGatedNavigationTests / ConcurrencyTokenFormTests と同じ探索ロジック)
    private static string FindViewsDirectory()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ルートに達するまで親を遡る
        while (dir != null)
        {
            // リポジトリルート配下の Views ディレクトリ候補を組み立てる
            var candidate = Path.Combine(dir.FullName, "src", "IncidentInsight.Web", "Views");
            // Views ディレクトリが見つかればそれを返す
            if (Directory.Exists(candidate)) return candidate;
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException("src/IncidentInsight.Web/Views がテスト実行位置から見つかりません。");
    }
}
