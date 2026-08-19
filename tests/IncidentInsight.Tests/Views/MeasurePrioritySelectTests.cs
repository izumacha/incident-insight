// 正規表現で Razor ビューのソースを走査するために取り込む
using System.Text.RegularExpressions;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// 尺度の唯一の真実の源(MeasurePriorityScale)の型名を検出語に使うために取り込む
using IncidentInsight.Web.Models.Enums;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Views;

// Guard-rail tests: 再発防止策の「優先度」ドロップダウンが、段階とラベルを
// MeasurePriorityScale(尺度の唯一の源)から生成していることを検査する。
//
// 過去の回帰: 4 つのビュー(Incidents/Create・Incidents/Details・
// PreventiveMeasures/Create・PreventiveMeasures/Edit)がいずれも
// <option value="1">高</option> を手書きしていた。段階を増やしても [Range] だけが広がり、
// 画面からは新しい段階を選べないまま、というズレが黙って発生する
// (CLAUDE.md §6 定数・ラベルの一元管理)。ラベルの言い換えも同様に取りこぼす。
// 単体テストでは View の直書きを検出できないため、View ソースを直接走査して防ぐ。
public class MeasurePrioritySelectTests
{
    // 優先度ドロップダウンの期待検出数。4 つのビューに 1 つずつ存在する。
    // 走査が空振りしても緑になってしまうのを防ぐため下限として使う
    // (ConcurrencyTokenFormTests / ChartAccessibilityTests と同じ空振り対策)
    private const int ExpectedPrioritySelectCount = 4;

    // <select ...> ... </select> のブロック全体を(改行を跨いで)抜き出す正規表現
    private static readonly Regex SelectBlockRegex =
        new(@"<select\b(?<attrs>[^>]*)>(?<body>.*?)</select>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

    // 値が数値リテラルで直書きされた <option>(例: <option value="1">)を検出する正規表現。
    // 尺度から生成していれば value は @p のような Razor 式になるので数字は現れない
    private static readonly Regex HardCodedOptionValueRegex =
        new(@"<option\b[^>]*\bvalue\s*=\s*""\d+""", RegexOptions.IgnoreCase);

    [Fact]
    public void PrioritySelects_BuildOptionsFromTheScale()
    {
        // リポジトリ内の Views ディレクトリを特定する
        var viewsDir = RepositoryPaths.Views;
        // 検出した違反(ファイル名と理由)を集める
        var violations = new List<string>();
        // 検査した優先度ドロップダウンの数を数える(空振り検知用)
        var inspectedSelects = 0;

        // すべての Razor ビューを走査する
        foreach (var file in Directory.EnumerateFiles(viewsDir, "*.cshtml", SearchOption.AllDirectories))
        {
            // ビューのソースを読み込む
            var source = File.ReadAllText(file);
            // ファイル内の <select> ブロックを列挙する
            foreach (Match select in SelectBlockRegex.Matches(source))
            {
                // 開きタグの属性部分(asp-for / name がここに現れる)
                var attrs = select.Groups["attrs"].Value;
                // 優先度にバインドされた <select> だけを対象にする
                if (!BindsToPriority(attrs)) continue;

                // 検査対象を 1 つ数える
                inspectedSelects++;
                // <option> を生成している本体部分
                var body = select.Groups["body"].Value;
                // リポジトリルートからの相対パス(違反メッセージを読みやすくするため)
                var relativePath = Path.GetRelativePath(RepositoryPaths.Root, file);

                // 尺度を参照せずに選択肢を組み立てていないか
                if (!body.Contains(nameof(MeasurePriorityScale), StringComparison.Ordinal))
                {
                    violations.Add($"{relativePath}: 優先度の <select> が {nameof(MeasurePriorityScale)} を参照していない");
                }

                // 値を数値リテラルで直書きしていないか
                if (HardCodedOptionValueRegex.IsMatch(body))
                {
                    violations.Add($"{relativePath}: 優先度の <option value=\"...\"> に段階の数値が直書きされている");
                }
            }
        }

        // 検出パターンが壊れて 1 件も拾えていない状態を「違反なし」と誤認しないようにする
        Assert.True(
            inspectedSelects >= ExpectedPrioritySelectCount,
            $"優先度の <select> を {inspectedSelects} 件しか検出できなかった"
            + $"(期待: {ExpectedPrioritySelectCount} 件以上)。検出パターンが実装とずれていないか確認すること");

        // 違反があればファイル名付きで報告する
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }

    // <select> の属性が再発防止策の優先度にバインドされているかを判定する。
    // asp-for="Priority" / asp-for="NewMeasure.Priority" / name="Measures[0].Priority" の
    // いずれの書き方でも拾えるよう、プロパティ名で終わっているかを見る
    private static bool BindsToPriority(string attrs)
    {
        // 属性値(ダブルクォートで囲まれた部分)を順に取り出す
        foreach (Match value in Regex.Matches(attrs, "\"(?<v>[^\"]*)\""))
        {
            // 属性値の中身を取り出す
            var text = value.Groups["v"].Value;
            // "Priority" そのもの、または "....Priority" の形なら優先度へのバインドとみなす
            if (text == PriorityPropertyName || text.EndsWith("." + PriorityPropertyName, StringComparison.Ordinal))
            {
                return true;
            }
        }
        // どの属性値も優先度を指していなかった
        return false;
    }

    // バインド先プロパティ名(PreventiveMeasure.Priority / MeasureFormViewModel.Priority と対応)
    private const string PriorityPropertyName = nameof(Web.Models.PreventiveMeasure.Priority);
}
