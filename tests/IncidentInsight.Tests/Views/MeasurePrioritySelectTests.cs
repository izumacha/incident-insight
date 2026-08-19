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

    // <option ...>本文</option> を 1 つずつ抜き出す正規表現(属性と表示文言を別々に検査するため)
    private static readonly Regex OptionBlockRegex =
        new(@"<option\b(?<attrs>[^>]*)>(?<body>.*?)</option>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

    // 値が数値リテラルで直書きされた <option>(例: <option value="1">)を検出する正規表現。
    // 尺度から生成していれば value は @p のような Razor 式になるので数字は現れない
    // 属性値は HTML/Razor では単一引用符でも書けるため、どちらの引用符でも拾えるようにする。
    // 二重引用符しか見ていないと、単一引用符で書かれた <select>/<option> がまるごと
    // 検査対象から外れ、直書きの 3 択がそのまま出荷されてしまう
    private static readonly Regex HardCodedOptionValueRegex =
        new(@"\bvalue\s*=\s*(""\d+""|'\d+')", RegexOptions.IgnoreCase);

    // value="" の空 option(絞り込みフォームの「すべて」行)を検出する正規表現
    private static readonly Regex BlankOptionValueRegex =
        new(@"\bvalue\s*=\s*(""\s*""|'\s*')", RegexOptions.IgnoreCase);

    // 属性値(二重引用符または単一引用符で囲まれた部分)を取り出す正規表現
    private static readonly Regex AttributeValueRegex =
        new(@"""(?<v>[^""]*)""|'(?<v>[^']*)'", RegexOptions.IgnoreCase);

    // ラベルを解決する唯一の入口。<option> の表示文言はここを通っていなければならない
    private const string LabelCallLiteral = nameof(MeasurePriorityScale) + "." + nameof(MeasurePriorityScale.Label) + "(";

    // 段階を列挙する唯一の入口。<select> の本体はここを回していなければならない
    private const string AllEnumerationLiteral = nameof(MeasurePriorityScale) + "." + nameof(MeasurePriorityScale.All);

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

                // 段階の列挙自体を尺度から回していないか(All を使わず option を並べていないか)
                if (!body.Contains(AllEnumerationLiteral, StringComparison.Ordinal))
                {
                    violations.Add($"{relativePath}: 優先度の <select> が {AllEnumerationLiteral} で段階を列挙していない");
                }

                // <option> を 1 つずつ検査する。value(段階の数値)と本文(表示ラベル)は
                // 別々に直書きされうるため、両方を個別に見る
                foreach (Match option in OptionBlockRegex.Matches(body))
                {
                    // 属性部分(value がここに現れる)
                    var optionAttrs = option.Groups["attrs"].Value;

                    // 「未選択」を表す value="" の空 option は段階そのものではないので検査対象外。
                    // 絞り込みフォームの先頭に置く <option value="">優先度(全て)</option> を
                    // ラベル未経由として誤検出しないための除外
                    if (BlankOptionValueRegex.IsMatch(optionAttrs)) continue;

                    // 値を数値リテラルで直書きしていないか
                    if (HardCodedOptionValueRegex.IsMatch(optionAttrs))
                    {
                        violations.Add($"{relativePath}: 優先度の <option value=\"...\"> に段階の数値が直書きされている");
                    }

                    // 表示ラベルを尺度から引かずに直書きしていないか。
                    // value だけ @p に直しつつ本文を三項演算子で「高/中/低」と書くような
                    // 書き換えは、数値の検査だけでは素通りしてしまう
                    if (!option.Groups["body"].Value.Contains(LabelCallLiteral, StringComparison.Ordinal))
                    {
                        violations.Add($"{relativePath}: 優先度の <option> の表示ラベルが {LabelCallLiteral}…) を経由していない");
                    }
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
    // いずれの書き方でも拾えるよう、プロパティ名で終わっているかを見る。
    // 比較は大文字小文字を無視する: 一覧の絞り込み <select> はクエリ文字列のパラメータ名に
    // 合わせて name="priority" のような小文字始まりで書く慣習(Views/Incidents/Index.cshtml の
    // name="incidentType" / name="severity" 等)があり、Ordinal 比較だと将来の優先度フィルタが
    // まるごと検査対象から漏れてしまうため
    private static bool BindsToPriority(string attrs)
    {
        // 属性値(二重引用符・単一引用符いずれかで囲まれた部分)を順に取り出す
        foreach (Match value in AttributeValueRegex.Matches(attrs))
        {
            // 属性値の中身を取り出す
            var text = value.Groups["v"].Value;
            // "Priority" そのもの、または "....Priority" の形なら優先度へのバインドとみなす
            if (text.Equals(PriorityPropertyName, StringComparison.OrdinalIgnoreCase)
                || text.EndsWith("." + PriorityPropertyName, StringComparison.OrdinalIgnoreCase))
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
