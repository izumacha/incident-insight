// エンティティ(PreventiveMeasure)の星表示を検証するために取り込む
using IncidentInsight.Web.Models;
// 尺度の唯一の真実の源(EffectivenessScale)と配色解決(EnumLabels)を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;
// 入力用 ViewModel(ReviewViewModel)の属性を調べるために取り込む
using IncidentInsight.Web.Models.ViewModels;
// [Range] / [Display] 属性を参照するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 有効性評価の尺度を一元管理する EffectivenessScale の不変条件テスト。
//
// 過去の回帰: 「1〜5 の 5 段階」「効果なし / 普通 / 非常に効果あり」という語彙と、
// 段階ごとの配色が AnalyticsController・Review.cshtml・Details.cshtml・ReviewViewModel・
// analytics.ts の 5 箇所に散在していた。片方だけ言い回しや段階数を変えると、
// 同じ評価が画面ごとに違う名前・違う色で表示される(CLAUDE.md §6 定数・ラベルの一元管理)。
// このテストは「語彙・段階数・配色はすべて EffectivenessScale 由来である」ことを機械的に固定する。
public class EffectivenessScaleTests
{
    [Fact]
    public void All_EnumeratesEveryStepFromMinToMax()
    {
        // 段階の一覧を取り出す
        var steps = EffectivenessScale.All.ToList();

        // 下限から上限まで 1 刻みで漏れなく並ぶこと
        Assert.Equal(Enumerable.Range(EffectivenessScale.Min, EffectivenessScale.Max - EffectivenessScale.Min + 1), steps);
        // 中央値が一覧に含まれること(初期選択に使うため、範囲外だと選択なしで画面が開いてしまう)
        Assert.Contains(EffectivenessScale.Middle, steps);
    }

    [Fact]
    public void ChartLabel_AnnotatesOnlyTheDescribedSteps()
    {
        // 端点・中央値には説明が括弧付きで入ること
        Assert.Equal($"★{EffectivenessScale.Min} ({EffectivenessScale.LowestDescription})",
            EffectivenessScale.ChartLabel(EffectivenessScale.Min));
        Assert.Equal($"★{EffectivenessScale.Middle} ({EffectivenessScale.MiddleDescription})",
            EffectivenessScale.ChartLabel(EffectivenessScale.Middle));
        Assert.Equal($"★{EffectivenessScale.Max} ({EffectivenessScale.HighestDescription})",
            EffectivenessScale.ChartLabel(EffectivenessScale.Max));
        // 説明を持たない段階は星と数字だけになること
        Assert.Equal("★2", EffectivenessScale.ChartLabel(2));
    }

    [Fact]
    public void ColorName_ResolvesToADistinctHexForEveryStep()
    {
        // 各段階の色名を 16 進へ解決する
        var hexes = EffectivenessScale.All
            .Select(r => EnumLabels.Hex(EffectivenessScale.ColorName(r)))
            .ToList();

        // 「悪い→良い」を色でも示すため、段階ごとに異なる色であること。
        // EnumLabels.Hex は未知の色名をグレーへフォールバックさせるので、
        // 色名を打ち間違えると複数段階が同じグレーに潰れ、この検査で落ちる
        Assert.Equal(hexes.Count, hexes.Distinct().Count());
        // フォールバック(secondary)に落ちた段階が無いこと
        Assert.DoesNotContain(EnumLabels.Hex("secondary"), hexes);
    }

    [Theory]
    // 範囲外の下側は「塗りつぶし星 0 個」へ丸める(★1 相当と読ませない)
    [InlineData(-1, "☆☆☆☆☆")]
    // 0 も同様に星 0 個
    [InlineData(0, "☆☆☆☆☆")]
    // 下限
    [InlineData(1, "★☆☆☆☆")]
    // 中央値
    [InlineData(3, "★★★☆☆")]
    // 上限
    [InlineData(5, "★★★★★")]
    // 範囲外の上側は上限へ丸める(星が 5 個を超えて崩れない)
    [InlineData(9, "★★★★★")]
    public void Stars_ClampsOutOfRangeValues(int rating, string expected)
    {
        // 星表記が想定どおりであること
        Assert.Equal(expected, EffectivenessScale.Stars(rating));
    }

    [Fact]
    public void Stars_ReturnsUnratedTextForNull()
    {
        // 未評価は専用の文言になること
        Assert.Equal(EffectivenessScale.UnratedText, EffectivenessScale.Stars(null));
        // エンティティ側の計算プロパティも同じ結果を返すこと(実装の委譲が外れていないことの確認)
        Assert.Equal(EffectivenessScale.UnratedText, new PreventiveMeasure().EffectivenessStars);
    }

    [Fact]
    public void PreventiveMeasure_EffectivenessStars_DelegatesToTheScale()
    {
        // 評価済みの対策を用意する
        var measure = new PreventiveMeasure { EffectivenessRating = EffectivenessScale.Middle };

        // エンティティの星表記が尺度の実装と一致すること
        Assert.Equal(EffectivenessScale.Stars(EffectivenessScale.Middle), measure.EffectivenessStars);
    }

    [Fact]
    public void ReviewViewModel_RangeAndDisplay_ComeFromTheScale()
    {
        // 有効性評価プロパティの属性を取り出す
        var property = typeof(ReviewViewModel).GetProperty(nameof(ReviewViewModel.EffectivenessRating))!;

        // [Range] の上下限が尺度と一致すること(片方だけ広げると保存できない値を入力させてしまう)
        var range = property.GetCustomAttributes(typeof(RangeAttribute), false).Cast<RangeAttribute>().Single();
        Assert.Equal(EffectivenessScale.Min, range.Minimum);
        Assert.Equal(EffectivenessScale.Max, range.Maximum);
        Assert.Equal(EffectivenessScale.RangeMessage, range.ErrorMessage);

        // [Display] の表示名が尺度から組み立てたものであること
        var display = property.GetCustomAttributes(typeof(DisplayAttribute), false).Cast<DisplayAttribute>().Single();
        Assert.Equal(EffectivenessScale.DisplayName, display.Name);
    }

    [Fact]
    public void HintText_ListsTheDescribedStepsInAscendingOrder()
    {
        // 凡例が「値=説明」を昇順で並べたものであること
        Assert.Equal(
            $"{EffectivenessScale.Min}={EffectivenessScale.LowestDescription}"
            + $" / {EffectivenessScale.Middle}={EffectivenessScale.MiddleDescription}"
            + $" / {EffectivenessScale.Max}={EffectivenessScale.HighestDescription}",
            EffectivenessScale.HintText);
    }
}
