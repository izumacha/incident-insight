// エンティティ(PreventiveMeasure)の計算プロパティを検証するために取り込む
using IncidentInsight.Web.Models;
// 尺度の唯一の真実の源(MeasurePriorityScale)と配色解決(EnumLabels)を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;
// 入力用 ViewModel(MeasureFormViewModel)の属性を調べるために取り込む
using IncidentInsight.Web.Models.ViewModels;
// [Range] / [Display] 属性を参照するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 再発防止策の優先度尺度を一元管理する MeasurePriorityScale の不変条件テスト。
//
// 過去の回帰: 「1=高 / 2=中 / 3=低 の 3 段階」という語彙・許容範囲・既定値・配色が
// PreventiveMeasure・MeasureFormViewModel・4 つの Razor ビューに散在していた。
// 片方だけ段階数や言い回しを変えると、[Range] は新しい段階を受け付けるのに
// ドロップダウンは古い 3 択のまま、といった食い違いが黙って発生する
// (CLAUDE.md §6 定数・ラベルの一元管理 / マジックナンバーを避ける)。
// このテストは「語彙・段階数・既定値・配色はすべて MeasurePriorityScale 由来である」ことを
// 機械的に固定する(EffectivenessScaleTests と同じ役割)。
public class MeasurePriorityScaleTests
{
    [Fact]
    public void All_EnumeratesEveryStepFromMinToMax()
    {
        // 段階の一覧を取り出す
        var steps = MeasurePriorityScale.All.ToList();

        // 下限から上限まで 1 刻みで漏れなく並ぶこと
        Assert.Equal(
            Enumerable.Range(MeasurePriorityScale.Min, MeasurePriorityScale.Max - MeasurePriorityScale.Min + 1),
            steps);
        // 既定値が一覧に含まれること(範囲外だと新規フォームが「選択なし」で開いてしまう)
        Assert.Contains(MeasurePriorityScale.Default, steps);
    }

    [Fact]
    public void Label_ReturnsTheJapaneseWordForEveryStep()
    {
        // 各段階に対応する日本語ラベルが引けること
        Assert.Equal(MeasurePriorityScale.HighLabel, MeasurePriorityScale.Label(MeasurePriorityScale.High));
        Assert.Equal(MeasurePriorityScale.MediumLabel, MeasurePriorityScale.Label(MeasurePriorityScale.Medium));
        Assert.Equal(MeasurePriorityScale.LowLabel, MeasurePriorityScale.Label(MeasurePriorityScale.Low));
    }

    [Fact]
    public void Label_HasNoBlankOrDuplicatedStep()
    {
        // 全段階のラベルを集める
        var labels = MeasurePriorityScale.All.Select(MeasurePriorityScale.Label).ToList();

        // 空のラベルが無いこと(ドロップダウンに選べない空行が出るのを防ぐ)
        Assert.DoesNotContain(labels, string.IsNullOrWhiteSpace);
        // 段階ごとに異なる文言であること(段階を増やして Label の switch を足し忘れると、
        // 新しい段階が UnknownLabel に落ちて既存段階と重複し、ここで落ちる)
        Assert.Equal(labels.Count, labels.Distinct().Count());
        // 範囲内の段階が「不明」表示へフォールバックしていないこと
        Assert.DoesNotContain(MeasurePriorityScale.UnknownLabel, labels);
    }

    [Theory]
    // 境界のすぐ外側は尺度から導出し、段階を増やしたときに「新しく有効になった段階」を
    // 誤って範囲外扱いし続けないようにする(MeasureFormViewModelTests と同じ方針)
    [InlineData(MeasurePriorityScale.Min - 1)]
    [InlineData(MeasurePriorityScale.Max + 1)]
    // 明らかに範囲外の値(境界に依存しないので直値のままでよい)
    [InlineData(-1)]
    public void Label_FallsBackForOutOfRangeValues(int priority)
    {
        // 範囲外の値は中立な記号になること(壊れたデータを正常な優先度に見せない fail-safe)
        Assert.Equal(MeasurePriorityScale.UnknownLabel, MeasurePriorityScale.Label(priority));
    }

    [Fact]
    public void ColorName_ResolvesToADistinctHexForEveryStep()
    {
        // 各段階の色名を 16 進へ解決する
        var hexes = MeasurePriorityScale.All
            .Select(p => EnumLabels.Hex(MeasurePriorityScale.ColorName(p)))
            .ToList();

        // 緊急度を色でも示すため、段階ごとに異なる色であること。
        // EnumLabels.Hex は未知の色名をグレーへフォールバックさせるので、
        // 色名を打ち間違えると複数段階が同じグレーに潰れ、この検査で落ちる
        Assert.Equal(hexes.Count, hexes.Distinct().Count());
    }

    [Fact]
    public void ColorName_ReturnsOnlyBadgeUsableColors()
    {
        // 優先度の配色は Details.cshtml / _MeasureCard.cshtml で
        // <span class="badge bg-@m.PriorityColor"> として使う。Bootstrap のテーマ色でない
        // 色名(拡張パレットの orange 等)を選ぶと .bg-orange クラスが存在せず、
        // 背景色の付かないバッジが静かに描画される。16 進へ解決できるかどうかだけでは
        // これを検出できない(EnumLabels.Hex は orange も解決してしまう)ため、
        // バッジのクラス名として使えることを個別に検査する
        foreach (var priority in MeasurePriorityScale.All)
        {
            // その段階の色名を取り出す
            var colorName = MeasurePriorityScale.ColorName(priority);
            // バッジの bg-* クラスとして成立する色名であること
            Assert.True(
                EnumLabels.IsBadgeUsable(colorName),
                $"優先度 {priority} の配色 '{colorName}' は badge の bg-* クラスとして使えない");
        }

        // 範囲外のフォールバック色もバッジとして成立すること
        // (壊れたデータの行だけバッジが透明になるのを防ぐ)
        Assert.True(EnumLabels.IsBadgeUsable(MeasurePriorityScale.UnknownColorName));
    }

    [Theory]
    // 境界のすぐ外側は尺度から導出する(Label 側の同名検査と揃える)
    [InlineData(MeasurePriorityScale.Min - 1)]
    [InlineData(MeasurePriorityScale.Max + 1)]
    public void ColorName_FallsBackToNeutralForOutOfRangeValues(int priority)
    {
        // 範囲外はグレーに倒し、配色から誤った緊急度を読み取らせないこと。
        // 期待値も尺度の定数から引き、フォールバック色を変えたときに
        // ここだけ古い色名を主張し続けないようにする
        Assert.Equal(MeasurePriorityScale.UnknownColorName, MeasurePriorityScale.ColorName(priority));
    }

    [Fact]
    public void PreventiveMeasure_PriorityMembers_DelegateToTheScale()
    {
        // 既定値のまま生成した対策は尺度の既定値を持つこと
        Assert.Equal(MeasurePriorityScale.Default, new PreventiveMeasure().Priority);

        // すべての段階でラベル・配色が尺度の実装と一致すること(委譲が外れていないことの確認)
        foreach (var priority in MeasurePriorityScale.All)
        {
            // 対象の優先度を持つ対策を組み立てる
            var measure = new PreventiveMeasure { Priority = priority };
            // ラベルが尺度由来であること
            Assert.Equal(MeasurePriorityScale.Label(priority), measure.PriorityLabel);
            // 配色が尺度由来であること
            Assert.Equal(MeasurePriorityScale.ColorName(priority), measure.PriorityColor);
        }
    }

    [Fact]
    public void PreventiveMeasure_RangeAndDisplay_ComeFromTheScale()
    {
        // エンティティ側の優先度プロパティの属性を取り出す
        var property = typeof(PreventiveMeasure).GetProperty(nameof(PreventiveMeasure.Priority))!;

        // [Range] の上下限が尺度と一致すること
        var range = property.GetCustomAttributes(typeof(RangeAttribute), false).Cast<RangeAttribute>().Single();
        Assert.Equal(MeasurePriorityScale.Min, range.Minimum);
        Assert.Equal(MeasurePriorityScale.Max, range.Maximum);

        // [Display] の表示名が尺度から引かれていること
        var display = property.GetCustomAttributes(typeof(DisplayAttribute), false).Cast<DisplayAttribute>().Single();
        Assert.Equal(MeasurePriorityScale.DisplayName, display.Name);
    }

    [Fact]
    public void MeasureFormViewModel_RangeAndDisplay_ComeFromTheScale()
    {
        // 入力用 ViewModel の優先度プロパティの属性を取り出す
        var property = typeof(MeasureFormViewModel).GetProperty(nameof(MeasureFormViewModel.Priority))!;

        // [Range] の上下限がエンティティ側と同じ尺度から来ていること
        // (片方だけ広げると、画面は通るのに保存できない値を入力させてしまう)
        var range = property.GetCustomAttributes(typeof(RangeAttribute), false).Cast<RangeAttribute>().Single();
        Assert.Equal(MeasurePriorityScale.Min, range.Minimum);
        Assert.Equal(MeasurePriorityScale.Max, range.Maximum);
        Assert.Equal(MeasurePriorityScale.RangeMessage, range.ErrorMessage);

        // [Display] の表示名が尺度から引かれていること
        var display = property.GetCustomAttributes(typeof(DisplayAttribute), false).Cast<DisplayAttribute>().Single();
        Assert.Equal(MeasurePriorityScale.DisplayName, display.Name);

        // 新規フォームの初期値が尺度の既定値であること
        Assert.Equal(MeasurePriorityScale.Default, new MeasureFormViewModel().Priority);
    }

    // RangeMessage は属性の引数として使うため const でなければならず、C# の定数式では
    // 数値を文字列へ変換できないので Min / Max を文中に直書きしている。段階数だけ変えて
    // 文言を直し忘れると、画面に「1(高)〜3(低)」と出たまま実際は別の範囲を受け付ける、
    // という食い違いが起きる。ここでその取りこぼしを CI で検知する
    // (EffectivenessScaleTests の同名検査と同じ趣旨)。
    [Fact]
    public void RangeMessage_StillMatchesTheActualBounds()
    {
        // メッセージが実際の下限とそのラベルを含んでいること
        Assert.Contains($"{MeasurePriorityScale.Min}({MeasurePriorityScale.Label(MeasurePriorityScale.Min)})",
            MeasurePriorityScale.RangeMessage);
        // メッセージが実際の上限とそのラベルを含んでいること
        Assert.Contains($"{MeasurePriorityScale.Max}({MeasurePriorityScale.Label(MeasurePriorityScale.Max)})",
            MeasurePriorityScale.RangeMessage);
    }
}
