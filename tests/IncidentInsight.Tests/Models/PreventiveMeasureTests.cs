using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;

namespace IncidentInsight.Tests.Models;

public class PreventiveMeasureTests
{
    // テスト内で使う固定の「今日」— DateTime.Today 直呼びを避け決定論的テストにするため固定値を使う
    private static readonly DateTime Today = new DateTime(2026, 6, 11);

    // --- IsOverdueOn ---

    [Fact]
    public void IsOverdueOn_PlannedPastDue_ReturnsTrue()
    {
        // 期限を今日の1日前に設定し、計画中ステータスで期限超過になることを確認する
        var m = new PreventiveMeasure { Status = MeasureStatus.Planned, DueDate = Today.AddDays(-1) };
        // IsOverdueOnに固定の今日を渡して期限超過と判定されるか検証する
        Assert.True(m.IsOverdueOn(Today));
    }

    [Fact]
    public void IsOverdueOn_Completed_ReturnsFalse_EvenIfPastDue()
    {
        // 完了済みは期限を過ぎていても超過扱いにならないことを確認する（完了後は期限無効）
        var m = new PreventiveMeasure { Status = MeasureStatus.Completed, DueDate = Today.AddDays(-30) };
        // 完了済みなのでfalseが返るはずと検証する
        Assert.False(m.IsOverdueOn(Today));
    }

    [Fact]
    public void IsOverdueOn_DueTodayOrFuture_ReturnsFalse()
    {
        // 期限が今日ちょうどの場合は超過扱いにならない（境界値テスト）
        var m = new PreventiveMeasure { Status = MeasureStatus.Planned, DueDate = Today };
        // DueDate == today なので超過ではなくfalseであることを検証する
        Assert.False(m.IsOverdueOn(Today));
    }

    // --- StatusLabel / StatusColorOn ---

    [Theory]
    [InlineData(MeasureStatus.Planned, "計画中")]
    [InlineData(MeasureStatus.InProgress, "進行中")]
    [InlineData(MeasureStatus.Completed, "完了")]
    public void StatusLabel_IsCorrect(MeasureStatus status, string expected)
    {
        // 各ステータスに対応する日本語ラベルが正しく返るかを検証する
        var m = new PreventiveMeasure { Status = status, DueDate = Today.AddDays(10) };
        // StatusLabel プロパティが期待文字列と一致することを確認する
        Assert.Equal(expected, m.StatusLabel);
    }

    [Fact]
    public void StatusColorOn_Planned_NotOverdue_IsWarning()
    {
        // 計画中かつ期限内（5日後）の場合は警告色(warning)になることを確認する
        var m = new PreventiveMeasure { Status = MeasureStatus.Planned, DueDate = Today.AddDays(5) };
        // StatusColorOnに固定の今日を渡して"warning"が返るか検証する
        Assert.Equal("warning", m.StatusColorOn(Today));
    }

    [Fact]
    public void StatusColorOn_Planned_Overdue_IsDanger()
    {
        // 計画中かつ期限超過（昨日が期限）の場合は危険色(danger)になることを確認する
        var m = new PreventiveMeasure { Status = MeasureStatus.Planned, DueDate = Today.AddDays(-1) };
        // StatusColorOnに固定の今日を渡して"danger"が返るか検証する
        Assert.Equal("danger", m.StatusColorOn(Today));
    }

    [Fact]
    public void StatusColorOn_Completed_IsSuccess()
    {
        // 完了済みは期限超過でも成功色(success)になることを確認する
        var m = new PreventiveMeasure { Status = MeasureStatus.Completed, DueDate = Today.AddDays(-1) };
        // StatusColorOnに固定の今日を渡して"success"が返るか検証する
        Assert.Equal("success", m.StatusColorOn(Today));
    }

    // --- PriorityLabel / PriorityColor ---

    [Theory]
    [InlineData(1, "高", "danger")]
    [InlineData(2, "中", "warning")]
    [InlineData(3, "低", "secondary")]
    public void PriorityLabel_And_Color_AreCorrect(int priority, string expectedLabel, string expectedColor)
    {
        // 優先度数値（1=高,2=中,3=低）に対応するラベルと色が正しいか検証する
        var m = new PreventiveMeasure { Priority = priority };
        // PriorityLabel が期待ラベルと一致するか確認する
        Assert.Equal(expectedLabel, m.PriorityLabel);
        // PriorityColor が期待色と一致するか確認する
        Assert.Equal(expectedColor, m.PriorityColor);
    }

    // --- EffectivenessStars ---

    [Fact]
    public void EffectivenessStars_NoRating_Returns未評価()
    {
        // 有効性評価が未設定（null）のとき「未評価」文字列が返ることを確認する
        var m = new PreventiveMeasure { EffectivenessRating = null };
        // EffectivenessStars プロパティが"未評価"を返すか検証する
        Assert.Equal("未評価", m.EffectivenessStars);
    }

    [Theory]
    [InlineData(1, "★☆☆☆☆")]
    [InlineData(3, "★★★☆☆")]
    [InlineData(5, "★★★★★")]
    public void EffectivenessStars_WithRating_ShowsCorrectStars(int rating, string expected)
    {
        // 評価値に応じた星文字列（★☆の組み合わせ）が正しく返るか検証する
        var m = new PreventiveMeasure { EffectivenessRating = rating };
        // EffectivenessStars プロパティが期待星文字列と一致するか確認する
        Assert.Equal(expected, m.EffectivenessStars);
    }

    // --- MeasureTypeLabel / MeasureTypeColor ---

    [Fact]
    public void MeasureTypeLabel_ShortTerm_IsCorrect()
    {
        // 短期対策タイプのラベルと色が正しいことを確認する
        var m = new PreventiveMeasure { MeasureType = MeasureTypeKind.ShortTerm };
        // 短期対策のラベルが"短期対策"であることを検証する
        Assert.Equal("短期対策", m.MeasureTypeLabel);
        // 短期対策の色が"success"であることを検証する
        Assert.Equal("success", m.MeasureTypeColor);
    }

    [Fact]
    public void MeasureTypeLabel_LongTerm_IsCorrect()
    {
        // 長期対策タイプのラベルと色が正しいことを確認する
        var m = new PreventiveMeasure { MeasureType = MeasureTypeKind.LongTerm };
        // 長期対策のラベルが"長期対策"であることを検証する
        Assert.Equal("長期対策", m.MeasureTypeLabel);
        // 長期対策の色が"info"であることを検証する
        Assert.Equal("info", m.MeasureTypeColor);
    }
}
