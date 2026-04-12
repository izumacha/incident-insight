using IncidentInsight.Web.Models;

namespace IncidentInsight.Tests.Models;

public class PreventiveMeasureTests
{
    // --- IsOverdue ---

    [Fact]
    public void IsOverdue_PlannedPastDue_ReturnsTrue()
    {
        var m = new PreventiveMeasure { Status = "Planned", DueDate = DateTime.Today.AddDays(-1) };
        Assert.True(m.IsOverdue);
    }

    [Fact]
    public void IsOverdue_Completed_ReturnsFalse_EvenIfPastDue()
    {
        var m = new PreventiveMeasure { Status = "Completed", DueDate = DateTime.Today.AddDays(-30) };
        Assert.False(m.IsOverdue);
    }

    [Fact]
    public void IsOverdue_DueTodayOrFuture_ReturnsFalse()
    {
        var m = new PreventiveMeasure { Status = "Planned", DueDate = DateTime.Today };
        Assert.False(m.IsOverdue);
    }

    // --- StatusLabel / StatusColor ---

    [Theory]
    [InlineData("Planned", "計画中")]
    [InlineData("InProgress", "進行中")]
    [InlineData("Completed", "完了")]
    public void StatusLabel_IsCorrect(string status, string expected)
    {
        var m = new PreventiveMeasure { Status = status, DueDate = DateTime.Today.AddDays(10) };
        Assert.Equal(expected, m.StatusLabel);
    }

    [Fact]
    public void StatusColor_Planned_NotOverdue_IsWarning()
    {
        var m = new PreventiveMeasure { Status = "Planned", DueDate = DateTime.Today.AddDays(5) };
        Assert.Equal("warning", m.StatusColor);
    }

    [Fact]
    public void StatusColor_Planned_Overdue_IsDanger()
    {
        var m = new PreventiveMeasure { Status = "Planned", DueDate = DateTime.Today.AddDays(-1) };
        Assert.Equal("danger", m.StatusColor);
    }

    [Fact]
    public void StatusColor_Completed_IsSuccess()
    {
        var m = new PreventiveMeasure { Status = "Completed", DueDate = DateTime.Today.AddDays(-1) };
        Assert.Equal("success", m.StatusColor);
    }

    // --- PriorityLabel / PriorityColor ---

    [Theory]
    [InlineData(1, "高", "danger")]
    [InlineData(2, "中", "warning")]
    [InlineData(3, "低", "secondary")]
    public void PriorityLabel_And_Color_AreCorrect(int priority, string expectedLabel, string expectedColor)
    {
        var m = new PreventiveMeasure { Priority = priority };
        Assert.Equal(expectedLabel, m.PriorityLabel);
        Assert.Equal(expectedColor, m.PriorityColor);
    }

    // --- EffectivenessStars ---

    [Fact]
    public void EffectivenessStars_NoRating_Returns未評価()
    {
        var m = new PreventiveMeasure { EffectivenessRating = null };
        Assert.Equal("未評価", m.EffectivenessStars);
    }

    [Theory]
    [InlineData(1, "★☆☆☆☆")]
    [InlineData(3, "★★★☆☆")]
    [InlineData(5, "★★★★★")]
    public void EffectivenessStars_WithRating_ShowsCorrectStars(int rating, string expected)
    {
        var m = new PreventiveMeasure { EffectivenessRating = rating };
        Assert.Equal(expected, m.EffectivenessStars);
    }

    // --- MeasureTypeLabel / MeasureTypeColor ---

    [Fact]
    public void MeasureTypeLabel_ShortTerm_IsCorrect()
    {
        var m = new PreventiveMeasure { MeasureType = "ShortTerm" };
        Assert.Equal("短期対策", m.MeasureTypeLabel);
        Assert.Equal("success", m.MeasureTypeColor);
    }

    [Fact]
    public void MeasureTypeLabel_LongTerm_IsCorrect()
    {
        var m = new PreventiveMeasure { MeasureType = "LongTerm" };
        Assert.Equal("長期対策", m.MeasureTypeLabel);
        Assert.Equal("info", m.MeasureTypeColor);
    }
}
