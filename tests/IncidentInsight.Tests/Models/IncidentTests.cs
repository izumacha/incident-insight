using IncidentInsight.Web.Models;
using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Tests.Models;

public class IncidentTests
{
    // --- SeverityLabel / SeverityColor ---

    [Theory]
    [InlineData("Level0", "レベル0 (ヒヤリハット)", "secondary")]
    [InlineData("Level1", "レベル1 (患者への影響なし)", "info")]
    [InlineData("Level3a", "レベル3a (軽微な処置)", "warning")]
    [InlineData("Level5", "レベル5 (死亡)", "dark")]
    public void SeverityLabel_And_Color_AreCorrect(string severity, string expectedLabel, string expectedColor)
    {
        var incident = new Incident { Severity = severity };
        Assert.Equal(expectedLabel, incident.SeverityLabel);
        Assert.Equal(expectedColor, incident.SeverityColor);
    }

    [Fact]
    public void SeverityLabel_UnknownValue_ReturnsSeverityAsIs()
    {
        var incident = new Incident { Severity = "Unknown" };
        Assert.Equal("Unknown", incident.SeverityLabel);
        Assert.Equal("secondary", incident.SeverityColor);
    }

    // --- MeasureStatusSummary ---

    [Fact]
    public void MeasureStatusSummary_NoMeasures_Returns未登録()
    {
        var incident = new Incident();
        Assert.Equal("未登録", incident.MeasureStatusSummary);
    }

    [Fact]
    public void MeasureStatusSummary_AllCompleted_Returns完了()
    {
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                new() { Status = "Completed", DueDate = DateTime.Today.AddDays(10) },
                new() { Status = "Completed", DueDate = DateTime.Today.AddDays(5) }
            }
        };
        Assert.Equal("完了", incident.MeasureStatusSummary);
    }

    [Fact]
    public void MeasureStatusSummary_AnyOverdue_Returns期限超過()
    {
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                new() { Status = "Planned", DueDate = DateTime.Today.AddDays(-1) }
            }
        };
        Assert.Equal("期限超過", incident.MeasureStatusSummary);
    }

    [Fact]
    public void MeasureStatusSummary_InProgressNotOverdue_Returns進行中()
    {
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                new() { Status = "InProgress", DueDate = DateTime.Today.AddDays(5) }
            }
        };
        Assert.Equal("進行中", incident.MeasureStatusSummary);
    }

    [Fact]
    public void MeasureStatusSummary_OnlyPlanned_Returns計画中()
    {
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                new() { Status = "Planned", DueDate = DateTime.Today.AddDays(10) }
            }
        };
        Assert.Equal("計画中", incident.MeasureStatusSummary);
    }

    // --- Validation ---

    [Fact]
    public void Incident_MissingRequired_FailsValidation()
    {
        var incident = new Incident { Department = "", IncidentType = "", ReporterName = "" };
        var results = new List<ValidationResult>();
        var ctx = new ValidationContext(incident);
        Validator.TryValidateObject(incident, ctx, results, true);

        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        Assert.Contains("Department", failedFields);
        Assert.Contains("IncidentType", failedFields);
        Assert.Contains("ReporterName", failedFields);
        Assert.Contains("Description", failedFields);
    }

    [Fact]
    public void Incident_AllRequired_PassesValidation()
    {
        var incident = new Incident
        {
            OccurredAt = DateTime.Now,
            Department = "内科病棟",
            IncidentType = "投薬ミス",
            Severity = "Level2",
            Description = "患者AにBさんの薬を投与した",
            ReporterName = "山田 花子"
        };
        var results = new List<ValidationResult>();
        var ctx = new ValidationContext(incident);
        var isValid = Validator.TryValidateObject(incident, ctx, results, true);

        Assert.True(isValid);
        Assert.Empty(results);
    }
}
