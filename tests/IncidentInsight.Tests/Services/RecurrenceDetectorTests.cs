using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;

namespace IncidentInsight.Tests.Services;

public class RecurrenceDetectorTests
{
    private static Incident MakeIncident(int id, string dept, IncidentTypeKind type, params int[] categoryIds)
    {
        var incident = new Incident
        {
            Id = id,
            Department = dept,
            IncidentType = type,
            Severity = IncidentSeverity.Level1,
            Description = "テスト",
            ReporterName = "テスト太郎",
            OccurredAt = DateTime.Now,
            ReportedAt = DateTime.Now
        };
        foreach (var c in categoryIds)
        {
            incident.CauseAnalyses.Add(new CauseAnalysis { CauseCategoryId = c, Why1 = "why1" });
        }
        return incident;
    }

    [Fact]
    public void FindSimilar_ReturnsEmpty_WhenTargetHasNoCauseAnalyses()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication);
        var candidates = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 10) };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Empty(result);
    }

    [Fact]
    public void FindSimilar_ReturnsEmpty_WhenNoCauseCategoryOverlaps()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);
        var candidates = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 20) };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Empty(result);
    }

    [Fact]
    public void FindSimilar_ReturnsMatch_WhenDeptTypeAndCauseOverlap()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10, 11);
        var candidates = new[]
        {
            MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 11),   // match
            MakeIncident(3, "外科病棟", IncidentTypeKind.Medication, 10),   // diff dept
            MakeIncident(4, "内科病棟", IncidentTypeKind.Fall, 10),         // diff type
            MakeIncident(5, "内科病棟", IncidentTypeKind.Medication, 99)    // no overlap
        };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Single(result);
        Assert.Equal(2, result[0].Id);
    }

    [Fact]
    public void FindSimilar_ExcludesTargetItself()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);
        var self = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);

        var result = RecurrenceDetector.FindSimilar(target, new[] { self });

        Assert.Empty(result);
    }
}
