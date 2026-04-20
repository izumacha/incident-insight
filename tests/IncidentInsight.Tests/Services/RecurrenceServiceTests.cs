using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Services;

public class RecurrenceServiceTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly RecurrenceService _svc;

    public RecurrenceServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _svc = new RecurrenceService(new SystemClock());
    }

    public void Dispose() => _db.Dispose();

    private static Incident MakeIncident(string dept, IncidentTypeKind type, DateTime occurredAt)
        => new()
        {
            Department = dept,
            IncidentType = type,
            Severity = IncidentSeverity.Level1,
            Description = "テスト",
            ReporterName = "テスト太郎",
            OccurredAt = occurredAt,
            ReportedAt = occurredAt
        };

    [Fact]
    public async Task FindRecurrencesForIncident_ReturnsSimilar_SameDeptTypeCauseOverlap()
    {
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat);
        await _db.SaveChangesAsync();

        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-5));
        var match = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-30));
        var diffDept = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        var diffType = MakeIncident("内科病棟", IncidentTypeKind.Fall, DateTime.Today.AddDays(-10));
        _db.Incidents.AddRange(target, match, diffDept, diffType);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = target.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = match.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = diffDept.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = diffType.Id, CauseCategoryId = cat.Id, Why1 = "w1" }
        );
        await _db.SaveChangesAsync();

        // Reload target with CauseAnalyses so the service sees the in-memory collection populated.
        var loaded = await _db.Incidents
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .FirstAsync(i => i.Id == target.Id);

        var result = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        Assert.Single(result);
        Assert.Equal(match.Id, result[0].Id);
    }

    [Fact]
    public async Task FindRecurrencesForIncident_AppliesTimeWindow_WhenWithinProvided()
    {
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat);
        await _db.SaveChangesAsync();

        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today);
        var inWindow = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        var outOfWindow = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-120));
        _db.Incidents.AddRange(target, inWindow, outOfWindow);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = target.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = inWindow.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = outOfWindow.Id, CauseCategoryId = cat.Id, Why1 = "w1" }
        );
        await _db.SaveChangesAsync();

        var loaded = await _db.Incidents
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .FirstAsync(i => i.Id == target.Id);

        var within90 = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents, TimeSpan.FromDays(90));
        var unbounded = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        Assert.Single(within90);
        Assert.Equal(inWindow.Id, within90[0].Id);
        Assert.Equal(2, unbounded.Count);
    }

    [Fact]
    public async Task FindRecurrencesForIncident_ReturnsEmpty_WhenTargetHasNoCauseAnalyses()
    {
        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today);
        _db.Incidents.Add(target);
        await _db.SaveChangesAsync();

        var loaded = await _db.Incidents
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .FirstAsync(i => i.Id == target.Id);

        var result = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        Assert.Empty(result);
    }

    [Fact]
    public async Task FindRecurrenceAlerts_GroupsRecentIncidents_IntoAlerts()
    {
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat);
        await _db.SaveChangesAsync();

        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-20));
        _db.Incidents.AddRange(a, b);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w2" }
        );
        await _db.SaveChangesAsync();

        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        Assert.Single(alerts);
        Assert.Equal(a.Id, alerts[0].CurrentIncident.Id);
        Assert.Contains(alerts[0].SimilarIncidents, s => s.Id == b.Id);
        Assert.Contains("外科病棟", alerts[0].PatternDescription);
    }

    [Fact]
    public async Task FindRecurrenceAlerts_RespectsRecentWindow()
    {
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat);
        await _db.SaveChangesAsync();

        // Both incidents outside the recent window → no alerts.
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-100));
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-200));
        _db.Incidents.AddRange(a, b);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w1" },
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w2" }
        );
        await _db.SaveChangesAsync();

        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        Assert.Empty(alerts);
    }

    [Fact]
    public async Task FindRecurrenceAlerts_DedupesAcrossAlerts_WhenIncidentsPairUp()
    {
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat);
        await _db.SaveChangesAsync();

        // Three recent incidents all matching → only one alert (first incident takes ownership, others marked processed).
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-5));
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-15));
        var c = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-25));
        _db.Incidents.AddRange(a, b, c);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w" },
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w" },
            new CauseAnalysis { IncidentId = c.Id, CauseCategoryId = cat.Id, Why1 = "w" }
        );
        await _db.SaveChangesAsync();

        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        Assert.Single(alerts);
        Assert.Equal(a.Id, alerts[0].CurrentIncident.Id);
        Assert.Equal(2, alerts[0].SimilarIncidents.Count);
    }
}
