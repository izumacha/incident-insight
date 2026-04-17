using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Data;

public class AuditSaveChangesInterceptorTests : IDisposable
{
    private readonly ApplicationDbContext _db;

    public AuditSaveChangesInterceptorTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .AddInterceptors(new AuditSaveChangesInterceptor())
            .Options;
        _db = new ApplicationDbContext(options);
    }

    public void Dispose() => _db.Dispose();

    private static Incident NewIncident() => new()
    {
        OccurredAt = DateTime.Now,
        Department = "内科病棟",
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト状況",
        ReporterName = "テスト太郎"
    };

    [Fact]
    public async Task Added_Incident_WritesAuditLog()
    {
        var incident = NewIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var logs = await _db.AuditLogs.ToListAsync();
        var log = Assert.Single(logs);
        Assert.Equal(nameof(Incident), log.EntityName);
        Assert.Equal("Added", log.Operation);
        Assert.Equal(incident.Id.ToString(), log.EntityKey);
        Assert.False(string.IsNullOrEmpty(log.ChangesJson));
    }

    [Fact]
    public async Task Modified_PreventiveMeasure_WritesAuditLogAndBumpsConcurrencyToken()
    {
        var incident = NewIncident();
        var measure = new PreventiveMeasure
        {
            Description = "テスト対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        };
        incident.PreventiveMeasures.Add(measure);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var originalToken = measure.ConcurrencyToken;

        // Modify status
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        await _db.SaveChangesAsync();

        var modifiedLog = await _db.AuditLogs
            .Where(a => a.EntityName == nameof(PreventiveMeasure) && a.Operation == "Modified")
            .SingleAsync();

        Assert.Contains("Status", modifiedLog.ChangesJson);
        Assert.NotEqual(originalToken, measure.ConcurrencyToken);
    }

    [Fact]
    public async Task Deleted_CauseAnalysis_WritesAuditLog()
    {
        var incident = NewIncident();
        var category = new CauseCategory { Name = "テスト分類", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var analysis = new CauseAnalysis
        {
            Incident = incident,
            CauseCategory = category,
            Why1 = "なぜ1"
        };
        incident.CauseAnalyses.Add(analysis);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.Remove(analysis);
        await _db.SaveChangesAsync();

        var deletedLog = await _db.AuditLogs
            .Where(a => a.EntityName == nameof(CauseAnalysis) && a.Operation == "Deleted")
            .SingleAsync();

        Assert.Equal(analysis.Id.ToString(), deletedLog.EntityKey);
    }

    [Fact]
    public async Task NonAuditedEntity_DoesNotProduceAuditLog()
    {
        var category = new CauseCategory { Name = "カテゴリA", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var logCount = await _db.AuditLogs.CountAsync();
        Assert.Equal(0, logCount);
    }
}
