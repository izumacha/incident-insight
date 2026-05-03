using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

// Tests for the optimistic concurrency failure path. The InMemory provider does
// not actually enforce [ConcurrencyCheck], so we use a DbContext subclass that
// raises DbUpdateConcurrencyException on SaveChanges to verify the controller's
// catch-block behaviour (TempData warning + redirect).
public class ConcurrencyTests : IDisposable
{
    private readonly ThrowingDbContext _db;

    public ConcurrencyTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ThrowingDbContext(options);
    }

    public void Dispose() => _db.Dispose();

    private sealed class ThrowingDbContext : ApplicationDbContext
    {
        public bool ThrowOnNextSave { get; set; }

        public ThrowingDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            if (ThrowOnNextSave)
            {
                ThrowOnNextSave = false;
                throw new DbUpdateConcurrencyException("simulated concurrency conflict");
            }
            return base.SaveChangesAsync(cancellationToken);
        }
    }

    private async Task<Incident> SeedIncidentAsync()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "テスト",
            ReporterName = "テスト太郎",
            OccurredAt = DateTime.Now,
            ReportedAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        return incident;
    }

    private async Task<PreventiveMeasure> SeedMeasureAsync(int incidentId)
    {
        var measure = new PreventiveMeasure
        {
            IncidentId = incidentId,
            Description = "テスト対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = "内科",
            Status = MeasureStatus.Planned,
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        };
        _db.PreventiveMeasures.Add(measure);
        await _db.SaveChangesAsync();
        return measure;
    }

    [Fact]
    public async Task IncidentsEdit_OnConcurrencyConflict_RedirectsToEditWithWarning()
    {
        var incident = await SeedIncidentAsync();
        var controller = new IncidentsController(_db, UserContextHelper.BuildAuthService(), new RecurrenceService(new SystemClock()), new SystemClock(), NullLogger<IncidentsController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        var vm = new IncidentCreateEditViewModel
        {
            Id = incident.Id,
            ConcurrencyToken = Guid.NewGuid(), // stale token
            OccurredAt = incident.OccurredAt,
            Department = incident.Department,
            IncidentType = incident.IncidentType,
            Severity = incident.Severity,
            Description = "更新後",
            ReporterName = incident.ReporterName
        };

        _db.ThrowOnNextSave = true;
        var result = await controller.Edit(incident.Id, vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Edit), redirect.ActionName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.NotNull(controller.TempData["Warning"]);
        Assert.Contains("他のユーザ", controller.TempData["Warning"]!.ToString());
    }

    [Fact]
    public async Task IncidentsCompleteMeasure_OnConcurrencyConflict_SetsWarningAndRedirectsToDetails()
    {
        // CompleteMeasure は IncidentMeasuresController に分離済み。リダイレクト先は
        // 引き続きインシデント詳細画面("Details" on "Incidents" controller)。
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        var controller = new IncidentMeasuresController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), NullLogger<IncidentMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        _db.ThrowOnNextSave = true;
        var result = await controller.CompleteMeasure(measure.Id, "完了メモ", Guid.NewGuid());

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.NotNull(controller.TempData["Warning"]);
    }

    [Fact]
    public async Task PreventiveMeasuresEdit_OnConcurrencyConflict_RedirectsToEditWithWarning()
    {
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        var controller = new PreventiveMeasuresController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        var vm = new MeasureFormViewModel
        {
            Id = measure.Id,
            IncidentId = measure.IncidentId,
            ConcurrencyToken = Guid.NewGuid(), // stale
            Description = "更新後",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = "内科",
            DueDate = DateTime.Today.AddDays(60),
            Priority = 1
        };

        _db.ThrowOnNextSave = true;
        var result = await controller.Edit(measure.Id, vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Edit), redirect.ActionName);
        Assert.NotNull(controller.TempData["Warning"]);
    }

    [Fact]
    public async Task IncidentsEdit_WhenTokenMatches_SavesAndRedirectsToDetails()
    {
        // Baseline happy-path check: without forcing a conflict, Edit should succeed.
        var incident = await SeedIncidentAsync();
        var controller = new IncidentsController(_db, UserContextHelper.BuildAuthService(), new RecurrenceService(new SystemClock()), new SystemClock(), NullLogger<IncidentsController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        var vm = new IncidentCreateEditViewModel
        {
            Id = incident.Id,
            ConcurrencyToken = incident.ConcurrencyToken,
            OccurredAt = incident.OccurredAt,
            Department = incident.Department,
            IncidentType = incident.IncidentType,
            Severity = incident.Severity,
            Description = "更新後の説明",
            ReporterName = incident.ReporterName
        };

        var result = await controller.Edit(incident.Id, vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Details), redirect.ActionName);
    }
}
