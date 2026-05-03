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

// IncidentMeasuresController 単体テスト。インシデント詳細画面から起動する
// 対策追加・完了登録・有効性評価の振る舞いを検証する。
public class IncidentMeasuresControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly IncidentMeasuresController _controller;

    public IncidentMeasuresControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new IncidentMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<IncidentMeasuresController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    private async Task<Incident> SeedIncidentAsync(string department = "内科病棟")
    {
        var incident = new Incident
        {
            Department = department,
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "状況",
            ReporterName = "報告者",
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
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2,
            Status = MeasureStatus.Planned
        };
        _db.PreventiveMeasures.Add(measure);
        await _db.SaveChangesAsync();
        return measure;
    }

    [Fact]
    public async Task AddMeasure_ValidModel_PersistsAndRedirectsToDetails()
    {
        var incident = await SeedIncidentAsync();

        var vm = new MeasureFormViewModel
        {
            IncidentId = incident.Id,
            Description = "新規対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当者A",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(15),
            Priority = 1
        };

        var result = await _controller.AddMeasure(vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        var saved = await _db.PreventiveMeasures.SingleAsync();
        Assert.Equal("新規対策", saved.Description);
        Assert.Equal(MeasureStatus.Planned, saved.Status);
    }

    [Fact]
    public async Task AddMeasure_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = await SeedIncidentAsync("外来");
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));

        var vm = new MeasureFormViewModel
        {
            IncidentId = incident.Id,
            Description = "他部署対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(10),
            Priority = 2
        };

        var result = await _controller.AddMeasure(vm);

        Assert.IsType<ForbidResult>(result);
        Assert.Empty(_db.PreventiveMeasures);
    }

    [Fact]
    public async Task CompleteMeasure_SetsStatusCompletedAndRedirects()
    {
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);

        var result = await _controller.CompleteMeasure(measure.Id, "完了報告メモ", measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        var updated = await _db.PreventiveMeasures.FindAsync(measure.Id);
        Assert.Equal(MeasureStatus.Completed, updated!.Status);
        Assert.Equal("完了報告メモ", updated.CompletionNote);
        Assert.NotNull(updated.CompletedAt);
    }

    [Fact]
    public async Task CompleteMeasure_NotFound_ReturnsNotFound()
    {
        var result = await _controller.CompleteMeasure(99999, null, Guid.NewGuid());
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task RateMeasure_OutOfRange_ReturnsBadRequest()
    {
        var result = await _controller.RateMeasure(1, 0, null, false, Guid.NewGuid());
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task RateMeasure_RecurrenceObserved_SetsWarning()
    {
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);

        var result = await _controller.RateMeasure(measure.Id, 4, "再発が確認された", true, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.NotNull(_controller.TempData["Warning"]);
        var updated = await _db.PreventiveMeasures.FindAsync(measure.Id);
        Assert.Equal(4, updated!.EffectivenessRating);
        Assert.True(updated.RecurrenceObserved);
    }

    [Fact]
    public async Task RateMeasure_NoRecurrence_SetsSuccess()
    {
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);

        var result = await _controller.RateMeasure(measure.Id, 5, "効果あり", false, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        Assert.NotNull(_controller.TempData["Success"]);
    }
}
