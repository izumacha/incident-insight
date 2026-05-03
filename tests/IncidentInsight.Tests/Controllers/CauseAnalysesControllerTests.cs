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

// CauseAnalysesController 単体テスト。なぜなぜ分析の追加・編集・削除の振る舞いを検証する。
// IncidentsController から分離した移送先のため、URL は /Incidents/... を維持し、
// リダイレクト先はインシデント詳細(Incidents/Details)になる。
public class CauseAnalysesControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly CauseAnalysesController _controller;

    public CauseAnalysesControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new CauseAnalysesController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<CauseAnalysesController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    private async Task<(Incident, CauseCategory)> SeedAsync(string department = "内科病棟")
    {
        var category = new CauseCategory { Name = "テスト分類", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
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
        return (incident, category);
    }

    [Fact]
    public async Task AddCauseAnalysis_ValidModel_PersistsAndRedirectsToDetails()
    {
        var (incident, category) = await SeedAsync();

        var vm = new CauseAnalysisFormViewModel
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "なぜ1: 確認漏れ",
            Why2 = "なぜ2: 手順未整備"
        };

        var result = await _controller.AddCauseAnalysis(vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        var saved = await _db.CauseAnalyses.SingleAsync();
        Assert.Equal("なぜ1: 確認漏れ", saved.Why1);
    }

    [Fact]
    public async Task AddCauseAnalysis_NonExistentIncident_ReturnsNotFound()
    {
        var vm = new CauseAnalysisFormViewModel
        {
            IncidentId = 99999,
            CauseCategoryId = 1,
            Why1 = "なぜ1"
        };

        var result = await _controller.AddCauseAnalysis(vm);

        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task AddCauseAnalysis_Staff_OtherDepartment_ReturnsForbid()
    {
        var (incident, category) = await SeedAsync("外来");
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));

        var vm = new CauseAnalysisFormViewModel
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "なぜ1"
        };

        var result = await _controller.AddCauseAnalysis(vm);

        Assert.IsType<ForbidResult>(result);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task EditCauseAnalysis_Get_ReturnsViewWithCurrentValues()
    {
        var (incident, category) = await SeedAsync();
        var analysis = new CauseAnalysis
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "初期値"
        };
        _db.CauseAnalyses.Add(analysis);
        await _db.SaveChangesAsync();

        var result = await _controller.EditCauseAnalysis(analysis.Id);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<CauseAnalysisFormViewModel>(view.Model);
        Assert.Equal("初期値", vm.Why1);
        Assert.Equal(analysis.ConcurrencyToken, vm.ConcurrencyToken);
    }

    [Fact]
    public async Task EditCauseAnalysis_NotFound_Returns404()
    {
        var result = await _controller.EditCauseAnalysis(99999);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task DeleteCauseAnalysis_RemovesEntityAndRedirects()
    {
        var (incident, category) = await SeedAsync();
        var analysis = new CauseAnalysis
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "削除対象"
        };
        _db.CauseAnalyses.Add(analysis);
        await _db.SaveChangesAsync();

        var result = await _controller.DeleteCauseAnalysis(analysis.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.False(await _db.CauseAnalyses.AnyAsync());
    }

    [Fact]
    public async Task DeleteCauseAnalysis_Staff_OtherDepartment_ReturnsForbid()
    {
        var (incident, category) = await SeedAsync("外来");
        var analysis = new CauseAnalysis
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "他部署"
        };
        _db.CauseAnalyses.Add(analysis);
        await _db.SaveChangesAsync();
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));

        var result = await _controller.DeleteCauseAnalysis(analysis.Id);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.CauseAnalyses.AnyAsync(a => a.Id == analysis.Id));
    }
}
