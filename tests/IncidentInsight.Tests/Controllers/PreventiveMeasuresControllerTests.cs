using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

public class PreventiveMeasuresControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly PreventiveMeasuresController _controller;

    public PreventiveMeasuresControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    private async Task<PreventiveMeasure> SeedMeasureAsync(
        string incidentDepartment,
        string? responsibleDepartment = null)
    {
        var incident = new Incident
        {
            Department = incidentDepartment,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "テスト",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        var measure = new PreventiveMeasure
        {
            Incident = incident,
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = responsibleDepartment ?? incidentDepartment,
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        };
        incident.PreventiveMeasures.Add(measure);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        return measure;
    }

    [Fact]
    public async Task Edit_Get_PopulatesAnalysisNote()
    {
        // 編集画面を開いたとき、既存の立案根拠メモが ViewModel に積まれること
        var measure = await SeedMeasureAsync("内科病棟");
        measure.AnalysisNote = "根本原因はダブルチェック未実施";
        await _db.SaveChangesAsync();

        var result = await _controller.Edit(measure.Id);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<IncidentInsight.Web.Models.ViewModels.MeasureFormViewModel>(view.Model);
        Assert.Equal("根本原因はダブルチェック未実施", vm.AnalysisNote);
    }

    [Fact]
    public async Task Edit_Post_SavesAnalysisNote()
    {
        // 編集 POST で立案根拠メモが保存されること(保存漏れ回帰防止)
        var measure = await SeedMeasureAsync("内科病棟");
        var vm = new IncidentInsight.Web.Models.ViewModels.MeasureFormViewModel
        {
            Id = measure.Id,
            IncidentId = measure.IncidentId,
            ConcurrencyToken = measure.ConcurrencyToken,
            Description = measure.Description,
            MeasureType = measure.MeasureType,
            ResponsiblePerson = measure.ResponsiblePerson,
            ResponsibleDepartment = measure.ResponsibleDepartment,
            DueDate = measure.DueDate,
            Priority = measure.Priority,
            AnalysisNote = "対策の根拠メモ"
        };

        var result = await _controller.Edit(measure.Id, vm);

        Assert.IsType<RedirectToActionResult>(result);
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal("対策の根拠メモ", saved.AnalysisNote);
    }

    [Fact]
    public async Task UpdateStatus_RevertFromCompleted_ClearsCompletedAt()
    {
        // 完了 → 進行中へ差し戻したとき、CompletedAt が null にクリアされること
        var measure = await SeedMeasureAsync("内科病棟");
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        await _db.SaveChangesAsync();

        var result = await _controller.UpdateStatus(
            measure.Id, MeasureStatus.InProgress, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.InProgress, saved.Status);
        Assert.Null(saved.CompletedAt);
    }

    [Fact]
    public async Task UpdateStatus_UndefinedEnumValue_ReturnsBadRequest_AndDoesNotPersist()
    {
        // モデルバインドで未定義の整数(例: 99)が status に入っても、定義外なら 400 で拒否し
        // DB のステータスが書き換わらない(fail-closed)ことを検証する
        var measure = await SeedMeasureAsync("内科病棟");
        // 事前状態は既定の Planned(計画中)
        Assert.Equal(MeasureStatus.Planned, measure.Status);

        // enum に存在しない値(99)をキャストして渡す
        var result = await _controller.UpdateStatus(
            measure.Id, (MeasureStatus)99, measure.ConcurrencyToken);

        // 400 BadRequest が返ること
        Assert.IsType<BadRequestObjectResult>(result);
        // DB のステータスは Planned のまま変化していないこと(不正値が永続化されない)
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, saved.Status);
    }

    [Fact]
    public async Task Delete_Staff_OtherDepartment_ReturnsForbid()
    {
        var measure = await SeedMeasureAsync("外来");

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Delete(measure.Id);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Delete_NotFound_ReturnsNotFound()
    {
        var result = await _controller.Delete(99999);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Admin_RemovesMeasure()
    {
        var measure = await SeedMeasureAsync("内科病棟");

        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
        Assert.NotNull(_controller.TempData["Success"]);
    }

    [Fact]
    public async Task Delete_RiskManager_RemovesMeasure_RegardlessOfDepartment()
    {
        // RiskManager は全部署横断で削除可能 (Policies.CanDeleteIncident)。
        var measure = await SeedMeasureAsync("外来");

        UserContextHelper.AttachUser(_controller, UserContextHelper.RiskManager());
        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Delete_Staff_IncidentDepartmentMismatch_ResponsibleDepartmentMatches_ReturnsForbid()
    {
        // Issue #29 回帰防止: 認可の判定は Incident の発生部署に基づくべきで、
        // PreventiveMeasure.ResponsibleDepartment が Staff の部署に一致しても通してはならない。
        var measure = await SeedMeasureAsync(
            incidentDepartment: "外来",
            responsibleDepartment: "内科病棟");

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Delete(measure.Id);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }
}
