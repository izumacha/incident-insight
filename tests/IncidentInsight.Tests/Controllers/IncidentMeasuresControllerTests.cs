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

    private async Task<PreventiveMeasure> SeedMeasureAsync(int incidentId, MeasureStatus status = MeasureStatus.Planned)
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
            Status = status
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
    public async Task CompleteMeasure_NoteTooLong_ReturnsBadRequest_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄
        // (Description/AnalysisNote 等)と同じ500文字上限がここで検証されることを確認する
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        var tooLongNote = new string('あ', 501);

        var result = await _controller.CompleteMeasure(measure.Id, tooLongNote, measure.ConcurrencyToken);

        Assert.IsType<BadRequestObjectResult>(result);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, unchanged.Status);
        Assert.Null(unchanged.CompletionNote);
    }

    [Fact]
    public async Task RateMeasure_OutOfRange_ReturnsBadRequest()
    {
        // 認可チェックが評価値の範囲検証より先に行われる設計のため、
        // 未認可扱い(403)ではなく検証エラー(400)を確認するには実在の対策をシードする必要がある
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);

        var result = await _controller.RateMeasure(measure.Id, 0, null, false, measure.ConcurrencyToken);
        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task RateMeasure_NoteTooLong_ReturnsBadRequest_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄と同じ
        // 500文字上限がここで検証されることを確認する
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);
        var tooLongNote = new string('あ', 501);

        var result = await _controller.RateMeasure(measure.Id, 3, tooLongNote, false, measure.ConcurrencyToken);

        Assert.IsType<BadRequestObjectResult>(result);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Null(unchanged.EffectivenessRating);
        Assert.Null(unchanged.EffectivenessNote);
    }

    [Fact]
    public async Task RateMeasure_RecurrenceObserved_SetsWarning()
    {
        var incident = await SeedIncidentAsync();
        // 有効性評価は完了済み対策にのみ許可されるため、完了状態でシードする
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);

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
        // 有効性評価は完了済み対策にのみ許可されるため、完了状態でシードする
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);

        var result = await _controller.RateMeasure(measure.Id, 5, "効果あり", false, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        Assert.NotNull(_controller.TempData["Success"]);
    }

    [Fact]
    public async Task RateMeasure_NotCompleted_RejectsWithoutPersisting()
    {
        // 未完了(Planned)の対策への有効性評価は fail-closed で拒否され、
        // 再発フラグ・評価値が書き込まれないこと(KPI 汚染の回帰防止)
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Planned);

        var result = await _controller.RateMeasure(measure.Id, 1, "未完了なのに評価", true, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.NotNull(_controller.TempData["Warning"]);
        var updated = await _db.PreventiveMeasures.FindAsync(measure.Id);
        // 評価値・再発有無・評価日時のいずれも保存されていないこと
        Assert.Null(updated!.EffectivenessRating);
        Assert.Null(updated.RecurrenceObserved);
        Assert.Null(updated.EffectivenessReviewedAt);
    }

    [Fact]
    public void AddMeasure_BindsWithNewMeasurePrefix()
    {
        // Details.cshtml のフォームは IncidentDetailViewModel.NewMeasure 経由で描画されるため、
        // フィールド名は「NewMeasure.Description」のように prefix 付きで POST される。
        // アクション引数に Bind(Prefix) が無いとバインダが空 prefix にフォールバックして
        // IncidentId が 0 のまま常に 404 になるため、prefix の一致をここで固定化する。
        var parameter = typeof(IncidentMeasuresController)
            .GetMethod(nameof(IncidentMeasuresController.AddMeasure))!
            .GetParameters().Single();

        var bind = Assert.IsType<BindAttribute>(
            parameter.GetCustomAttributes(typeof(BindAttribute), inherit: false).Single());
        Assert.Equal(nameof(IncidentDetailViewModel.NewMeasure), bind.Prefix);
    }
}
