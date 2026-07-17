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
            new RecurrenceService(new SystemClock()),
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
    public async Task AddMeasure_ValidationFailure_ReturnsDetailsViewWithPreservedInput()
    {
        // このアクションは成功時は Details へリダイレクトするが、バリデーション失敗時は
        // 入力済みの値を失わないよう Details ビューをそのまま再描画する(回帰防止:
        // 以前は失敗時も無条件でリダイレクトしており、Details の GET が
        // NewMeasure を空の ViewModel で再初期化するため入力内容がすべて失われていた)。
        var incident = await SeedIncidentAsync();

        var vm = new MeasureFormViewModel
        {
            IncidentId = incident.Id,
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "田中太郎",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
            // Description(必須)を意図的に未設定のままにし、実際の POST で [Required] により
            // 発生する ModelState エラーを手動で再現する(モデルバインディングを経ないため)
        };
        _controller.ModelState.AddModelError(nameof(MeasureFormViewModel.Description), "対策内容を入力してください");

        var result = await _controller.AddMeasure(vm);

        // 保存されていないこと(バリデーション失敗のため)
        Assert.Empty(_db.PreventiveMeasures);
        // Details ビューがそのまま返り、入力済みの値(Description 以外)が保持されていること
        var view = Assert.IsType<ViewResult>(result);
        Assert.Equal("~/Views/Incidents/Details.cshtml", view.ViewName);
        var detailVm = Assert.IsType<IncidentDetailViewModel>(view.Model);
        Assert.Equal(incident.Id, detailVm.Incident.Id);
        Assert.Equal("田中太郎", detailVm.NewMeasure.ResponsiblePerson);
        Assert.Equal("内科病棟", detailVm.NewMeasure.ResponsibleDepartment);
        Assert.Equal(incident.Id, detailVm.NewMeasure.IncidentId);
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
    public async Task CompleteMeasure_AlreadyCompleted_RedirectsWithWarning_AndDoesNotOverwrite()
    {
        // すでに完了済みの対策への再完了 POST(古いタブからの再送信など)は fail-closed で
        // 拒否され、元の CompletedAt / CompletionNote が黙って上書きされないことを確認する。
        // 上書きを許すと有効性評価日時が完了日時より前になる等、KPI の時系列整合性が壊れる。
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);
        // 元の完了日時・完了メモを設定しておく
        var originalCompletedAt = new DateTime(2026, 6, 1, 10, 0, 0);
        measure.CompletedAt = originalCompletedAt;
        measure.CompletionNote = "最初の完了メモ";
        await _db.SaveChangesAsync();

        var result = await _controller.CompleteMeasure(measure.Id, "2回目の完了メモ", measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Contains("すでに完了", _controller.TempData["Warning"] as string);
        // 元の完了情報が保持されていること
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(originalCompletedAt, unchanged.CompletedAt);
        Assert.Equal("最初の完了メモ", unchanged.CompletionNote);
    }

    [Fact]
    public async Task CompleteMeasure_NotFound_ReturnsNotFound()
    {
        var result = await _controller.CompleteMeasure(99999, null, Guid.NewGuid());
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task CompleteMeasure_NoteTooLong_RedirectsWithWarning_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄
        // (Description/AnalysisNote 等)と同じ500文字上限がここで検証されることを確認する。
        // 他の失敗経路(同時編集衝突など)と同じく、生の BadRequest ではなく
        // TempData["Warning"] + Details へのリダイレクトで通知されることを確認する。
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        var tooLongNote = new string('あ', 501);

        var result = await _controller.CompleteMeasure(measure.Id, tooLongNote, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.Contains("500文字以内", _controller.TempData["Warning"] as string);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, unchanged.Status);
        Assert.Null(unchanged.CompletionNote);
    }

    [Fact]
    public async Task RateMeasure_OutOfRange_RedirectsWithWarning_AndDoesNotPersist()
    {
        // 認可チェックが評価値の範囲検証より先に行われる設計のため、
        // 未認可扱い(403)ではなく検証エラーを確認するには実在の対策をシードする必要がある。
        // 検証失敗は他の失敗経路と同じく TempData["Warning"] + Details へのリダイレクトで
        // 通知される(生の BadRequest はモーダル/コンテキストを失わせてしまうため)
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);

        var result = await _controller.RateMeasure(measure.Id, 0, null, false, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Contains("1〜5", _controller.TempData["Warning"] as string);
        // 範囲外の評価値が保存されていないこと
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Null(unchanged.EffectivenessRating);
    }

    [Fact]
    public async Task RateMeasure_NoteTooLong_RedirectsWithWarning_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄と同じ
        // 500文字上限がここで検証されることを確認する。他の失敗経路(ライフサイクル逸脱・
        // 同時編集衝突など)と同じく、生の BadRequest ではなく TempData["Warning"] +
        // Details へのリダイレクトで通知されることを確認する。
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);
        var tooLongNote = new string('あ', 501);

        var result = await _controller.RateMeasure(measure.Id, 3, tooLongNote, false, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.Contains("500文字以内", _controller.TempData["Warning"] as string);
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
    public async Task RateMeasure_RecurrenceObservedNotSelected_RejectsWithoutPersisting()
    {
        // recurrenceObserved が null(フォームでどちらのラジオも選ばずに送信した状態を再現)の場合、
        // false へ暗黙にフォールバックせず fail-closed で拒否し、何も保存しないことを確認する
        // (Details.cshtml の noRecurrence ラジオに checked が誤って付いていた回帰の再発防止)
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id, MeasureStatus.Completed);

        var result = await _controller.RateMeasure(measure.Id, 4, "未選択のまま送信", null, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.Contains("再発の有無を選択", _controller.TempData["Warning"] as string);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Null(unchanged.EffectivenessRating);
        Assert.Null(unchanged.RecurrenceObserved);
        Assert.Null(unchanged.EffectivenessReviewedAt);
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
}
