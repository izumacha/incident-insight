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
        string? responsibleDepartment = null,
        int siblingMeasureCount = 0)
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
        // HasAtLeastOneValidMeasure 不変条件の検証用に、削除しても0件にならないよう
        // 同じインシデントに追加の対策(sibling)を必要数だけ積んでおく
        for (var i = 0; i < siblingMeasureCount; i++)
        {
            incident.PreventiveMeasures.Add(new PreventiveMeasure
            {
                Incident = incident,
                Description = $"対策(sibling {i + 1})",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当B",
                ResponsibleDepartment = responsibleDepartment ?? incidentDepartment,
                DueDate = DateTime.Today.AddDays(30),
                Priority = 2
            });
        }
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
        // 削除後も対策が1件残るよう sibling を1件追加しておく(0件になる削除は別途拒否ケースで検証)
        var measure = await SeedMeasureAsync("内科病棟", siblingMeasureCount: 1);

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
        // 削除後も対策が1件残るよう sibling を1件追加しておく。
        var measure = await SeedMeasureAsync("外来", siblingMeasureCount: 1);

        UserContextHelper.AttachUser(_controller, UserContextHelper.RiskManager());
        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Delete_LastRemainingMeasure_IsRejected()
    {
        // インシデントに対策が1件しかない場合、削除すると「対策0件のインシデント」という
        // 不正状態(HasAtLeastOneValidMeasure 不変条件違反)が生まれるため拒否されるべき
        var measure = await SeedMeasureAsync("内科病棟");

        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        // 削除は行われず、対策は DB に残ったまま
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
        Assert.NotNull(_controller.TempData["Warning"]);
    }

    [Fact]
    public async Task Delete_WithMultipleRemainingMeasures_Succeeds()
    {
        // 対策が2件以上残っている場合は、1件削除しても不変条件を満たすため成功する
        var measure = await SeedMeasureAsync("内科病棟", siblingMeasureCount: 2);

        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
        // 残りの2件は削除されずに残っていること
        Assert.Equal(2, await _db.PreventiveMeasures.CountAsync(m => m.IncidentId == measure.IncidentId));
        Assert.NotNull(_controller.TempData["Success"]);
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

    [Fact]
    public async Task Review_Post_Completed_PersistsAndRedirectsToIndex()
    {
        // 完了済み対策なら有効性評価が保存され、一覧へリダイレクトされること
        var measure = await SeedMeasureAsync("内科病棟");
        measure.Status = MeasureStatus.Completed;
        await _db.SaveChangesAsync();

        var vm = new IncidentInsight.Web.Models.ViewModels.ReviewViewModel
        {
            Id = measure.Id,
            ConcurrencyToken = measure.ConcurrencyToken,
            EffectivenessRating = 4,
            EffectivenessNote = "効果あり",
            RecurrenceObserved = false
        };

        var result = await _controller.Review(measure.Id, vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        var updated = await _db.PreventiveMeasures.FindAsync(measure.Id);
        Assert.Equal(4, updated!.EffectivenessRating);
        Assert.False(updated.RecurrenceObserved);
        Assert.NotNull(updated.EffectivenessReviewedAt);
    }

    [Fact]
    public async Task Review_Post_NotCompleted_RejectsWithoutPersisting()
    {
        // 未完了(Planned)の対策への有効性評価は fail-closed で拒否され、
        // 再発フラグ・評価値が書き込まれないこと(KPI 汚染の回帰防止)
        var measure = await SeedMeasureAsync("内科病棟");

        var vm = new IncidentInsight.Web.Models.ViewModels.ReviewViewModel
        {
            Id = measure.Id,
            ConcurrencyToken = measure.ConcurrencyToken,
            EffectivenessRating = 1,
            EffectivenessNote = "未完了なのに評価",
            RecurrenceObserved = true
        };

        var result = await _controller.Review(measure.Id, vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.NotNull(_controller.TempData["Warning"]);
        var updated = await _db.PreventiveMeasures.FindAsync(measure.Id);
        // 評価値・再発有無・評価日時のいずれも保存されていないこと
        Assert.Null(updated!.EffectivenessRating);
        Assert.Null(updated.RecurrenceObserved);
        Assert.Null(updated.EffectivenessReviewedAt);
    }
}
