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
        var vm = Assert.IsType<MeasureFormViewModel>(view.Model);
        Assert.Equal("根本原因はダブルチェック未実施", vm.AnalysisNote);
    }

    [Fact]
    public async Task Edit_Post_SavesAnalysisNote()
    {
        // 編集 POST で立案根拠メモが保存されること(保存漏れ回帰防止)
        var measure = await SeedMeasureAsync("内科病棟");
        var vm = new MeasureFormViewModel
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
    public async Task Edit_Post_InvalidModel_UsesOwnIncidentForViewBag_IgnoringClientIncidentId()
    {
        // 編集 POST のバリデーション失敗時、再描画用の ViewBag.Incident には
        // クライアント送信の vm.IncidentId ではなく、認可済みの measure.Incident が
        // 使われること(改ざんされた IncidentId で他インシデントの情報を覗けない)
        // 対象の対策を1件シードする
        var measure = await SeedMeasureAsync("内科病棟");
        // 攻撃者が指したい「別のインシデント」をシードする(別部署想定)
        var otherIncident = new Incident
        {
            Department = "外科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level3a,
            Description = "他部署の機微情報",
            ReporterName = "別部署担当",
            // 発生日時は固定日付(TestFixtures.Today)にして実行日時に依存しない決定論的テストにする
            OccurredAt = TestFixtures.Today
        };
        // 別インシデントを DB に登録する
        _db.Incidents.Add(otherIncident);
        // 保存を確定して Id を採番させる
        await _db.SaveChangesAsync();

        // hidden field 改ざんを模して IncidentId に別インシデントの Id を入れた ViewModel を作る
        var vm = new MeasureFormViewModel
        {
            Id = measure.Id,
            IncidentId = otherIncident.Id,
            ConcurrencyToken = measure.ConcurrencyToken
        };
        // バリデーション失敗経路に入れるためエラーを人為的に追加する
        _controller.ModelState.AddModelError("Description", "対策内容を入力してください");

        // 編集 POST を実行する
        var result = await _controller.Edit(measure.Id, vm);

        // フォーム再描画(ViewResult)になること
        var view = Assert.IsType<ViewResult>(result);
        // ViewBag.Incident(= ViewData["Incident"])に積まれたインシデントを取り出す
        var shownIncident = Assert.IsType<Incident>(view.ViewData["Incident"]);
        // 対策自身の親インシデントが使われていること(改ざん値ではない)
        Assert.Equal(measure.IncidentId, shownIncident.Id);
        // 改ざんで指した別インシデントは表示されないこと
        Assert.NotEqual(otherIncident.Id, shownIncident.Id);
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
    public async Task UpdateStatus_RevertFromCompleted_ClearsEffectivenessReviewData()
    {
        // 完了 → 有効性評価済み の対策をカンバンで進行中へ差し戻したとき、
        // 完了後にしか存在してはいけない効果評価4項目(評価値/コメント/再発フラグ/評価日時)が
        // すべて null にクリアされること(残ると未完了の対策が再発/効果なし KPI を汚染するため)
        var measure = await SeedMeasureAsync("内科病棟");
        // 完了させ、さらに「再発あり・低評価」で有効性評価済みの状態を作る
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        measure.EffectivenessRating = 2;
        measure.EffectivenessNote = "効果が薄かった";
        measure.RecurrenceObserved = true;
        measure.EffectivenessReviewedAt = DateTime.Now;
        await _db.SaveChangesAsync();

        // カンバン上で完了から進行中へ差し戻す
        var result = await _controller.UpdateStatus(
            measure.Id, MeasureStatus.InProgress, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        // ステータスと完了日時が差し戻されていること
        Assert.Equal(MeasureStatus.InProgress, saved.Status);
        Assert.Null(saved.CompletedAt);
        // 効果評価4項目がすべてクリアされていること(KPI汚染防止の不変条件)
        Assert.Null(saved.EffectivenessRating);
        Assert.Null(saved.EffectivenessNote);
        Assert.Null(saved.RecurrenceObserved);
        Assert.Null(saved.EffectivenessReviewedAt);
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
    public async Task UpdateStatus_Success_SetsTempDataSuccess()
    {
        // 保存が成功した場合、他のミューテーション系アクションと同じく
        // TempData["Success"] が設定されること(以前は成功時に何もトーストが出ない欠落があった)
        var measure = await SeedMeasureAsync("内科病棟");

        var result = await _controller.UpdateStatus(
            measure.Id, MeasureStatus.InProgress, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        Assert.NotNull(_controller.TempData["Success"]);
        // 衝突時の警告メッセージとは別物であること(誤って両方立ってしまう回帰の検出用)
        Assert.False(_controller.TempData.ContainsKey("Warning"));
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
    public async Task Complete_NoteTooLong_ReturnsBadRequest_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄
        // (Description/AnalysisNote 等)と同じ500文字上限がここで検証されることを確認する
        var measure = await SeedMeasureAsync("内科病棟");
        var tooLongNote = new string('あ', 501);

        var result = await _controller.Complete(measure.Id, tooLongNote, measure.ConcurrencyToken);

        Assert.IsType<BadRequestObjectResult>(result);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, unchanged.Status);
        Assert.Null(unchanged.CompletionNote);
    }

    [Fact]
    public async Task Review_Post_Completed_PersistsAndRedirectsToIndex()
    {
        // 完了済み対策なら有効性評価が保存され、一覧へリダイレクトされること
        var measure = await SeedMeasureAsync("内科病棟");
        measure.Status = MeasureStatus.Completed;
        await _db.SaveChangesAsync();

        var vm = new ReviewViewModel
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

        var vm = new ReviewViewModel
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
