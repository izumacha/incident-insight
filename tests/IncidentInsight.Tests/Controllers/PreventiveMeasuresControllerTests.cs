using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
// InMemoryEventId は InMemory プロバイダの警告 ID を参照するために必要
using Microsoft.EntityFrameworkCore.Diagnostics;
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
            // InMemory プロバイダはトランザクションをサポートしないため警告が出るが、
            // テスト用途ではトランザクション整合性を検証しないので例外扱いにせず無視する。
            // 本番の SQLite/SQL Server/PostgreSQL では BeginTransactionAsync は正常に動作する
            // (Delete が TOCTOU 対策で Serializable トランザクションを使うため必要)。
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
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
    public async Task UpdateStatus_RevertFromCompleted_ClearsCompletionNote()
    {
        // 完了報告メモ付きで完了済みの対策をカンバンで差し戻したとき、
        // 完了報告メモ(CompletionNote)もクリアされること。残ると差し戻し後の
        // 未完了カードに古い完了報告が表示され続け、再完了時の新しい報告と食い違う
        var measure = await SeedMeasureAsync("内科病棟");
        // 完了済み + 完了報告メモありの状態を作る
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        measure.CompletionNote = "手順書を改訂して周知済み";
        await _db.SaveChangesAsync();

        // カンバン上で完了から進行中へ差し戻す
        var result = await _controller.UpdateStatus(
            measure.Id, MeasureStatus.InProgress, measure.ConcurrencyToken);

        Assert.IsType<RedirectToActionResult>(result);
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        // ステータスと完了日時が差し戻されていること
        Assert.Equal(MeasureStatus.InProgress, saved.Status);
        Assert.Null(saved.CompletedAt);
        // 完了報告メモがクリアされていること(古い完了報告の残留防止)
        Assert.Null(saved.CompletionNote);
    }

    [Fact]
    public async Task UpdateStatus_UndefinedEnumValue_RedirectsWithWarning_AndDoesNotPersist()
    {
        // モデルバインドで未定義の整数(例: 99)が status に入っても、定義外なら拒否し
        // DB のステータスが書き換わらない(fail-closed)ことを検証する。
        // 拒否は他の失敗経路と同じく TempData["Warning"] + 一覧へのリダイレクトで通知される
        // (生の BadRequest はカンバン画面のコンテキストを失わせてしまうため)
        var measure = await SeedMeasureAsync("内科病棟");
        // 事前状態は既定の Planned(計画中)
        Assert.Equal(MeasureStatus.Planned, measure.Status);

        // enum に存在しない値(99)をキャストして渡す
        var result = await _controller.UpdateStatus(
            measure.Id, (MeasureStatus)99, measure.ConcurrencyToken);

        // 警告付きで一覧へリダイレクトされること
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Contains("不正なステータス値", _controller.TempData["Warning"] as string);
        // DB のステータスは Planned のまま変化していないこと(不正値が永続化されない)
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, saved.Status);
    }

    [Fact]
    public async Task UpdateStatus_RecompleteCompletedMeasure_RedirectsWithWarning_AndDoesNotRewriteCompletedAt()
    {
        // すでに完了済みの対策に「完了」を再指定しても拒否され、CompletedAt と
        // 効果評価データが書き換わらないこと(fail-closed)を検証する。
        // ここを素通しにすると、評価済みの対策で CompletedAt だけが現在時刻へ動き、
        // EffectivenessReviewedAt < CompletedAt という時系列矛盾が生まれてしまう
        // (Complete / CompleteMeasure が再完了を拒否しているのと同じライフサイクル強制)
        var measure = await SeedMeasureAsync("内科病棟");
        // 「過去に完了し、その後に有効性評価済み」の状態を作る
        var originalCompletedAt = DateTime.Now.AddDays(-30);
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = originalCompletedAt;
        measure.EffectivenessRating = 4;
        measure.EffectivenessNote = "十分な効果があった";
        measure.RecurrenceObserved = false;
        measure.EffectivenessReviewedAt = DateTime.Now.AddDays(-10);
        await _db.SaveChangesAsync();

        // 完了済みの対策へ「完了」を再指定する(古いタブからの再送信や改ざん POST を模す)
        var result = await _controller.UpdateStatus(
            measure.Id, MeasureStatus.Completed, measure.ConcurrencyToken);

        // 警告付きで一覧へリダイレクトされること
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Contains("すでに完了しています", _controller.TempData["Warning"] as string);
        // DB の完了日時・評価データが一切書き換わっていないこと
        var saved = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Completed, saved.Status);
        Assert.Equal(originalCompletedAt, saved.CompletedAt);
        Assert.Equal(4, saved.EffectivenessRating);
        Assert.NotNull(saved.EffectivenessReviewedAt);
        // 時系列の不変条件(完了日時 <= 評価日時)が保たれていること
        Assert.True(saved.CompletedAt <= saved.EffectivenessReviewedAt);
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
        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Delete_NotFound_ReturnsNotFound()
    {
        var result = await _controller.Delete(99999, Guid.NewGuid());
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Admin_RemovesMeasure()
    {
        // 削除後も対策が1件残るよう sibling を1件追加しておく(0件になる削除は別途拒否ケースで検証)
        var measure = await SeedMeasureAsync("内科病棟", siblingMeasureCount: 1);

        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

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
        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

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

        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

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

        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
        // 残りの2件は削除されずに残っていること
        Assert.Equal(2, await _db.PreventiveMeasures.CountAsync(m => m.IncidentId == measure.IncidentId));
        Assert.NotNull(_controller.TempData["Success"]);
    }

    [Fact]
    public async Task Delete_ConcurrentRequestsOnLastTwoMeasures_NeverLeavesZeroMeasures()
    {
        // TOCTOU競合状態の回帰テスト: 対策がちょうど2件のインシデントに対して、
        // 別々の対策を同時に削除する2つのリクエストが来ても、両方成功して
        // 「対策0件」という不変条件違反の状態にならないことを検証する。
        //
        // InMemory プロバイダはトランザクションを実装しない(=このテストクラスの
        // 共有 _db では競合状態自体が起きない)ため、実際にファイルロックで
        // 排他制御される一時ファイルの SQLite を使い、2つの独立した DbContext
        // (=2つの同時 HTTP リクエストを模す)から本物の並行実行を発生させる。
        var dbPath = Path.Combine(Path.GetTempPath(), $"incident-insight-toctou-{Guid.NewGuid():N}.db");
        var connectionString = $"Data Source={dbPath}";
        try
        {
            int incidentId;
            int measureAId;
            int measureBId;
            Guid measureAToken;
            Guid measureBToken;
            // マイグレーション経由ではなく EnsureCreated で素早くスキーマだけ作る
            // (このテストは並行実行時の行ロック挙動だけを見るため、既存マイグレーション
            // 履歴とのプロバイダ間差異は問題にならない)
            await using (var setupDb = new ApplicationDbContext(
                new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options))
            {
                await setupDb.Database.EnsureCreatedAsync();
                var incident = new Incident
                {
                    Department = "内科病棟",
                    IncidentType = IncidentTypeKind.Fall,
                    Severity = IncidentSeverity.Level2,
                    Description = "テスト",
                    ReporterName = "担当",
                    OccurredAt = DateTime.Now
                };
                var measureA = new PreventiveMeasure
                {
                    Incident = incident,
                    Description = "対策A",
                    MeasureType = MeasureTypeKind.ShortTerm,
                    ResponsiblePerson = "担当A",
                    ResponsibleDepartment = "内科病棟",
                    DueDate = DateTime.Today.AddDays(30),
                    Priority = 2
                };
                var measureB = new PreventiveMeasure
                {
                    Incident = incident,
                    Description = "対策B",
                    MeasureType = MeasureTypeKind.ShortTerm,
                    ResponsiblePerson = "担当B",
                    ResponsibleDepartment = "内科病棟",
                    DueDate = DateTime.Today.AddDays(30),
                    Priority = 2
                };
                incident.PreventiveMeasures.Add(measureA);
                incident.PreventiveMeasures.Add(measureB);
                setupDb.Incidents.Add(incident);
                await setupDb.SaveChangesAsync();
                incidentId = incident.Id;
                measureAId = measureA.Id;
                measureBId = measureB.Id;
                measureAToken = measureA.ConcurrencyToken;
                measureBToken = measureB.ConcurrencyToken;
            }

            // それぞれ別の DbContext・別の Controller インスタンスで、
            // 別スレッド(Task.Run)から本物の並行実行として Delete を呼ぶ
            Task<IActionResult> RunDeleteOnOwnThreadAsync(int measureId, Guid concurrencyToken) => Task.Run(async () =>
            {
                await using var db = new ApplicationDbContext(
                    new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options);
                var controller = new PreventiveMeasuresController(
                    db,
                    UserContextHelper.BuildAuthService(),
                    new SystemClock(),
                    NullLogger<PreventiveMeasuresController>.Instance);
                UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
                return await controller.Delete(measureId, concurrencyToken);
            });

            var taskA = RunDeleteOnOwnThreadAsync(measureAId, measureAToken);
            var taskB = RunDeleteOnOwnThreadAsync(measureBId, measureBToken);
            await Task.WhenAll(taskA, taskB);

            // 検証: 両方が成功して対策0件になってはならない
            // (どちらか一方が成功しもう一方は「最後の1件」または「同時実行の衝突」で
            // 拒否されるか、まれに両方とも衝突で拒否される。いずれにせよ最低1件は残る)
            await using var verifyDb = new ApplicationDbContext(
                new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options);
            var remaining = await verifyDb.PreventiveMeasures.CountAsync(m => m.IncidentId == incidentId);
            Assert.True(remaining >= 1, "同時削除リクエストによって対策が0件になってはならない(HasAtLeastOneValidMeasure不変条件)");
        }
        finally
        {
            // 一時DBファイルの後始末(共通ヘルパーで WAL/SHM 等の補助ファイルも一括削除)
            SqliteTestFiles.Cleanup(dbPath);
        }
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
        var result = await _controller.Delete(measure.Id, measure.ConcurrencyToken);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Complete_NoteTooLong_RedirectsWithWarning_AndDoesNotPersist()
    {
        // この経路は ViewModel を介さず生の文字列を受け取るため、他の自由記述欄
        // (Description/AnalysisNote 等)と同じ500文字上限がここで検証されることを確認する。
        // 他の失敗経路(同時編集衝突など)と同じく、生の BadRequest ではなく
        // TempData["Warning"] + Index へのリダイレクトで通知されることを確認する。
        var measure = await SeedMeasureAsync("内科病棟");
        var tooLongNote = new string('あ', 501);

        var result = await _controller.Complete(measure.Id, tooLongNote, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Contains("500文字以内", _controller.TempData["Warning"] as string);
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(MeasureStatus.Planned, unchanged.Status);
        Assert.Null(unchanged.CompletionNote);
    }

    [Fact]
    public async Task Complete_AlreadyCompleted_RedirectsWithWarning_AndDoesNotOverwrite()
    {
        // すでに完了済みの対策への再完了 POST(古いタブからの再送信など)は fail-closed で
        // 拒否され、元の CompletedAt / CompletionNote が黙って上書きされないことを確認する。
        // 上書きを許すと有効性評価日時が完了日時より前になる等、KPI の時系列整合性が壊れる。
        var measure = await SeedMeasureAsync("内科病棟");
        var originalCompletedAt = new DateTime(2026, 6, 1, 10, 0, 0);
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = originalCompletedAt;
        measure.CompletionNote = "最初の完了メモ";
        await _db.SaveChangesAsync();

        var result = await _controller.Complete(measure.Id, "2回目の完了メモ", measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Contains("すでに完了", _controller.TempData["Warning"] as string);
        // 元の完了情報が保持されていること
        var unchanged = await _db.PreventiveMeasures.AsNoTracking().FirstAsync(m => m.Id == measure.Id);
        Assert.Equal(originalCompletedAt, unchanged.CompletedAt);
        Assert.Equal("最初の完了メモ", unchanged.CompletionNote);
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

    // 担当部署フィルタのドロップダウン選択肢が Incident.Departments(発生部署の許可リスト)
    // ではなく、実際に保存されている対策の担当部署(自由記述)から重複なし・昇順で
    // 生成されることを確認する(許可リスト外の担当部署が永遠にヒットしない回帰の防止)
    [Fact]
    public async Task Index_ResponsibleDepartmentOptions_BuiltFromMeasureFreeTextDepartments()
    {
        // Incident.Departments の許可リストに無い自由記述の担当部署を持つ対策を投入する
        // (看護部を 2 件にして重複除去も同時に検証する)
        await SeedMeasureAsync("内科病棟", responsibleDepartment: "看護部");
        await SeedMeasureAsync("内科病棟", responsibleDepartment: "医療安全室");
        await SeedMeasureAsync("外来", responsibleDepartment: "看護部");

        // カンバン一覧を無条件で表示する
        var result = await _controller.Index(null, null, null, null, null);

        Assert.IsType<ViewResult>(result);
        // ドロップダウン選択肢が ViewBag に積まれていること
        // (ViewBag は dynamic のため object へキャストして型を確定させてから検証する)
        var options = Assert.IsType<List<string>>((object)_controller.ViewBag.ResponsibleDepartmentOptions);
        // 重複が除去され 2 件になっていること
        Assert.Equal(2, options.Count);
        // 実データ由来の自由記述の担当部署が両方含まれていること
        Assert.Contains("看護部", options);
        Assert.Contains("医療安全室", options);
        // 昇順で安定して並んでいること
        Assert.Equal(options.OrderBy(d => d).ToList(), options);
    }

    // 自由記述の担当部署でも完全一致フィルタが機能することを確認する
    // (選択肢の生成元を実データに変えてもフィルタ挙動は完全一致のまま)
    [Fact]
    public async Task Index_FilterByFreeTextResponsibleDepartment_ReturnsMatchingOnly()
    {
        // 異なる担当部署の対策を 2 件投入する
        await SeedMeasureAsync("内科病棟", responsibleDepartment: "看護部");
        await SeedMeasureAsync("内科病棟", responsibleDepartment: "医療安全室");

        // 担当部署「看護部」で絞り込んで一覧を表示する
        var result = await _controller.Index(null, null, "看護部", null, null);

        // ビューの主モデル(絞り込み後の対策一覧)を取り出す
        var view = Assert.IsType<ViewResult>(result);
        var measures = Assert.IsType<List<PreventiveMeasure>>(view.Model);
        // 看護部の 1 件だけが返ること(完全一致フィルタの維持)
        var matched = Assert.Single(measures);
        Assert.Equal("看護部", matched.ResponsibleDepartment);
    }

    // MaxKanbanRows 件を超えない範囲では、絞り込み後の対策が全件そのまま返り、
    // Truncated フラグが立たず、TotalCount も返却件数と一致することを確認する
    [Fact]
    public async Task Index_WithinLimit_ReturnsAllMeasuresAndIsNotTruncated()
    {
        // 少数(3件)を投入する。上限(1000件)には遠く及ばない
        for (var i = 0; i < 3; i++)
        {
            await SeedMeasureAsync($"内科病棟{i}");
        }

        var result = await _controller.Index(null, null, null, null, null);

        Assert.IsType<ViewResult>(result);
        Assert.Equal(3, _controller.ViewBag.TotalCount);
        Assert.False((bool)_controller.ViewBag.Truncated);
    }

    // MaxKanbanRows 件を超える対策が絞り込みに一致する場合、取得件数自体は上限で
    // 打ち切られるが、TotalCount は上限適用前の真の総数を反映し、Truncated が
    // true になることを確認する(§8 一覧取得の上限の回帰防止)
    [Fact]
    public async Task Index_ExceedsMaxKanbanRows_TruncatesRowsButReportsTrueTotalCount()
    {
        // MaxKanbanRows をわずかに超える件数を1回の SaveChangesAsync でまとめて投入する
        // (SeedMeasureAsync を件数分呼ぶと保存が都度発生し遅くなるため、ここだけ直接構築する)
        const int seedCount = PreventiveMeasuresController.MaxKanbanRows + 5;
        for (var i = 0; i < seedCount; i++)
        {
            var incident = new Incident
            {
                Department = "内科病棟",
                IncidentType = IncidentTypeKind.Fall,
                Severity = IncidentSeverity.Level2,
                Description = "上限検証用",
                ReporterName = "担当",
                OccurredAt = DateTime.Now
            };
            incident.PreventiveMeasures.Add(new PreventiveMeasure
            {
                Incident = incident,
                Description = $"対策{i}",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当A",
                ResponsibleDepartment = "内科病棟",
                DueDate = DateTime.Today.AddDays(30),
                Priority = 2
            });
            _db.Incidents.Add(incident);
        }
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null);

        Assert.IsType<ViewResult>(result);
        // TotalCount は上限を超えた真の総数(全件)を反映する
        Assert.Equal(seedCount, _controller.ViewBag.TotalCount);
        // 上限を超えたため Truncated は true
        Assert.True((bool)_controller.ViewBag.Truncated);
        // 実際にレーンへ振り分けられた対策の合計は上限(MaxKanbanRows)で打ち切られている
        var plannedCount = ((List<PreventiveMeasure>)_controller.ViewBag.Planned).Count;
        var inProgressCount = ((List<PreventiveMeasure>)_controller.ViewBag.InProgress).Count;
        var completedCount = ((List<PreventiveMeasure>)_controller.ViewBag.Completed).Count;
        Assert.Equal(PreventiveMeasuresController.MaxKanbanRows, plannedCount + inProgressCount + completedCount);
    }
}
