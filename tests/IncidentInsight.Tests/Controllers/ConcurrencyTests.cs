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
            // InMemory プロバイダはトランザクションをサポートしないため警告が出るが、
            // テスト用途ではトランザクション整合性を検証しないので例外扱いにせず無視する。
            // 本番の SQLite/SQL Server/PostgreSQL では BeginTransactionAsync は正常に動作する
            // (PreventiveMeasuresController.Delete が TOCTOU 対策で Serializable
            // トランザクションを使うため必要)。
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        _db = new ThrowingDbContext(options);
    }

    public void Dispose() => _db.Dispose();

    private sealed class ThrowingDbContext : ApplicationDbContext
    {
        public bool ThrowOnNextSave { get; set; }
        // Serializable分離レベルでの直列化エラーは、行のConcurrencyToken不一致とは別に、
        // ConcurrencyExceptionではないただのDbUpdateExceptionとしてSaveChangesAsyncから
        // 飛んでくることがある(PostgreSQL/SQL Serverの実際の直列化エラーを模す)。
        public bool ThrowSerializationConflictOnNextSave { get; set; }

        public ThrowingDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            if (ThrowOnNextSave)
            {
                ThrowOnNextSave = false;
                throw new DbUpdateConcurrencyException("simulated concurrency conflict");
            }
            if (ThrowSerializationConflictOnNextSave)
            {
                ThrowSerializationConflictOnNextSave = false;
                // DbUpdateConcurrencyExceptionのサブタイプではない、素のDbUpdateExceptionとして投げる
                throw new DbUpdateException("simulated serialization conflict");
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
        var controller = new IncidentMeasuresController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), new RecurrenceService(new SystemClock()), NullLogger<IncidentMeasuresController>.Instance);
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
    public async Task IncidentsDelete_OnConcurrencyConflict_SetsWarningAndRedirectsToDetails()
    {
        // 削除中に他ユーザーの更新と衝突した場合、未処理例外にせず詳細画面へ警告付きで戻す。
        var incident = await SeedIncidentAsync();
        var controller = new IncidentsController(_db, UserContextHelper.BuildAuthService(), new RecurrenceService(new SystemClock()), new SystemClock(), NullLogger<IncidentsController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        _db.ThrowOnNextSave = true;
        var result = await controller.Delete(incident.Id, incident.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Details), redirect.ActionName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.NotNull(controller.TempData["Warning"]);
        Assert.Contains("他のユーザ", controller.TempData["Warning"]!.ToString());
        // 例外で中断しても DB からは削除されていないこと(ロールバック相当)を確認
        Assert.True(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
    }

    [Fact]
    public async Task PreventiveMeasuresDelete_OnConcurrencyConflict_SetsWarningAndRedirectsToIndex()
    {
        // 唯一の対策にならないよう sibling を1件追加してから削除を試みる
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        await SeedMeasureAsync(incident.Id);
        var controller = new PreventiveMeasuresController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        _db.ThrowOnNextSave = true;
        var result = await controller.Delete(measure.Id, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.NotNull(controller.TempData["Warning"]);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task PreventiveMeasuresDelete_OnSerializationConflict_SetsWarningAndRedirectsToIndex()
    {
        // 回帰テスト(/code-review 指摘対応): TOCTOU対策のSerializableトランザクションは
        // 元々コミット時点のDbExceptionしか捕捉しておらず、SaveChangesAsync自体が
        // (ConcurrencyToken不一致とは別の)直列化エラー由来のDbUpdateExceptionを
        // 投げるケースを捕捉できていなかった。SQLiteでは実際に競合状態を再現しても
        // このパスには到達しない(単一ライタロックでブロックされるため)ため、この
        // ThrowingDbContextで直接シミュレートして検証する。
        var incident = await SeedIncidentAsync();
        var measure = await SeedMeasureAsync(incident.Id);
        await SeedMeasureAsync(incident.Id);
        var controller = new PreventiveMeasuresController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        _db.ThrowSerializationConflictOnNextSave = true;
        var result = await controller.Delete(measure.Id, measure.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.NotNull(controller.TempData["Warning"]);
        // 例外時は削除が確定していないこと
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task CauseAnalysesDeleteCauseAnalysis_OnConcurrencyConflict_SetsWarningAndRedirectsToDetails()
    {
        var incident = await SeedIncidentAsync();
        var category = new CauseCategory { Name = "テスト分類", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        var analysis = new CauseAnalysis
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "削除対象"
        };
        _db.CauseAnalyses.Add(analysis);
        await _db.SaveChangesAsync();
        var controller = new CauseAnalysesController(_db, UserContextHelper.BuildAuthService(), new SystemClock(), new RecurrenceService(new SystemClock()), NullLogger<CauseAnalysesController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        _db.ThrowOnNextSave = true;
        var result = await controller.DeleteCauseAnalysis(analysis.Id, analysis.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        Assert.Equal("Incidents", redirect.ControllerName);
        Assert.Equal(incident.Id, redirect.RouteValues!["id"]);
        Assert.NotNull(controller.TempData["Warning"]);
        Assert.True(await _db.CauseAnalyses.AnyAsync(a => a.Id == analysis.Id));
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

    [Fact]
    public async Task IncidentsDelete_WithStaleClientToken_RejectsAndPreservesIncident()
    {
        // 回帰テスト: Delete は元々 concurrencyToken を受け取らず、DB から取得した
        // 最新値をそのまま削除していたため、画面表示後に他ユーザーが更新した内容が
        // あっても検知できなかった(ConcurrencyTests の他ケースは ThrowingDbContext で
        // 例外を強制するだけで、実際の OriginalValue ピン留めまでは検証していない)。
        // InMemory プロバイダは [ConcurrencyCheck] を実施しないため、ここでは本物の
        // 楽観ロックが効く SQLite ファイル DB を使い、表示時点のトークンと DB の
        // 現在値が食い違う場合に削除が拒否されることを直接検証する。
        var dbPath = Path.Combine(Path.GetTempPath(), $"incident-insight-delete-concurrency-{Guid.NewGuid():N}.db");
        var connectionString = $"Data Source={dbPath}";
        try
        {
            int incidentId;
            Guid staleToken;
            // マイグレーション経由ではなく EnsureCreated で素早くスキーマだけ作る
            // (このテストは ConcurrencyToken の突合せだけを見るため、既存マイグレーション
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
                setupDb.Incidents.Add(incident);
                await setupDb.SaveChangesAsync();
                incidentId = incident.Id;
                // 「画面表示時点」のトークンとして控えておく(この後 DB 側だけ更新する)
                staleToken = incident.ConcurrencyToken;

                // 別ユーザーが先に編集した状況を模して、DB側のトークンだけを回転させる。
                // AuditSaveChangesInterceptor は本番では Modified 時にトークンを自動回転
                // させるが、このインターセプターは Program.cs の DI 経由でのみ
                // ApplicationDbContext に登録されるため、テストが直接 `new
                // ApplicationDbContext(options)` するこの経路には付いていない。
                // そのため、ここでは直接 ConcurrencyToken を書き換えて衝突状態を作る。
                incident.Description = "他ユーザーによる更新後";
                incident.ConcurrencyToken = Guid.NewGuid();
                await setupDb.SaveChangesAsync();
                Assert.NotEqual(staleToken, incident.ConcurrencyToken);
            }

            await using var db = new ApplicationDbContext(
                new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options);
            var controller = new IncidentsController(db, UserContextHelper.BuildAuthService(), new RecurrenceService(new SystemClock()), new SystemClock(), NullLogger<IncidentsController>.Instance);
            UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

            // 画面表示時点の(今はもう古い)トークンで削除を試みる
            var result = await controller.Delete(incidentId, staleToken);

            var redirect = Assert.IsType<RedirectToActionResult>(result);
            Assert.Equal(nameof(IncidentsController.Details), redirect.ActionName);
            Assert.NotNull(controller.TempData["Warning"]);
            // 拒否され、インシデントは削除されずに残っていること
            Assert.True(await db.Incidents.AnyAsync(i => i.Id == incidentId));
        }
        finally
        {
            // 一時DBファイルの後始末(共通ヘルパーで WAL/SHM 等の補助ファイルも一括削除)
            SqliteTestFiles.Cleanup(dbPath);
        }
    }
}
