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

public class IncidentsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly IncidentsController _controller;

    public IncidentsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            // InMemory プロバイダはトランザクションをサポートしないため警告が出るが、
            // テスト用途ではトランザクション整合性を検証しないので例外扱いにせず無視する。
            // 本番の SQLite/SQL Server/PostgreSQL では BeginTransactionAsync は正常に動作する。
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(new SystemClock()),
            new SystemClock(),
            NullLogger<IncidentsController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    private IncidentCreateEditViewModel ValidViewModel(string dept = "内科病棟") => new()
    {
        // DateTime.Now / DateTime.Today を直接使わず SystemClock 経由で取得する(CLAUDE.md §3 準拠)
        OccurredAt = new SystemClock().Now,
        Department = dept,
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト状況",
        ReporterName = "テスト太郎",
        Measures = new List<MeasureFormViewModel>
        {
            new()
            {
                Description = "テスト対策",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = dept,
                // DueDate も SystemClock 経由で設定(DateTime.Today を直接使わない)
                DueDate = new SystemClock().Today.AddDays(30),
                Priority = 2
            }
        }
    };

    // --- Create POST ---

    [Fact]
    public async Task Create_Post_ValidModel_RedirectsToDetails()
    {
        var vm = ValidViewModel();

        var result = await _controller.Create(vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesIncidentToDb()
    {
        var vm = ValidViewModel("外科病棟");

        await _controller.Create(vm);

        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("外科病棟", saved.Department);
        Assert.Equal(IncidentTypeKind.Medication, saved.IncidentType);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesMeasure()
    {
        var vm = ValidViewModel();

        await _controller.Create(vm);

        var measure = await _db.PreventiveMeasures.FirstOrDefaultAsync();
        Assert.NotNull(measure);
        Assert.Equal("テスト対策", measure.Description);
        Assert.Equal(MeasureStatus.Planned, measure.Status);
    }

    [Fact]
    public async Task Create_Post_InvalidModel_ReturnsCreateView()
    {
        _controller.ModelState.AddModelError("Department", "Required");
        var vm = new IncidentCreateEditViewModel();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
    }

    [Fact]
    public async Task Create_Post_WithoutMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_WithOnlyWhitespaceMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>
        {
            new() { Description = "   " },
            new() { Description = "\t" }
        };

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_PersistedMeasureWithFieldError_KeepsError_AndDoesNotSave()
    {
        // 対策内容ありの行(=保存対象)を 1 件持つ妥当な ViewModel を用意する
        var vm = ValidViewModel();
        // model binding が「実施期限が不正」と判定した状況を再現する(保存される行のエラー)
        _controller.ModelState.AddModelError("Measures[0].DueDate", "実施期限を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 保存される対策行のフィールド検証は除去されず、再描画されることを確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        // ModelState は無効のまま(エラーが残っている)であること
        Assert.False(_controller.ModelState.IsValid);
        // 該当行のエラーキーが残っていること(空行のように消されていないこと)
        Assert.True(_controller.ModelState.ContainsKey("Measures[0].DueDate"));
        // 不正なデータでインシデントが保存されていないことを確認する
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_EmptyExtraMeasureRow_RemovesItsErrors_AndSaves()
    {
        // [0] は妥当な対策行、[1] は対策内容が空の余分な行(保存されない行)を用意する
        var vm = ValidViewModel();
        vm.Measures.Add(new MeasureFormViewModel { Description = "" });
        // 空行に対して model binding が付けた Required エラーを再現する
        _controller.ModelState.AddModelError("Measures[1].DueDate", "実施期限を入力してください");
        _controller.ModelState.AddModelError("Measures[1].ResponsiblePerson", "担当者を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 空行のエラーは除去され、検証を通過して詳細画面へリダイレクトされることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        // 空行のエラーキーが ModelState から除去されていること
        Assert.False(_controller.ModelState.ContainsKey("Measures[1].DueDate"));
        // インシデントが 1 件保存されていること
        Assert.Single(_db.Incidents);
        // 保存される対策は対策内容ありの 1 件だけ(空行は永続化されない)であること
        Assert.Single(_db.PreventiveMeasures);
    }

    [Fact]
    public async Task Create_Post_EmptyRow_DoesNotStripHigherIndexedRowError()
    {
        // [0] は妥当な対策行。[1..9] は空行、[10] は対策内容ありの保存対象行にする。
        var vm = ValidViewModel();
        // インデックス 1〜10 を埋める(1〜9 は空行、10 は対策内容あり)
        for (int i = 1; i <= 10; i++)
        {
            // i==10 のときだけ対策内容を入れて保存対象の行にする
            vm.Measures.Add(new MeasureFormViewModel { Description = i == 10 ? "10番目の対策" : "" });
        }
        // 空行[1]の Required エラーと、保存対象[10]のフィールドエラーを再現する
        _controller.ModelState.AddModelError("Measures[1].DueDate", "実施期限を入力してください");
        _controller.ModelState.AddModelError("Measures[10].DueDate", "実施期限を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 空行[1]の除去で [10] のエラーが巻き込まれないこと(プレフィックス誤一致防止)を確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        // 保存対象[10]のエラーは残っていること
        Assert.True(_controller.ModelState.ContainsKey("Measures[10].DueDate"));
        // 空行[1]のエラーは除去されていること
        Assert.False(_controller.ModelState.ContainsKey("Measures[1].DueDate"));
        // 不正データなのでインシデントは保存されないこと
        Assert.Empty(_db.Incidents);
    }

    // --- Create POST: department scope enforcement for Staff (issue #63) ---

    [Fact]
    public async Task Create_Post_Staff_OverridesSubmittedDepartmentWithOwn()
    {
        // Staff(内科病棟)としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // フォームでは他部署(外科病棟)を選んで送信する
        var vm = ValidViewModel("外科病棟");

        // Create を実行する
        await _controller.Create(vm);

        // サーバ側で自部署(内科病棟)に上書きされて保存されることを確認する
        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("内科病棟", saved!.Department);
    }

    [Fact]
    public async Task Create_Post_StaffWithoutDepartmentClaim_ReturnsView_AndDoesNotSave()
    {
        // 所属部署クレームを持たない Staff としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Build(AppRoles.Staff));
        // 入力自体は妥当な ViewModel を送る
        var vm = ValidViewModel("内科病棟");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 自部署を特定できないため再描画され、インシデントは保存されないことを確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Department)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_Admin_KeepsSubmittedDepartment()
    {
        // 既定の Admin(全件アクセス)のまま、他部署を指定して送信する
        var vm = ValidViewModel("外来");

        // Create を実行する
        await _controller.Create(vm);

        // Admin はフォームの部署がそのまま保存される(上書きされない)ことを確認する
        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("外来", saved!.Department);
    }

    [Fact]
    public async Task Edit_Post_Staff_CannotReassignDepartmentToAnother()
    {
        // 内科病棟のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 楽観的同時実行制御用に現在のトークンを控える
        var token = incident.ConcurrencyToken;

        // Staff(内科病棟)としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // 編集フォームで部署を外科病棟へ付け替えようとする
        var vm = ValidViewModel("外科病棟");
        vm.ConcurrencyToken = token;

        // Edit を実行する
        await _controller.Edit(incident.Id, vm);

        // 部署が内科病棟のまま(他部署へ付け替えられない)ことを確認する
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("内科病棟", reloaded!.Department);
    }

    // --- Index GET / Filtering ---

    [Fact]
    public async Task Index_NoFilter_ReturnsAllIncidents()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(2, vm!.TotalCount);
    }

    [Fact]
    public async Task Index_DepartmentFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, "ICU", null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal("ICU", i.Department));
    }

    [Fact]
    public async Task Index_SeverityFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level4, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level0, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, IncidentSeverity.Level4, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Equal(IncidentSeverity.Level4, vm.Incidents[0].Severity);
    }

    [Fact]
    public async Task Index_SearchFilter_MatchesDescription()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "点滴ラインが抜けた", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "薬を誤投与", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("点滴", null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Contains("点滴", vm.Incidents[0].Description);
    }

    // --- Details GET ---

    [Fact]
    public async Task Details_ExistingId_ReturnsViewWithIncident()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "廊下で転倒",
            ReporterName = "山田",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(incident.Id) as ViewResult;
        var vm = result?.Model as IncidentDetailViewModel;

        Assert.NotNull(vm);
        Assert.Equal(incident.Id, vm.Incident.Id);
    }

    [Fact]
    public async Task Details_NonExistentId_ReturnsNotFound()
    {
        var result = await _controller.Details(9999);
        Assert.IsType<NotFoundResult>(result);
    }

    // --- Authorization: Staff scope ---

    [Fact]
    public async Task Index_Staff_OnlySeesOwnDepartment()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "内科病棟", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来",     IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal("内科病棟", i.Department));
    }

    [Fact]
    public async Task Details_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Details(incident.Id);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Edit_Get_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Edit(incident.Id);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Edit_Post_Staff_OtherDepartment_ReturnsForbid()
    {
        // 外来(他部署)のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "他部署担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 楽観的同時実行制御用に現在のトークンを控える
        var token = incident.ConcurrencyToken;

        // Staff(内科病棟)として、他部署(外来)のインシデントを編集しようとする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // 編集フォームを用意する(自部署を送っても、そもそも編集権限が無いはず)
        var vm = ValidViewModel("内科病棟");
        vm.ConcurrencyToken = token;

        // Edit(POST) を実行する
        var result = await _controller.Edit(incident.Id, vm);

        // 他部署のインシデントは部署スコープ認可で弾かれ ForbidResult になる
        // (部署上書きより前に認可で拒否されることの確認 = IDOR 防止)
        Assert.IsType<ForbidResult>(result);
        // インシデントの内容が一切変更されていないことを確認する
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("編集前", reloaded!.Description);
        Assert.Equal("外来", reloaded.Department);
    }

    [Fact]
    public async Task Delete_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Delete(incident.Id);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
    }

    [Fact]
    public async Task Delete_NotFound_ReturnsNotFound()
    {
        var result = await _controller.Delete(99999);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Admin_RemovesIncident()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "削除対象",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var result = await _controller.Delete(incident.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Index), redirect.ActionName);
        Assert.False(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
        Assert.NotNull(_controller.TempData["Success"]);
    }

    [Fact]
    public async Task Delete_RiskManager_RemovesIncident_RegardlessOfDepartment()
    {
        // RiskManager は全部署横断で削除できる (Policies.CanDeleteIncident)。
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署の削除対象",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.RiskManager());
        var result = await _controller.Delete(incident.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Index), redirect.ActionName);
        Assert.False(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
    }

    [Fact]
    public async Task Edit_Get_Staff_SameDepartment_ReturnsView()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "同部署",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Edit(incident.Id);

        Assert.IsType<ViewResult>(result);
    }
}
