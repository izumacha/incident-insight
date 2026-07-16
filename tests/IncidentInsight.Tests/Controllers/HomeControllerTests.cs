using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Controllers;

public class HomeControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly HomeController _controller;

    public HomeControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new HomeController(_db, new RecurrenceService(new SystemClock()), new SystemClock());
        // Existing tests assume a privileged viewer; Staff-scope tests build their own.
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    private Incident MakeIncident(string dept = "内科病棟",
        IncidentTypeKind type = IncidentTypeKind.Medication,
        IncidentSeverity severity = IncidentSeverity.Level2,
        DateTime? occurredAt = null) => new()
    {
        Department = dept,
        IncidentType = type,
        Severity = severity,
        Description = "テスト",
        ReporterName = "テスト太郎",
        OccurredAt = occurredAt ?? DateTime.Now,
        ReportedAt = DateTime.Now
    };

    [Fact]
    public async Task Index_EmptyDb_ReturnsDashboardWithZeroCounts()
    {
        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.NotNull(vm);
        Assert.Equal(0, vm.TotalIncidents);
        Assert.Equal(0, vm.OpenMeasures);
        Assert.Equal(0, vm.OverdueMeasures);
    }

    [Fact]
    public async Task Index_PeriodYear_CountsAllYearIncidents()
    {
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: DateTime.Today.AddMonths(-6)),
            MakeIncident(occurredAt: DateTime.Today.AddMonths(-11)),
            MakeIncident(occurredAt: DateTime.Today.AddYears(-2))  // 期間外
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("year") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(2, vm!.TotalIncidents);
        Assert.Equal("year", vm.Period);
    }

    [Fact]
    public async Task Index_PeriodMonth_CountsLastMonthOnly()
    {
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: DateTime.Today.AddDays(-15)),  // 期間内
            MakeIncident(occurredAt: DateTime.Today.AddMonths(-3))  // 期間外
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("month") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(1, vm!.TotalIncidents);
    }

    [Fact]
    public async Task Index_PeriodWeek_KpiWindowMatchesChartWindow()
    {
        // 回帰テスト: 以前は KPI(TotalIncidents)の集計開始日が today.AddDays(-7) で
        // 実質8暦日分(today-7〜today)を数えていたが、直下の折れ線グラフ(MonthlyCounts)は
        // today.AddDays(-6)で7暦日分(today-6〜today)しか集計しておらず、
        // ちょうど境界のtoday-7に発生したインシデントはKPI合計には含まれるのに
        // グラフの7本のバーには1件も現れないという不整合があった。
        // 修正後は両方とも同じ7暦日窓(today-6〜today)を使うため、today-7のインシデントは
        // KPIからも除外され、グラフの日数(7)と整合する。
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: DateTime.Today.AddDays(-7)),  // 窓の外(境界日の1日前)
            MakeIncident(occurredAt: DateTime.Today.AddDays(-6))   // 窓の中(境界日)
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("week") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // today-7 のインシデントは除外され、today-6 の1件だけがKPIに数えられる
        Assert.Equal(1, vm!.TotalIncidents);
        // グラフ側も同じ1件だけを today-6 の日に計上している
        Assert.Equal(7, vm.MonthlyCounts.Count);
        Assert.Equal(1, vm.MonthlyCounts.Sum(c => c.Count));
    }

    [Fact]
    public async Task Index_OverdueMeasures_CountsOnlyNotCompleted()
    {
        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _db.PreventiveMeasures.AddRange(
            new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = "対策A",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当A",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Planned,
                DueDate = DateTime.Today.AddDays(-5)  // overdue
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = "対策B",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当B",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Completed,
                DueDate = DateTime.Today.AddDays(-10)  // completed は除外
            }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(1, vm!.OverdueMeasures);
        Assert.Equal(1, vm.OpenMeasures);
        Assert.Equal(1, vm.CompletedMeasures);
    }

    [Fact]
    public async Task Index_OverdueMeasureList_IsCappedButKpiCountReflectsFullTotal()
    {
        // 回帰テスト: 以前は「期限超過の対策一覧」パネル用のクエリに上限がなく、
        // 画面には Take(5) で 5 件しか出さないにもかかわらず DB からは期限超過対策を
        // 全件フェッチしていた(§8 一覧取得は必ず上限を持たせる、に反する無制限取得)。
        // ここでは HomeController.OverdueAlertLimit(5) を超える件数の期限超過対策を用意し、
        // (1) OverdueMeasureList が上限件数までしか含まれないこと、
        // (2) KPI の OverdueMeasures(件数)は上限に関わらず全件を正しく数えていること、
        // の両方を確認する。
        const int overdueAlertLimit = 5; // HomeController.OverdueAlertLimit と同じ値(private のためテスト側で明示)
        const int overdueCountInDb = overdueAlertLimit + 3; // 上限より多く用意する

        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        for (int i = 0; i < overdueCountInDb; i++)
        {
            _db.PreventiveMeasures.Add(new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = $"対策{i}",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Planned,
                DueDate = DateTime.Today.AddDays(-1 - i) // すべて期限超過、期限日はバラける
            });
        }
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // KPI の総数は上限を超えても正確に全件(overdueCountInDb)を反映する
        Assert.Equal(overdueCountInDb, vm!.OverdueMeasures);
        // 一覧パネルは OverdueAlertLimit 件までしか返さない(DB 側で切り捨て済み)
        Assert.Equal(overdueAlertLimit, vm.OverdueMeasureList.Count);
    }

    [Fact]
    public async Task Index_RecurrenceDetection_AlertsForSameDeptTypeCategory()
    {
        var category = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var inc1 = MakeIncident(dept: "外科病棟", type: IncidentTypeKind.Medication, occurredAt: DateTime.Today.AddDays(-10));
        var inc2 = MakeIncident(dept: "外科病棟", type: IncidentTypeKind.Medication, occurredAt: DateTime.Today.AddDays(-20));
        _db.Incidents.AddRange(inc1, inc2);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = inc1.Id, CauseCategoryId = category.Id, Why1 = "原因1" },
            new CauseAnalysis { IncidentId = inc2.Id, CauseCategoryId = category.Id, Why1 = "原因2" }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.NotEmpty(vm!.RecurrenceAlerts);
        Assert.Contains(vm.RecurrenceAlerts, a => a.PatternDescription.Contains("外科病棟"));
    }

    [Fact]
    public async Task Index_WeekPeriod_MonthlyCounts_Has7DailyLabels()
    {
        var result = await _controller.Index("week") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(7, vm!.MonthlyCounts.Count);
        // Daily labels should be in M/d format
        Assert.Matches(@"^\d{1,2}/\d{1,2}$", vm.MonthlyCounts.First().Label);
    }

    [Fact]
    public async Task Index_YearPeriod_MonthlyCounts_Has12MonthLabels()
    {
        var result = await _controller.Index("year") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(12, vm!.MonthlyCounts.Count);
        Assert.Matches(@"^\d{4}年\d{1,2}月$", vm.MonthlyCounts.First().Label);
    }
}
