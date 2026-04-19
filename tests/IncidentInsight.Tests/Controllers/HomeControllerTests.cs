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
        _controller = new HomeController(_db, new RecurrenceService(), new SystemClock());
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
