using System.Diagnostics;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly IRecurrenceService _recurrence;
    private readonly IClock _clock;

    public HomeController(ApplicationDbContext db, IRecurrenceService recurrence, IClock clock)
    {
        _db = db;
        _recurrence = recurrence;
        _clock = clock;
    }

    public async Task<IActionResult> Index(string? period)
    {
        period ??= "year";
        var today = _clock.Today;
        var thisMonthStart = new DateTime(today.Year, today.Month, 1);

        // Period window for KPIs and trend chart
        var periodStart = period switch
        {
            "week"    => today.AddDays(-7),
            "month"   => today.AddMonths(-1),
            "quarter" => today.AddMonths(-3),
            _         => today.AddYears(-1)
        };

        // Staff は自部署のデータのみ。Admin / RiskManager はフィルタなし。
        var incidents = _db.Incidents.AsNoTracking().ScopedByUser(User);
        var measures = _db.PreventiveMeasures.AsNoTracking().ScopedByUser(User);

        // KPI counts are aggregated server-side (no full-table materialization).
        var totalIncidents = await incidents
            .CountAsync(i => i.OccurredAt >= periodStart);
        var thisMonthIncidents = await incidents
            .CountAsync(i => i.OccurredAt >= thisMonthStart);
        var openMeasures = await measures
            .CountAsync(m => m.Status != MeasureStatus.Completed);
        var overdueMeasures = await measures
            .CountAsync(m => m.Status != MeasureStatus.Completed && m.DueDate < today);
        var completedMeasures = await measures
            .CountAsync(m => m.Status == MeasureStatus.Completed);
        var failedMeasures = await measures
            .CountAsync(m => m.RecurrenceObserved == true);

        var recentIncidents = await incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory)
            .Include(i => i.PreventiveMeasures)
            .OrderByDescending(i => i.OccurredAt)
            .Take(5)
            .ToListAsync();

        var overdueMeasureList = await measures
            .Include(m => m.Incident)
            .Where(m => m.Status != MeasureStatus.Completed && m.DueDate < today)
            .OrderBy(m => m.DueDate)
            .ToListAsync();

        // Trend chart is aggregated SQL-side (GroupBy → Year/Month or Date) so the
        // controller never materializes full-table incident rows just to count them.
        var monthlyCounts = new List<MonthlyCount>();
        if (period == "week")
        {
            var weekStart = today.AddDays(-6);
            var weekEnd = today.AddDays(1);
            var dailyGroups = await incidents
                .Where(i => i.OccurredAt >= weekStart && i.OccurredAt < weekEnd)
                .GroupBy(i => i.OccurredAt.Date)
                .Select(g => new { Day = g.Key, Count = g.Count() })
                .ToListAsync();
            var byDay = dailyGroups.ToDictionary(g => g.Day, g => g.Count);
            for (int i = 6; i >= 0; i--)
            {
                var day = today.AddDays(-i);
                byDay.TryGetValue(day, out var count);
                monthlyCounts.Add(new MonthlyCount { Label = day.ToString("M/d"), Count = count });
            }
        }
        else
        {
            int months = period switch { "month" => 4, "quarter" => 6, _ => 12 };
            var firstMonthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-(months - 1));
            var monthlyGroups = await incidents
                .Where(i => i.OccurredAt >= firstMonthStart)
                .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
                .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
                .ToListAsync();
            var byMonth = monthlyGroups.ToDictionary(g => (g.Year, g.Month), g => g.Count);
            for (int i = months - 1; i >= 0; i--)
            {
                var monthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
                byMonth.TryGetValue((monthStart.Year, monthStart.Month), out var count);
                monthlyCounts.Add(new MonthlyCount { Label = monthStart.ToString("yyyy年M月"), Count = count });
            }
        }

        // 再発検出はサービスに集約。90 日ウィンドウは IncidentsController.Details (無制限) と
        // 業務ルールを揃えたまま、ダッシュボードでのみ時間窓を適用する。
        var recurrenceAlerts = await _recurrence.FindRecurrenceAlertsAsync(incidents, TimeSpan.FromDays(90));

        var vm = new DashboardViewModel
        {
            Period = period,
            TotalIncidents = totalIncidents,
            ThisMonthIncidents = thisMonthIncidents,
            OpenMeasures = openMeasures,
            OverdueMeasures = overdueMeasures,
            CompletedMeasures = completedMeasures,
            FailedMeasures = failedMeasures,
            RecentIncidents = recentIncidents,
            OverdueMeasureList = overdueMeasureList,
            RecurrenceAlerts = recurrenceAlerts,
            MonthlyCounts = monthlyCounts
        };

        return View(vm);
    }

    [AllowAnonymous]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult Error()
    {
        var vm = new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
        };
        return View(vm);
    }
}
