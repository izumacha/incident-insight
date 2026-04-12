using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ApplicationDbContext _db;

    public HomeController(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index(string? period)
    {
        period ??= "year";
        var today = DateTime.Today;
        var thisMonthStart = new DateTime(today.Year, today.Month, 1);
        var ninetyDaysAgo = today.AddDays(-90);

        // Period window for KPIs and trend chart
        var periodStart = period switch
        {
            "week"    => today.AddDays(-7),
            "month"   => today.AddMonths(-1),
            "quarter" => today.AddMonths(-3),
            _         => today.AddYears(-1)
        };

        var allIncidents = await _db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory)
            .Include(i => i.PreventiveMeasures)
            .OrderByDescending(i => i.OccurredAt)
            .ToListAsync();

        var periodIncidents = allIncidents.Where(i => i.OccurredAt >= periodStart).ToList();

        var allMeasures = await _db.PreventiveMeasures.ToListAsync();

        var totalIncidents = periodIncidents.Count;
        var thisMonthIncidents = allIncidents.Count(i => i.OccurredAt >= thisMonthStart);
        var openMeasures = allMeasures.Count(m => m.Status != "Completed");
        var overdueMeasures = allMeasures.Count(m => m.IsOverdue);
        var completedMeasures = allMeasures.Count(m => m.Status == "Completed");
        var failedMeasures = allMeasures.Count(m => m.RecurrenceObserved == true);

        var recentIncidents = allIncidents.Take(5).ToList();

        var overdueMeasureList = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .Where(m => m.Status != "Completed" && m.DueDate < today)
            .OrderBy(m => m.DueDate)
            .ToListAsync();

        // Monthly / weekly counts for trend chart
        var monthlyCounts = new List<MonthlyCount>();
        if (period == "week")
        {
            // Daily for last 7 days
            for (int i = 6; i >= 0; i--)
            {
                var day = today.AddDays(-i);
                var count = allIncidents.Count(inc => inc.OccurredAt.Date == day);
                monthlyCounts.Add(new MonthlyCount { Label = day.ToString("M/d"), Count = count });
            }
        }
        else
        {
            int months = period switch { "month" => 4, "quarter" => 6, _ => 12 };
            for (int i = months - 1; i >= 0; i--)
            {
                var monthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
                var monthEnd = monthStart.AddMonths(1);
                var count = allIncidents.Count(inc => inc.OccurredAt >= monthStart && inc.OccurredAt < monthEnd);
                monthlyCounts.Add(new MonthlyCount { Label = monthStart.ToString("yyyy年M月"), Count = count });
            }
        }

        // Recurrence detection (always based on 90-day window)
        var recentList = allIncidents.Where(i => i.OccurredAt >= ninetyDaysAgo).ToList();
        var recurrenceAlerts = new List<RecurrenceAlert>();
        var processed = new HashSet<int>();

        foreach (var incident in recentList)
        {
            if (processed.Contains(incident.Id)) continue;
            var catIds = incident.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
            var similar = allIncidents
                .Where(o => o.Id != incident.Id
                    && o.Department == incident.Department
                    && o.IncidentType == incident.IncidentType
                    && o.CauseAnalyses.Any(ca => catIds.Contains(ca.CauseCategoryId)))
                .ToList();

            if (similar.Any())
            {
                recurrenceAlerts.Add(new RecurrenceAlert
                {
                    CurrentIncident = incident,
                    SimilarIncidents = similar,
                    PatternDescription = $"{incident.Department} / {incident.IncidentType}"
                });
                processed.Add(incident.Id);
                foreach (var s in similar) processed.Add(s.Id);
            }
        }

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
    public IActionResult Error() => View();
}
