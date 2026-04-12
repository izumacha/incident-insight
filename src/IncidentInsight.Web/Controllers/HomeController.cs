using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class HomeController : Controller
{
    private readonly ApplicationDbContext _db;

    public HomeController(ApplicationDbContext db)
    {
        _db = db;
    }

    public async Task<IActionResult> Index()
    {
        var today = DateTime.Today;
        var thisMonthStart = new DateTime(today.Year, today.Month, 1);
        var ninetyDaysAgo = today.AddDays(-90);

        var allIncidents = await _db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory)
            .Include(i => i.PreventiveMeasures)
            .OrderByDescending(i => i.OccurredAt)
            .ToListAsync();

        var allMeasures = await _db.PreventiveMeasures.ToListAsync();

        var totalIncidents = allIncidents.Count;
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

        // Monthly counts (last 12 months)
        var monthlyCounts = new List<MonthlyCount>();
        for (int i = 11; i >= 0; i--)
        {
            var monthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
            var monthEnd = monthStart.AddMonths(1);
            var count = allIncidents.Count(inc => inc.OccurredAt >= monthStart && inc.OccurredAt < monthEnd);
            monthlyCounts.Add(new MonthlyCount
            {
                Label = monthStart.ToString("yyyy年M月"),
                Count = count
            });
        }

        // Recurrence detection
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

    public IActionResult Error() => View();
}
