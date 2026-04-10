using IncidentInsight.Web.Data;
using IncidentInsight.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class DashboardController(AppDbContext db) : Controller
{
    public async Task<IActionResult> Index()
    {
        var categoryStats = await db.IncidentReports
            .GroupBy(i => i.CauseCategory)
            .Select(g => new CategoryStat { Category = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .ToListAsync();

        var sixMonthsAgo = DateTime.UtcNow.AddMonths(-5);
        var monthlyStatsRaw = await db.IncidentReports
            .Where(i => i.OccurredAt >= sixMonthsAgo)
            .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
            .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
            .OrderBy(g => g.Year).ThenBy(g => g.Month)
            .ToListAsync();

        var vm = new DashboardViewModel
        {
            TotalIncidents = await db.IncidentReports.CountAsync(),
            OpenCountermeasures = await db.Countermeasures.CountAsync(c => !c.IsCompleted),
            CategoryStats = categoryStats,
            MonthlyStats = monthlyStatsRaw
                .Select(x => new MonthlyStat
                {
                    Month = $"{x.Year}-{x.Month:D2}",
                    Count = x.Count
                })
                .ToList()
        };

        return View(vm);
    }
}
