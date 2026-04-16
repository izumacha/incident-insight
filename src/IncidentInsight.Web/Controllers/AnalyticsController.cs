using IncidentInsight.Web.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class AnalyticsController : Controller
{
    private readonly ApplicationDbContext _db;

    public AnalyticsController(ApplicationDbContext db)
    {
        _db = db;
    }

    public IActionResult Index() => View();

    // GET /Analytics/MonthlyTrend
    public async Task<IActionResult> MonthlyTrend(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(department)) query = query.Where(i => i.Department == department);

        var incidents = await query.Select(i => new { i.OccurredAt }).ToListAsync();

        var today = DateTime.Today;
        var labels = new List<string>();
        var counts = new List<int>();

        for (int i = 11; i >= 0; i--)
        {
            var start = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
            var end = start.AddMonths(1);
            labels.Add(start.ToString("M月"));
            counts.Add(incidents.Count(x => x.OccurredAt >= start && x.OccurredAt < end));
        }

        return Json(new { labels, data = counts });
    }

    // GET /Analytics/ByCause
    public async Task<IActionResult> ByCause(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        var query = _db.CauseAnalyses.AsNoTracking()
            .Include(ca => ca.CauseCategory).ThenInclude(c => c!.Parent)
            .Include(ca => ca.Incident)
            .AsQueryable();

        if (!string.IsNullOrEmpty(department))
            query = query.Where(ca => ca.Incident.Department == department);
        if (dateFrom.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt <= dateTo.Value);

        var analyses = await query.ToListAsync();

        var grouped = analyses
            .GroupBy(ca => ca.CauseCategory?.Parent?.Name ?? ca.CauseCategory?.Name ?? "不明")
            .Select(g => new { label = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToList();

        return Json(new
        {
            labels = grouped.Select(x => x.label),
            data = grouped.Select(x => x.count)
        });
    }

    // GET /Analytics/ByDepartment
    public async Task<IActionResult> ByDepartment(DateTime? dateFrom, DateTime? dateTo)
    {
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt <= dateTo.Value);

        var grouped = await query
            .GroupBy(i => i.Department)
            .Select(g => new { department = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        return Json(new
        {
            labels = grouped.Select(x => x.department),
            data = grouped.Select(x => x.count)
        });
    }

    // GET /Analytics/BySeverity
    public async Task<IActionResult> BySeverity(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        if (!string.IsNullOrEmpty(department)) query = query.Where(i => i.Department == department);
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt <= dateTo.Value);

        var severityOrder = new[] { "Level0", "Level1", "Level2", "Level3a", "Level3b", "Level4", "Level5" };
        var grouped = await query
            .GroupBy(i => i.Severity)
            .Select(g => new { severity = g.Key, count = g.Count() })
            .ToListAsync();

        var ordered = severityOrder
            .Select(s => new
            {
                label = Models.Incident.SeverityLevels.TryGetValue(s, out var name) ? name : s,
                count = grouped.FirstOrDefault(g => g.severity == s)?.count ?? 0
            })
            .ToList();

        return Json(new
        {
            labels = ordered.Select(x => x.label),
            data = ordered.Select(x => x.count)
        });
    }

    // GET /Analytics/MeasureStatus
    public async Task<IActionResult> MeasureStatus()
    {
        var today = DateTime.Today;
        var measures = await _db.PreventiveMeasures.AsNoTracking().ToListAsync();

        var planned = measures.Count(m => m.Status == "Planned" && !m.IsOverdue);
        var inProgress = measures.Count(m => m.Status == "InProgress" && !m.IsOverdue);
        var overdue = measures.Count(m => m.IsOverdue);
        var completed = measures.Count(m => m.Status == "Completed");

        return Json(new
        {
            labels = new[] { "計画中", "進行中", "期限超過", "完了" },
            data = new[] { planned, inProgress, overdue, completed },
            colors = new[] { "#ffc107", "#0d6efd", "#dc3545", "#198754" }
        });
    }

    // GET /Analytics/EffectivenessRating
    public async Task<IActionResult> EffectivenessRating()
    {
        var measures = await _db.PreventiveMeasures.AsNoTracking()
            .Where(m => m.EffectivenessRating != null)
            .ToListAsync();

        var counts = Enumerable.Range(1, 5)
            .Select(r => new { rating = r, count = measures.Count(m => m.EffectivenessRating == r) })
            .ToList();

        var recurred = measures.Count(m => m.RecurrenceObserved == true);
        var prevented = measures.Count(m => m.RecurrenceObserved == false);

        return Json(new
        {
            labels = new[] { "★1 (効果なし)", "★2", "★3 (普通)", "★4", "★5 (非常に効果あり)" },
            data = counts.Select(x => x.count),
            recurrenceStats = new { recurred, prevented }
        });
    }

    // GET /Analytics/GetSubcategories?parentId=1
    public async Task<IActionResult> GetSubcategories(int parentId)
    {
        var children = await _db.CauseCategories.AsNoTracking()
            .Where(c => c.ParentId == parentId)
            .OrderBy(c => c.DisplayOrder)
            .Select(c => new { c.Id, c.Name })
            .ToListAsync();

        return Json(children);
    }

    // GET /Analytics/ByIncidentType
    public async Task<IActionResult> ByIncidentType(DateTime? dateFrom, DateTime? dateTo)
    {
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt <= dateTo.Value);

        var grouped = await query
            .GroupBy(i => i.IncidentType)
            .Select(g => new { type = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        return Json(new
        {
            labels = grouped.Select(x => x.type),
            data = grouped.Select(x => x.count)
        });
    }
}
