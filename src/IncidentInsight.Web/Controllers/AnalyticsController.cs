using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize(Policy = Policies.CanViewAnalytics)]
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
        var today = DateTime.Today;
        var firstMonthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-11);

        var query = _db.Incidents.AsNoTracking()
            .Where(i => i.OccurredAt >= firstMonthStart);
        if (!string.IsNullOrEmpty(department)) query = query.Where(i => i.Department == department);

        var groups = await query
            .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
            .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
            .ToListAsync();
        var byMonth = groups.ToDictionary(g => (g.Year, g.Month), g => g.Count);

        var labels = new List<string>();
        var counts = new List<int>();
        for (int i = 11; i >= 0; i--)
        {
            var start = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
            labels.Add(start.ToString("M月"));
            byMonth.TryGetValue((start.Year, start.Month), out var count);
            counts.Add(count);
        }

        return Json(new { labels, data = counts });
    }

    // GET /Analytics/ByCause
    public async Task<IActionResult> ByCause(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        var query = _db.CauseAnalyses.AsNoTracking().AsQueryable();

        if (!string.IsNullOrEmpty(department))
            query = query.Where(ca => ca.Incident.Department == department);
        if (dateFrom.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt < dateTo.Value.Date.AddDays(1));

        // GroupBy runs on the server: we pick the parent name when present, otherwise
        // the leaf name, without materializing each CauseAnalysis row.
        var grouped = await query
            .GroupBy(ca => ca.CauseCategory!.Parent != null
                ? ca.CauseCategory.Parent.Name
                : ca.CauseCategory.Name)
            .Select(g => new { label = g.Key ?? "不明", count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

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
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

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
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

        var grouped = await query
            .GroupBy(i => i.Severity)
            .Select(g => new { severity = g.Key, count = g.Count() })
            .ToListAsync();

        var ordered = Enum.GetValues<IncidentSeverity>()
            .Select(s => new
            {
                label = EnumLabels.Japanese(s),
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
        // IsOverdue is a CLR-only computed property, so we inline its predicate
        // (Status != Completed && DueDate < today) so EF can translate it.
        var today = DateTime.Today;
        var counts = await _db.PreventiveMeasures.AsNoTracking()
            .GroupBy(_ => 1)
            .Select(g => new
            {
                Planned    = g.Count(m => m.Status == Models.Enums.MeasureStatus.Planned    && m.DueDate >= today),
                InProgress = g.Count(m => m.Status == Models.Enums.MeasureStatus.InProgress && m.DueDate >= today),
                Overdue    = g.Count(m => m.Status != Models.Enums.MeasureStatus.Completed  && m.DueDate <  today),
                Completed  = g.Count(m => m.Status == Models.Enums.MeasureStatus.Completed)
            })
            .FirstOrDefaultAsync();

        var planned = counts?.Planned ?? 0;
        var inProgress = counts?.InProgress ?? 0;
        var overdue = counts?.Overdue ?? 0;
        var completed = counts?.Completed ?? 0;

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
        var ratings = await _db.PreventiveMeasures.AsNoTracking()
            .Where(m => m.EffectivenessRating != null)
            .GroupBy(m => m.EffectivenessRating!.Value)
            .Select(g => new { Rating = g.Key, Count = g.Count() })
            .ToListAsync();

        var byRating = ratings.ToDictionary(x => x.Rating, x => x.Count);
        var counts = Enumerable.Range(1, 5)
            .Select(r => byRating.TryGetValue(r, out var c) ? c : 0)
            .ToList();

        var recurred = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == true);
        var prevented = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == false);

        return Json(new
        {
            labels = new[] { "★1 (効果なし)", "★2", "★3 (普通)", "★4", "★5 (非常に効果あり)" },
            data = counts,
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
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

        var grouped = await query
            .GroupBy(i => i.IncidentType)
            .Select(g => new { type = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        return Json(new
        {
            labels = grouped.Select(x => IncidentTypeMapping.JapaneseLabel(x.type)),
            data = grouped.Select(x => x.count)
        });
    }
}
