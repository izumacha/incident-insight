using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class IncidentReportsController(AppDbContext db) : Controller
{
    private static readonly TimeZoneInfo JapanTimeZone = ResolveJapanTimeZone();

    public async Task<IActionResult> Index()
    {
        var incidents = await db.IncidentReports
            .Include(i => i.Countermeasures)
            .OrderByDescending(i => i.OccurredAt)
            .ToListAsync();

        return View(incidents);
    }

    public async Task<IActionResult> Details(int id)
    {
        var incident = await db.IncidentReports
            .Include(i => i.Countermeasures)
            .FirstOrDefaultAsync(i => i.Id == id);

        if (incident is null) return NotFound();
        return View(incident);
    }

    public IActionResult Create() => View(new IncidentReport
    {
        OccurredAt = TimeZoneInfo.ConvertTime(DateTime.UtcNow, JapanTimeZone),
        LifecycleStatus = IncidentLifecycleStatus.Reported
    });

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(
        [Bind("Title,Department,Description,OccurredAt,CauseCategory,Severity,RecurrenceRisk,InitialResponse,RootCauseSummary,PotentialImpact,LifecycleStatus")]
        IncidentReport model,
        string? countermeasureAction,
        string? owner)
    {
        model.Title = model.Title.Trim();
        model.Department = model.Department.Trim();
        model.Description = model.Description.Trim();
        model.InitialResponse = model.InitialResponse.Trim();
        model.RootCauseSummary = model.RootCauseSummary.Trim();
        model.PotentialImpact = model.PotentialImpact.Trim();
        model.OccurredAt = TimeZoneInfo.ConvertTime(
            DateTime.SpecifyKind(model.OccurredAt, DateTimeKind.Local),
            JapanTimeZone);

        if (!ModelState.IsValid) return View(model);

        if (!string.IsNullOrWhiteSpace(countermeasureAction))
        {
            model.Countermeasures.Add(new Countermeasure
            {
                ActionPlan = countermeasureAction.Trim(),
                Owner = owner?.Trim() ?? string.Empty,
                IsCompleted = false,
                ReviewNote = "初期登録"
            });
        }

        db.IncidentReports.Add(model);
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }

    private static TimeZoneInfo ResolveJapanTimeZone()
    {
        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById("Asia/Tokyo");
        }
        catch (TimeZoneNotFoundException)
        {
            return TimeZoneInfo.FindSystemTimeZoneById("Tokyo Standard Time");
        }
    }
}
