using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class IncidentReportsController(AppDbContext db) : Controller
{
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

    public IActionResult Create() => View(new IncidentReport());

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(IncidentReport model, string? countermeasureAction, string? owner)
    {
        if (!ModelState.IsValid) return View(model);

        if (!string.IsNullOrWhiteSpace(countermeasureAction))
        {
            model.Countermeasures.Add(new Countermeasure
            {
                ActionPlan = countermeasureAction,
                Owner = owner ?? string.Empty,
                IsCompleted = false
            });
        }

        db.IncidentReports.Add(model);
        await db.SaveChangesAsync();
        return RedirectToAction(nameof(Index));
    }
}
