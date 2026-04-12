using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class PreventiveMeasuresController : Controller
{
    private readonly ApplicationDbContext _db;

    public PreventiveMeasuresController(ApplicationDbContext db)
    {
        _db = db;
    }

    // GET /PreventiveMeasures
    public async Task<IActionResult> Index(string? status, string? responsible,
        string? responsibleDepartment, DateTime? dateFrom, DateTime? dateTo)
    {
        var query = _db.PreventiveMeasures
            .Include(m => m.Incident)
            .AsQueryable();

        if (!string.IsNullOrEmpty(status))
            query = query.Where(m => m.Status == status);
        if (!string.IsNullOrEmpty(responsible))
            query = query.Where(m => m.ResponsiblePerson.Contains(responsible) || m.ResponsibleDepartment.Contains(responsible));
        if (!string.IsNullOrEmpty(responsibleDepartment))
            query = query.Where(m => m.ResponsibleDepartment == responsibleDepartment);
        if (dateFrom.HasValue)
            query = query.Where(m => m.DueDate >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(m => m.DueDate <= dateTo.Value);

        var measures = await query.OrderBy(m => m.DueDate).ToListAsync();

        var today = DateTime.Today;
        var planned = measures.Where(m => m.Status == "Planned").OrderBy(m => m.DueDate).ToList();
        var inProgress = measures.Where(m => m.Status == "InProgress").OrderBy(m => m.DueDate).ToList();
        var completed = measures.Where(m => m.Status == "Completed").OrderByDescending(m => m.CompletedAt).ToList();

        ViewBag.Planned = planned;
        ViewBag.InProgress = inProgress;
        ViewBag.Completed = completed;
        ViewBag.FilterStatus = status;
        ViewBag.FilterResponsible = responsible;
        ViewBag.FilterResponsibleDepartment = responsibleDepartment;
        ViewBag.DateFrom = dateFrom;
        ViewBag.DateTo = dateTo;

        // Stats
        ViewBag.TotalCount = measures.Count;
        ViewBag.OverdueCount = measures.Count(m => m.IsOverdue);
        ViewBag.CompletionRate = measures.Count == 0 ? 0
            : Math.Round((double)completed.Count / measures.Count * 100, 1);
        ViewBag.FailedCount = measures.Count(m => m.RecurrenceObserved == true);

        return View(measures);
    }

    // GET /PreventiveMeasures/Create?incidentId=3
    public async Task<IActionResult> Create(int? incidentId)
    {
        if (incidentId == null) return BadRequest();
        var incident = await _db.Incidents.FindAsync(incidentId);
        if (incident == null) return NotFound();

        ViewBag.Incident = incident;
        var vm = new MeasureFormViewModel
        {
            IncidentId = incidentId.Value,
            DueDate = DateTime.Today.AddDays(30)
        };
        return View(vm);
    }

    // POST /PreventiveMeasures/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(MeasureFormViewModel vm)
    {
        if (!ModelState.IsValid)
        {
            ViewBag.Incident = await _db.Incidents.FindAsync(vm.IncidentId);
            return View(vm);
        }

        _db.PreventiveMeasures.Add(new PreventiveMeasure
        {
            IncidentId = vm.IncidentId,
            Description = vm.Description,
            MeasureType = vm.MeasureType,
            ResponsiblePerson = vm.ResponsiblePerson,
            ResponsibleDepartment = vm.ResponsibleDepartment,
            DueDate = vm.DueDate,
            Priority = vm.Priority,
            Status = "Planned"
        });
        await _db.SaveChangesAsync();
        TempData["Success"] = "再発防止策を登録しました。";
        return RedirectToAction("Details", "Incidents", new { id = vm.IncidentId });
    }

    // GET /PreventiveMeasures/Edit/5
    public async Task<IActionResult> Edit(int id)
    {
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();

        ViewBag.Incident = measure.Incident;
        var vm = new MeasureFormViewModel
        {
            Id = measure.Id,
            IncidentId = measure.IncidentId,
            Description = measure.Description,
            MeasureType = measure.MeasureType,
            ResponsiblePerson = measure.ResponsiblePerson,
            ResponsibleDepartment = measure.ResponsibleDepartment,
            DueDate = measure.DueDate,
            Priority = measure.Priority
        };
        return View(vm);
    }

    // POST /PreventiveMeasures/Edit/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, MeasureFormViewModel vm)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure == null) return NotFound();

        if (!ModelState.IsValid)
        {
            ViewBag.Incident = await _db.Incidents.FindAsync(vm.IncidentId);
            return View(vm);
        }

        measure.Description = vm.Description;
        measure.MeasureType = vm.MeasureType;
        measure.ResponsiblePerson = vm.ResponsiblePerson;
        measure.ResponsibleDepartment = vm.ResponsibleDepartment;
        measure.DueDate = vm.DueDate;
        measure.Priority = vm.Priority;
        await _db.SaveChangesAsync();

        TempData["Success"] = "再発防止策を更新しました。";
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }

    // POST /PreventiveMeasures/Complete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete(int id, string? completionNote)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure == null) return NotFound();

        measure.Status = "Completed";
        measure.CompletedAt = DateTime.Now;
        measure.CompletionNote = completionNote;
        await _db.SaveChangesAsync();

        TempData["Success"] = "対策を完了しました。有効性評価も記録してください。";
        return RedirectToAction(nameof(Index));
    }

    // GET /PreventiveMeasures/Review/5
    public async Task<IActionResult> Review(int id)
    {
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();

        ViewBag.Measure = measure;
        var vm = new ReviewViewModel
        {
            Id = id,
            EffectivenessRating = measure.EffectivenessRating ?? 3,
            EffectivenessNote = measure.EffectivenessNote,
            RecurrenceObserved = measure.RecurrenceObserved ?? false
        };
        return View(vm);
    }

    // POST /PreventiveMeasures/Review/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Review(int id, ReviewViewModel vm)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure == null) return NotFound();

        if (!ModelState.IsValid)
        {
            ViewBag.Measure = measure;
            return View(vm);
        }

        measure.EffectivenessRating = vm.EffectivenessRating;
        measure.EffectivenessNote = vm.EffectivenessNote;
        measure.RecurrenceObserved = vm.RecurrenceObserved;
        measure.EffectivenessReviewedAt = DateTime.Now;
        await _db.SaveChangesAsync();

        if (vm.RecurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を記録しました。";

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/UpdateStatus/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateStatus(int id, string status)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure == null) return NotFound();

        if (PreventiveMeasure.StatusValues.Contains(status))
        {
            measure.Status = status;
            if (status == "Completed") measure.CompletedAt = DateTime.Now;
            await _db.SaveChangesAsync();
        }

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure != null)
        {
            var incidentId = measure.IncidentId;
            _db.PreventiveMeasures.Remove(measure);
            await _db.SaveChangesAsync();
            TempData["Success"] = "再発防止策を削除しました。";
        }
        return RedirectToAction(nameof(Index));
    }
}
