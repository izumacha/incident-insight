using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class IncidentsController : Controller
{
    private readonly ApplicationDbContext _db;
    private const int PageSize = 20;

    public IncidentsController(ApplicationDbContext db)
    {
        _db = db;
    }

    // GET /Incidents
    public async Task<IActionResult> Index(string? search, string? department,
        string? incidentType, string? severity, DateTime? dateFrom, DateTime? dateTo, int page = 1)
    {
        var query = _db.Incidents
            .Include(i => i.PreventiveMeasures)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(i => i.Description.Contains(search) || i.ReporterName.Contains(search));
        if (!string.IsNullOrWhiteSpace(department))
            query = query.Where(i => i.Department == department);
        if (!string.IsNullOrWhiteSpace(incidentType))
            query = query.Where(i => i.IncidentType == incidentType);
        if (!string.IsNullOrWhiteSpace(severity))
            query = query.Where(i => i.Severity == severity);
        if (dateFrom.HasValue)
            query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(i => i.OccurredAt < dateTo.Value.AddDays(1));

        var total = await query.CountAsync();
        var incidents = await query
            .OrderByDescending(i => i.OccurredAt)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        var vm = new IncidentListViewModel
        {
            Incidents = incidents,
            TotalCount = total,
            Page = page,
            PageSize = PageSize,
            Search = search,
            Department = department,
            IncidentType = incidentType,
            Severity = severity,
            DateFrom = dateFrom,
            DateTo = dateTo
        };

        return View(vm);
    }

    // GET /Incidents/Details/5
    public async Task<IActionResult> Details(int id)
    {
        var incident = await _db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory).ThenInclude(cc => cc!.Parent)
            .Include(i => i.PreventiveMeasures)
            .FirstOrDefaultAsync(i => i.Id == id);

        if (incident == null) return NotFound();

        // Recurrence detection
        var catIds = incident.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
        var similar = await _db.Incidents
            .Include(o => o.CauseAnalyses)
            .Where(o => o.Id != id
                && o.Department == incident.Department
                && o.IncidentType == incident.IncidentType)
            .ToListAsync();
        similar = similar
            .Where(o => o.CauseAnalyses.Any(ca => catIds.Contains(ca.CauseCategoryId)))
            .ToList();

        var causeOptions = await BuildCauseCategoryOptions();

        var vm = new IncidentDetailViewModel
        {
            Incident = incident,
            SimilarIncidents = similar,
            CauseCategoryOptions = causeOptions,
            NewCauseAnalysis = new CauseAnalysisFormViewModel { IncidentId = id },
            NewMeasure = new MeasureFormViewModel { IncidentId = id }
        };

        return View(vm);
    }

    // GET /Incidents/Create
    public async Task<IActionResult> Create()
    {
        var vm = new IncidentCreateEditViewModel
        {
            OccurredAt = DateTime.Now,
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        return View(vm);
    }

    // POST /Incidents/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(IncidentCreateEditViewModel vm)
    {
        // Remove sub-form validation noise from ModelState
        ModelState.Remove("CauseAnalysis.CauseCategoryOptions");

        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        var incident = new Incident
        {
            OccurredAt = vm.OccurredAt,
            Department = vm.Department,
            IncidentType = vm.IncidentType,
            Severity = vm.Severity,
            Description = vm.Description,
            ImmediateActions = vm.ImmediateActions,
            ReporterName = vm.ReporterName,
            ReportedAt = DateTime.Now
        };

        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // Save cause analysis
        if (vm.CauseAnalysis.CauseCategoryId > 0 && !string.IsNullOrWhiteSpace(vm.CauseAnalysis.Why1))
        {
            var analysis = new CauseAnalysis
            {
                IncidentId = incident.Id,
                CauseCategoryId = vm.CauseAnalysis.CauseCategoryId,
                Why1 = vm.CauseAnalysis.Why1,
                Why2 = vm.CauseAnalysis.Why2,
                Why3 = vm.CauseAnalysis.Why3,
                Why4 = vm.CauseAnalysis.Why4,
                Why5 = vm.CauseAnalysis.Why5,
                RootCauseSummary = vm.CauseAnalysis.RootCauseSummary,
                AnalystName = vm.CauseAnalysis.AnalystName,
                AnalyzedAt = DateTime.Now,
                AdditionalNotes = vm.CauseAnalysis.AdditionalNotes
            };
            _db.CauseAnalyses.Add(analysis);
        }

        // Save measures
        foreach (var m in vm.Measures.Where(m => !string.IsNullOrWhiteSpace(m.Description)))
        {
            _db.PreventiveMeasures.Add(new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = m.Description,
                MeasureType = m.MeasureType,
                ResponsiblePerson = m.ResponsiblePerson,
                ResponsibleDepartment = m.ResponsibleDepartment,
                DueDate = m.DueDate,
                Priority = m.Priority,
                Status = "Planned"
            });
        }

        await _db.SaveChangesAsync();

        TempData["Success"] = "インシデントを登録しました。";
        return RedirectToAction(nameof(Details), new { id = incident.Id });
    }

    // GET /Incidents/Edit/5
    public async Task<IActionResult> Edit(int id)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident == null) return NotFound();

        var vm = new IncidentCreateEditViewModel
        {
            Id = incident.Id,
            OccurredAt = incident.OccurredAt,
            Department = incident.Department,
            IncidentType = incident.IncidentType,
            Severity = incident.Severity,
            Description = incident.Description,
            ImmediateActions = incident.ImmediateActions,
            ReporterName = incident.ReporterName,
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        return View(vm);
    }

    // POST /Incidents/Edit/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, IncidentCreateEditViewModel vm)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident == null) return NotFound();

        // Remove sub-form keys from ModelState
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith("CauseAnalysis.") || k.StartsWith("Measures["))
            .ToList())
        {
            ModelState.Remove(key);
        }

        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        incident.OccurredAt = vm.OccurredAt;
        incident.Department = vm.Department;
        incident.IncidentType = vm.IncidentType;
        incident.Severity = vm.Severity;
        incident.Description = vm.Description;
        incident.ImmediateActions = vm.ImmediateActions;
        incident.ReporterName = vm.ReporterName;

        await _db.SaveChangesAsync();
        TempData["Success"] = "インシデントを更新しました。";
        return RedirectToAction(nameof(Details), new { id });
    }

    // POST /Incidents/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(int id)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident != null)
        {
            _db.Incidents.Remove(incident);
            await _db.SaveChangesAsync();
            TempData["Success"] = "インシデントを削除しました。";
        }
        return RedirectToAction(nameof(Index));
    }

    // POST /Incidents/AddCauseAnalysis
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddCauseAnalysis(CauseAnalysisFormViewModel vm)
    {
        ModelState.Remove("CauseCategoryOptions");
        if (ModelState.IsValid)
        {
            _db.CauseAnalyses.Add(new CauseAnalysis
            {
                IncidentId = vm.IncidentId,
                CauseCategoryId = vm.CauseCategoryId,
                Why1 = vm.Why1,
                Why2 = vm.Why2,
                Why3 = vm.Why3,
                Why4 = vm.Why4,
                Why5 = vm.Why5,
                RootCauseSummary = vm.RootCauseSummary,
                AnalystName = vm.AnalystName,
                AnalyzedAt = DateTime.Now,
                AdditionalNotes = vm.AdditionalNotes
            });
            await _db.SaveChangesAsync();
            TempData["Success"] = "原因分析を追加しました。";
        }
        return RedirectToAction(nameof(Details), new { id = vm.IncidentId });
    }

    // POST /Incidents/DeleteCauseAnalysis/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteCauseAnalysis(int id)
    {
        var analysis = await _db.CauseAnalyses.FindAsync(id);
        if (analysis != null)
        {
            var incidentId = analysis.IncidentId;
            _db.CauseAnalyses.Remove(analysis);
            await _db.SaveChangesAsync();
            TempData["Success"] = "原因分析を削除しました。";
            return RedirectToAction(nameof(Details), new { id = incidentId });
        }
        return NotFound();
    }

    // POST /Incidents/AddMeasure
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddMeasure(MeasureFormViewModel vm)
    {
        if (ModelState.IsValid)
        {
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
            TempData["Success"] = "再発防止策を追加しました。";
        }
        return RedirectToAction(nameof(Details), new { id = vm.IncidentId });
    }

    // POST /Incidents/CompleteMeasure/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteMeasure(int id, string? completionNote)
    {
        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure != null)
        {
            measure.Status = "Completed";
            measure.CompletedAt = DateTime.Now;
            measure.CompletionNote = completionNote;
            await _db.SaveChangesAsync();
            TempData["Success"] = "対策を完了しました。有効性評価を忘れずに行ってください。";
            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }
        return NotFound();
    }

    // POST /Incidents/RateMeasure/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RateMeasure(int id, int effectivenessRating, string? effectivenessNote, bool recurrenceObserved)
    {
        if (effectivenessRating < 1 || effectivenessRating > 5)
            return BadRequest("有効性評価は1〜5の値を指定してください。");

        var measure = await _db.PreventiveMeasures.FindAsync(id);
        if (measure != null)
        {
            measure.EffectivenessRating = effectivenessRating;
            measure.EffectivenessNote = effectivenessNote;
            measure.RecurrenceObserved = recurrenceObserved;
            measure.EffectivenessReviewedAt = DateTime.Now;
            await _db.SaveChangesAsync();

            if (recurrenceObserved)
                TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
            else
                TempData["Success"] = "有効性評価を登録しました。";

            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }
        return NotFound();
    }

    private async Task<List<SelectListItem>> BuildCauseCategoryOptions()
    {
        var cats = await _db.CauseCategories
            .Include(c => c.Children)
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            .ToListAsync();

        var items = new List<SelectListItem>();
        foreach (var parent in cats)
        {
            var group = new SelectListGroup { Name = parent.Name };
            foreach (var child in parent.Children.OrderBy(c => c.DisplayOrder))
            {
                items.Add(new SelectListItem
                {
                    Value = child.Id.ToString(),
                    Text = child.Name,
                    Group = group
                });
            }
        }
        return items;
    }
}
