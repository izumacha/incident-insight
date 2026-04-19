using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class IncidentsController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _auth;
    private readonly IRecurrenceService _recurrence;
    private readonly ILogger<IncidentsController> _logger;
    private const int PageSize = 20;

    public IncidentsController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IRecurrenceService recurrence,
        ILogger<IncidentsController> logger)
    {
        _db = db;
        _auth = auth;
        _recurrence = recurrence;
        _logger = logger;
    }

    // GET /Incidents
    public async Task<IActionResult> Index(string? search, string? department,
        IncidentTypeKind? incidentType, IncidentSeverity? severity, DateTime? dateFrom, DateTime? dateTo,
        int? causeCategoryId, string? sortBy, int page = 1)
    {
        var query = _db.Incidents
            .Include(i => i.PreventiveMeasures)
            .Include(i => i.CauseAnalyses)
            .AsQueryable()
            .ScopedByUser(User);

        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(i => i.Description.Contains(search) || i.ReporterName.Contains(search));
        if (!string.IsNullOrWhiteSpace(department))
            query = query.Where(i => i.Department == department);
        if (incidentType.HasValue)
            query = query.Where(i => i.IncidentType == incidentType.Value);
        if (severity.HasValue)
            query = query.Where(i => i.Severity == severity.Value);
        if (dateFrom.HasValue)
            query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(i => i.OccurredAt < dateTo.Value.AddDays(1));
        if (causeCategoryId.HasValue)
            query = query.Where(i => i.CauseAnalyses.Any(ca =>
                ca.CauseCategoryId == causeCategoryId.Value ||
                ca.CauseCategory.ParentId == causeCategoryId.Value));

        // Sort
        query = sortBy switch
        {
            "severity" => query.OrderByDescending(i => i.Severity),
            "overdue"  => query.OrderByDescending(i => i.PreventiveMeasures
                              .Any(m => m.Status != MeasureStatus.Completed && m.DueDate < DateTime.Today)),
            _          => query.OrderByDescending(i => i.OccurredAt)
        };

        var total = await query.CountAsync();
        var incidents = await query
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        // Build cause category options (parent categories only)
        var parentCats = await _db.CauseCategories
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
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
            DateTo = dateTo,
            CauseCategoryId = causeCategoryId,
            SortBy = sortBy,
            CauseCategoryOptions = parentCats
                .Select(c => new SelectListItem(c.Name, c.Id.ToString()))
                .ToList()
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
        if (!await IsAuthorizedFor(incident, Policies.CanViewIncident)) return Forbid();

        // 再発検出はサービスに集約(HomeController と同じマッチングルールを共有)。
        var similar = await _recurrence.FindRecurrencesForIncidentAsync(incident, _db.Incidents);

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

        if (!HasAtLeastOneValidMeasure(vm.Measures))
            ModelState.AddModelError(nameof(vm.Measures), "再発防止策を1件以上入力してください。");

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
                AnalysisNote = m.AnalysisNote,
                Status = MeasureStatus.Planned
            });
        }

        await _db.SaveChangesAsync();

        TempData["Success"] = "インシデントを登録しました。";
        return RedirectToAction(nameof(Details), new { id = incident.Id });
    }

    private static bool HasAtLeastOneValidMeasure(IEnumerable<MeasureFormViewModel>? measures)
        => measures?.Any(m => !string.IsNullOrWhiteSpace(m.Description)) == true;

    // GET /Incidents/Edit/5
    public async Task<IActionResult> Edit(int id)
    {
        var incident = await _db.Incidents.FindAsync(id);
        if (incident == null) return NotFound();
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        var vm = new IncidentCreateEditViewModel
        {
            Id = incident.Id,
            ConcurrencyToken = incident.ConcurrencyToken,
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
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

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

        // 楽観的同時実行制御: クライアントが編集開始時点で保持していたトークンを
        // OriginalValue に適用する。DB の現在値と一致しない場合に
        // DbUpdateConcurrencyException が投げられる。
        _db.Entry(incident).Property(nameof(Incident.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict updating Incident {IncidentId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(Edit), new { id });
        }
        TempData["Success"] = "インシデントを更新しました。";
        return RedirectToAction(nameof(Details), new { id });
    }

    // POST /Incidents/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = Policies.CanDeleteIncident)]
    public async Task<IActionResult> Delete(int id)
    {
        // 子(CauseAnalysis / PreventiveMeasure)を Include して ChangeTracker に載せておく。
        // OnDelete(Cascade) は DB 側でも子行を消すが、それだけだと AuditSaveChangesInterceptor が
        // 子の Deleted エントリを拾えず、監査ログから抜け落ちる。
        var incident = await _db.Incidents
            .Include(i => i.CauseAnalyses)
            .Include(i => i.PreventiveMeasures)
            .FirstOrDefaultAsync(i => i.Id == id);
        if (incident == null) return NotFound();
        if (!await IsAuthorizedFor(incident, Policies.CanDeleteIncident)) return Forbid();

        _db.Incidents.Remove(incident);
        await _db.SaveChangesAsync();
        TempData["Success"] = "インシデントを削除しました。";
        return RedirectToAction(nameof(Index));
    }

    // GET /Incidents/EditCauseAnalysis/5
    public async Task<IActionResult> EditCauseAnalysis(int id)
    {
        var analysis = await _db.CauseAnalyses
            .Include(a => a.CauseCategory)
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        if (analysis == null) return NotFound();
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        var vm = new CauseAnalysisFormViewModel
        {
            Id = analysis.Id,
            IncidentId = analysis.IncidentId,
            ConcurrencyToken = analysis.ConcurrencyToken,
            CauseCategoryId = analysis.CauseCategoryId,
            Why1 = analysis.Why1,
            Why2 = analysis.Why2,
            Why3 = analysis.Why3,
            Why4 = analysis.Why4,
            Why5 = analysis.Why5,
            RootCauseSummary = analysis.RootCauseSummary,
            AnalystName = analysis.AnalystName,
            AdditionalNotes = analysis.AdditionalNotes,
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        return View(vm);
    }

    // POST /Incidents/EditCauseAnalysis/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditCauseAnalysis(int id, CauseAnalysisFormViewModel vm)
    {
        ModelState.Remove("CauseCategoryOptions");
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        if (analysis == null) return NotFound();
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        analysis.CauseCategoryId = vm.CauseCategoryId;
        analysis.Why1 = vm.Why1;
        analysis.Why2 = vm.Why2;
        analysis.Why3 = vm.Why3;
        analysis.Why4 = vm.Why4;
        analysis.Why5 = vm.Why5;
        analysis.RootCauseSummary = vm.RootCauseSummary;
        analysis.AnalystName = vm.AnalystName;
        analysis.AdditionalNotes = vm.AdditionalNotes;
        // 監査目的で編集時にも分析日時を更新する(初回登録と再分析の区別は監査ログで追跡)
        analysis.AnalyzedAt = DateTime.Now;

        _db.Entry(analysis).Property(nameof(CauseAnalysis.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict updating CauseAnalysis {AnalysisId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(EditCauseAnalysis), new { id });
        }
        TempData["Success"] = "原因分析を更新しました。";
        return RedirectToAction(nameof(Details), new { id = analysis.IncidentId });
    }

    // POST /Incidents/AddCauseAnalysis
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddCauseAnalysis(CauseAnalysisFormViewModel vm)
    {
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        if (incident == null) return NotFound();
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

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
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        if (analysis == null) return NotFound();
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        var incidentId = analysis.IncidentId;
        _db.CauseAnalyses.Remove(analysis);
        await _db.SaveChangesAsync();
        TempData["Success"] = "原因分析を削除しました。";
        return RedirectToAction(nameof(Details), new { id = incidentId });
    }

    // POST /Incidents/AddMeasure
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddMeasure(MeasureFormViewModel vm)
    {
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        if (incident == null) return NotFound();
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

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
                AnalysisNote = vm.AnalysisNote,
                Status = MeasureStatus.Planned
            });
            await _db.SaveChangesAsync();
            TempData["Success"] = "再発防止策を追加しました。";
        }
        return RedirectToAction(nameof(Details), new { id = vm.IncidentId });
    }

    // POST /Incidents/CompleteMeasure/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteMeasure(int id, string? completionNote, Guid concurrencyToken)
    {
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        measure.CompletionNote = completionNote;

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、完了登録は保存されませんでした。最新の状態を読み直してから再度操作してください。";
            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }
        TempData["Success"] = "対策を完了しました。有効性評価を忘れずに行ってください。";
        return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
    }

    // POST /Incidents/RateMeasure/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RateMeasure(int id, int effectivenessRating, string? effectivenessNote, bool recurrenceObserved, Guid concurrencyToken)
    {
        if (effectivenessRating < 1 || effectivenessRating > 5)
            return BadRequest("有効性評価は1〜5の値を指定してください。");

        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        measure.EffectivenessRating = effectivenessRating;
        measure.EffectivenessNote = effectivenessNote;
        measure.RecurrenceObserved = recurrenceObserved;
        measure.EffectivenessReviewedAt = DateTime.Now;

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict rating PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、有効性評価は保存されませんでした。最新の状態を読み直してから再度登録してください。";
            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }

        if (recurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を登録しました。";

        return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
    }

    // リソース（Incident）に対する Policy 評価。Admin/RiskManager は通過、Staff は部署一致で通過。
    private async Task<bool> IsAuthorizedFor(Incident? incident, string policy)
    {
        if (incident == null) return false;
        var result = await _auth.AuthorizeAsync(User, incident, policy);
        return result.Succeeded;
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
