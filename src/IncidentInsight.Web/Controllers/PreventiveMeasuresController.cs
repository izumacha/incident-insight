using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

[Authorize]
public class PreventiveMeasuresController : Controller
{
    private readonly ApplicationDbContext _db;
    private readonly IAuthorizationService _auth;
    private readonly IClock _clock;
    private readonly ILogger<PreventiveMeasuresController> _logger;

    public PreventiveMeasuresController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IClock clock,
        ILogger<PreventiveMeasuresController> logger)
    {
        _db = db;
        _auth = auth;
        _clock = clock;
        _logger = logger;
    }

    // GET /PreventiveMeasures
    public async Task<IActionResult> Index(MeasureStatus? status, string? responsible,
        string? responsibleDepartment, DateTime? dateFrom, DateTime? dateTo)
    {
        var query = _db.PreventiveMeasures
            .Include(m => m.Incident)
            .AsQueryable()
            .ScopedByUser(User);

        if (status.HasValue)
            query = query.Where(m => m.Status == status.Value);
        if (!string.IsNullOrEmpty(responsible))
            query = query.Where(m => m.ResponsiblePerson.Contains(responsible) || m.ResponsibleDepartment.Contains(responsible));
        if (!string.IsNullOrEmpty(responsibleDepartment))
            query = query.Where(m => m.ResponsibleDepartment == responsibleDepartment);
        if (dateFrom.HasValue)
            query = query.Where(m => m.DueDate >= dateFrom.Value);
        if (dateTo.HasValue)
            query = query.Where(m => m.DueDate < dateTo.Value.Date.AddDays(1));

        var measures = await query.OrderBy(m => m.DueDate).ToListAsync();

        var planned = measures.Where(m => m.Status == MeasureStatus.Planned).OrderBy(m => m.DueDate).ToList();
        var inProgress = measures.Where(m => m.Status == MeasureStatus.InProgress).OrderBy(m => m.DueDate).ToList();
        var completed = measures.Where(m => m.Status == MeasureStatus.Completed).OrderByDescending(m => m.CompletedAt).ToList();

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
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        ViewBag.Incident = incident;
        var vm = new MeasureFormViewModel
        {
            IncidentId = incidentId.Value,
            DueDate = _clock.Today.AddDays(30)
        };
        return View(vm);
    }

    // POST /PreventiveMeasures/Create
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(MeasureFormViewModel vm)
    {
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        if (incident == null) return NotFound();
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        if (!ModelState.IsValid)
        {
            ViewBag.Incident = incident;
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
            Status = MeasureStatus.Planned
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
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        ViewBag.Incident = measure.Incident;
        var vm = new MeasureFormViewModel
        {
            Id = measure.Id,
            IncidentId = measure.IncidentId,
            ConcurrencyToken = measure.ConcurrencyToken,
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
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

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

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict updating PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(Edit), new { id });
        }

        TempData["Success"] = "再発防止策を更新しました。";
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }

    // POST /PreventiveMeasures/Complete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete(int id, string? completionNote, Guid concurrencyToken)
    {
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = _clock.Now;
        measure.CompletionNote = completionNote;

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、完了登録は保存されませんでした。画面を更新してから再度操作してください。";
            return RedirectToAction(nameof(Index));
        }

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
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        ViewBag.Measure = measure;
        var vm = new ReviewViewModel
        {
            Id = id,
            ConcurrencyToken = measure.ConcurrencyToken,
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
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        if (!ModelState.IsValid)
        {
            ViewBag.Measure = measure;
            return View(vm);
        }

        measure.EffectivenessRating = vm.EffectivenessRating;
        measure.EffectivenessNote = vm.EffectivenessNote;
        measure.RecurrenceObserved = vm.RecurrenceObserved;
        measure.EffectivenessReviewedAt = _clock.Now;

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict reviewing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、有効性評価は保存されませんでした。最新の状態を読み直してから再度登録してください。";
            return RedirectToAction(nameof(Review), new { id });
        }

        if (vm.RecurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を記録しました。";

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/UpdateStatus/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateStatus(int id, MeasureStatus status, Guid concurrencyToken)
    {
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        measure.Status = status;
        if (status == MeasureStatus.Completed) measure.CompletedAt = _clock.Now;

        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            _logger.LogWarning(ex, "Concurrency conflict changing status of PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、ステータス変更は保存されませんでした。画面を更新してから再度操作してください。";
        }

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/Delete/5
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = Policies.CanDeleteIncident)]
    public async Task<IActionResult> Delete(int id)
    {
        // Incident を Include して部署スコープの認可判定(SameDepartmentHandler)に
        // 必要なナビゲーションを確実にロードする。
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanDeleteIncident)) return Forbid();

        _db.PreventiveMeasures.Remove(measure);
        await _db.SaveChangesAsync();
        TempData["Success"] = "再発防止策を削除しました。";
        return RedirectToAction(nameof(Index));
    }

    // リソース（Incident）に対する Policy 評価。Admin/RiskManager は通過、Staff は部署一致で通過。
    private async Task<bool> IsAuthorizedFor(Incident? incident, string policy)
    {
        if (incident == null) return false;
        var result = await _auth.AuthorizeAsync(User, incident, policy);
        return result.Succeeded;
    }
}
