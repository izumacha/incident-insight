// 共通ヘルパ(認可判定)
using IncidentInsight.Web.Controllers.Internal;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(PreventiveMeasure / Incident)
using IncidentInsight.Web.Models;
// MeasureStatus enum
using IncidentInsight.Web.Models.Enums;
// ViewModel(MeasureFormViewModel)
using IncidentInsight.Web.Models.ViewModels;
// 認可ポリシー名
using IncidentInsight.Web.Authorization;
// 時刻源サービス
using IncidentInsight.Web.Services;
// IAuthorizationService
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底
using Microsoft.AspNetCore.Mvc;
// EF Core 拡張
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

/// <summary>
/// インシデント詳細画面から起動する再発防止策のネスト操作(追加・完了・有効性評価)を担当する。
/// 既存のカンバン UI(/PreventiveMeasures/...) は PreventiveMeasuresController が担当する。
///
/// 互換性のため URL は /Incidents/{Action}/{id?} を維持する。
/// 例: /Incidents/CompleteMeasure/5 → このコントローラが処理する。
/// View 側のフォームは asp-controller="IncidentMeasures" を指定すること。
/// </summary>
[Authorize]
[Route("Incidents/[action]/{id?}")]
public class IncidentMeasuresController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // リソース認可評価用サービス
    private readonly IAuthorizationService _auth;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;
    // ログ出力用(同時編集衝突などの警告)
    private readonly ILogger<IncidentMeasuresController> _logger;

    // コンストラクタ: DI で依存を受け取る
    public IncidentMeasuresController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IClock clock,
        ILogger<IncidentMeasuresController> logger)
    {
        _db = db;
        _auth = auth;
        _clock = clock;
        _logger = logger;
    }

    // POST /Incidents/AddMeasure
    // 詳細画面から再発防止策を追加する
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddMeasure(MeasureFormViewModel vm)
    {
        // 親インシデントを取得
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, incident, Policies.CanEditIncident))
            return Forbid();

        // バリデーション OK なら保存
        if (ModelState.IsValid)
        {
            // 新しい対策を ChangeTracker に追加(初期ステータス: 計画中)
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
            // DB へ反映
            await _db.SaveChangesAsync();
            // 成功通知
            TempData["Success"] = "再発防止策を追加しました。";
        }
        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = vm.IncidentId });
    }

    // POST /Incidents/CompleteMeasure/5
    // 再発防止策を「完了」に変更する
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> CompleteMeasure(int id, string? completionNote, Guid concurrencyToken)
    {
        // 対象の対策を親インシデントと共に取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 無ければ 404
        if (measure == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, measure.Incident, Policies.CanEditIncident))
            return Forbid();

        // ステータスを完了へ、完了日時と完了コメントをセット
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = _clock.Now;
        measure.CompletionNote = completionNote;

        // 同時編集検知用のトークンをクライアント値でセット
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            // DB へ反映
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突: ログを残してユーザーに再読み込みを促す
            _logger.LogWarning(ex, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、完了登録は保存されませんでした。最新の状態を読み直してから再度操作してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }
        // 成功通知(次ステップの有効性評価を促す)
        TempData["Success"] = "対策を完了しました。有効性評価を忘れずに行ってください。";
        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }

    // POST /Incidents/RateMeasure/5
    // 再発防止策の有効性評価(1〜5 + 再発有無)を登録
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RateMeasure(int id, int effectivenessRating, string? effectivenessNote, bool recurrenceObserved, Guid concurrencyToken)
    {
        // 評価値の範囲チェック
        if (effectivenessRating < 1 || effectivenessRating > 5)
            return BadRequest("有効性評価は1〜5の値を指定してください。");

        // 対象の対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 無ければ 404
        if (measure == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, measure.Incident, Policies.CanEditIncident))
            return Forbid();

        // 評価値・コメント・再発有無・評価日時を設定
        measure.EffectivenessRating = effectivenessRating;
        measure.EffectivenessNote = effectivenessNote;
        measure.RecurrenceObserved = recurrenceObserved;
        measure.EffectivenessReviewedAt = _clock.Now;

        // 同時編集検知トークンを設定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            // DB へ反映
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突: ログを残してユーザーに再読み込みを促す
            _logger.LogWarning(ex, "Concurrency conflict rating PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、有効性評価は保存されませんでした。最新の状態を読み直してから再度登録してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // 再発が確認された場合は警告、されていなければ成功通知
        if (recurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を登録しました。";

        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }
}
