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
// 時刻源サービス・再発検知サービス(IRecurrenceService)
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
    // 再発検知サービス(AddMeasure がバリデーション失敗時に Details ビューモデルを
    // 組み立て直す際、IncidentsController.Details と同じ内容にするために必要)
    private readonly IRecurrenceService _recurrence;
    // ログ出力用(同時編集衝突などの警告)
    private readonly ILogger<IncidentMeasuresController> _logger;

    // コンストラクタ: DI で依存を受け取る
    public IncidentMeasuresController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IClock clock,
        IRecurrenceService recurrence,
        ILogger<IncidentMeasuresController> logger)
    {
        _db = db;
        _auth = auth;
        _clock = clock;
        _recurrence = recurrence;
        _logger = logger;
    }

    // POST /Incidents/AddMeasure
    // 詳細画面から再発防止策を追加する
    // 注: 詳細画面のフォームは IncidentDetailViewModel.NewMeasure 経由で描画されるため、
    //     フィールド名は「NewMeasure.Description」のように prefix 付きで POST される。
    //     Bind(Prefix) を指定しないとバインダが空 prefix にフォールバックして
    //     IncidentId が 0 のままになり、常に 404 になる。
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddMeasure(
        [Bind(Prefix = nameof(IncidentDetailViewModel.NewMeasure))] MeasureFormViewModel vm)
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
            // 詳細画面へ戻す
            return RedirectToAction("Details", "Incidents", new { id = vm.IncidentId });
        }

        // バリデーション失敗: 黙って飲み込まずユーザーに入力不備を通知する。
        // このアクションは成功時は Details へリダイレクトするが、失敗時に同じ redirect を
        // 使うと入力済みの値が失われてしまう。TempData(既定はクッキーに乗る
        // CookieTempDataProvider)へ入力値そのものを退避する方式は、自由記述欄
        // (なぜなぜ分析・対策内容等、PHI を含みうる)をクライアント側のクッキーへ丸ごと
        // 載せてしまう上、Cookie の実質的なサイズ上限(多くのブラウザで 4KB 程度)を
        // 超える恐れもあるため採用しない。代わりに Details と同じ ViewModel をこの場で
        // サーバー側だけで組み立て、入力済みの値を保持したまま Details ビューをそのまま
        // 再描画する(データはクライアントを経由しない)。
        TempData["Warning"] = "入力内容に不備があります。再発防止策フォームの項目を確認してください。";
        var detailVm = await IncidentControllerHelpers.BuildIncidentDetailViewModelAsync(
            _db, _recurrence, _clock, vm.IncidentId, newMeasureOverride: vm);
        // 冒頭の FindAsync 成功後に別ユーザーがインシデントを削除した場合は null が返る。
        // null のまま Details ビューへ渡すと NullReferenceException(HTTP 500)になるため 404 を返す
        if (detailVm == null) return NotFound();
        return View("~/Views/Incidents/Details.cshtml", detailVm);
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

        // 完了報告メモの長さを検証する。この経路は ViewModel を介さず生の文字列を
        // 直接受け取るため、共通ヘルパー(IncidentControllerHelpers.ValidateFreeTextLength)で
        // 他の自由記述欄(Description/AnalysisNote 等)と同じ上限を検証する
        // (§9 入力は信用しない / PreventiveMeasuresController.Complete と同じ理由)。
        // 検証失敗時は、このアクションの他の失敗経路(同時編集衝突など)と同じく
        // TempData["Warning"] + Details へのリダイレクトで通知する(生の BadRequest は
        // 詳細画面のモーダル/コンテキストを失わせてしまうため)。
        var completionNoteError = IncidentControllerHelpers.ValidateFreeTextLength(completionNote, "完了報告内容");
        if (completionNoteError != null)
        {
            TempData["Warning"] = completionNoteError;
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // すでに完了済みなら再完了を拒否する(fail-closed)。ここで拒否しないと、
        // 古いタブからの再送信で CompletedAt / CompletionNote が黙って上書きされ、
        // 有効性評価日時(EffectivenessReviewedAt)が完了日時より前になる等、
        // KPI の時系列整合性が壊れてしまう(RateMeasure / UpdateStatus と同じライフサイクル強制)。
        if (measure.Status == MeasureStatus.Completed)
        {
            TempData["Warning"] = "この対策はすでに完了しています。完了内容を修正する場合は、カンバンでステータスを一度差し戻してから再度完了してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // ステータスを完了へ、完了日時と完了コメントをセット
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = _clock.Now;
        measure.CompletionNote = completionNote;

        // 同時編集検知用のトークンをクライアント値でセット
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // DB へ反映を試行(衝突時はログを残してユーザーに再読み込みを促す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id))
        {
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
    public async Task<IActionResult> RateMeasure(int id, int effectivenessRating, string? effectivenessNote, bool? recurrenceObserved, Guid concurrencyToken)
    {
        // 対象の対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 無ければ 404
        if (measure == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        // (認可チェックは入力値検証より必ず先に行う。EditCauseAnalysis と同じ設計原則:
        // 未認可ユーザーに入力バリデーションの詳細を先に返してしまわないため)
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, measure.Incident, Policies.CanEditIncident))
            return Forbid();

        // 評価値の範囲チェック。他の失敗経路と同じく TempData["Warning"] + Details への
        // リダイレクトで通知する(生の BadRequest は詳細画面のモーダル/コンテキストを失わせてしまうため)
        if (effectivenessRating < 1 || effectivenessRating > 5)
        {
            TempData["Warning"] = "有効性評価は1〜5の値を指定してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // 再発の有無が未選択(null)なら拒否する。bool で受けて false をデフォルトにすると、
        // フォームでどちらのラジオも選択せず送信した場合に「再発なし」が暗黙に確定してしまい、
        // PreventiveMeasuresController.Review(ReviewViewModel.RecurrenceObserved は bool? + [Required])
        // と同じ抜け穴になる(医療インシデントの再発検知 KPI に影響しうるため fail-closed で拒否する)。
        if (recurrenceObserved == null)
        {
            TempData["Warning"] = "再発の有無を選択してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // 有効性評価コメントの長さを検証する。この経路は ViewModel を介さず生の文字列を
        // 直接受け取るため、共通ヘルパー(IncidentControllerHelpers.ValidateFreeTextLength)で
        // 他の自由記述欄(Description/AnalysisNote 等)と同じ上限を検証する
        // (§9 入力は信用しない / ReviewViewModel.EffectivenessNote と同じ理由)。
        // 検証失敗時は、このアクションの他の失敗経路(ライフサイクル逸脱・同時編集衝突など)と
        // 同じく TempData["Warning"] + Details へのリダイレクトで通知する(生の BadRequest は
        // 詳細画面のモーダル/コンテキストを失わせてしまうため)。
        var effectivenessNoteError = IncidentControllerHelpers.ValidateFreeTextLength(effectivenessNote, "有効性評価コメント");
        if (effectivenessNoteError != null)
        {
            TempData["Warning"] = effectivenessNoteError;
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // ライフサイクル(Planned → InProgress → Completed → 有効性評価)を強制する。
        // 完了していない対策は「実施していない」ため有効性評価の対象外。ここで拒否しないと、
        // フォーム改ざんやカンバンでの完了差し戻し(UpdateStatus)後の再送により、未完了の対策へ
        // RecurrenceObserved=true を書き込め、再発/効果なし KPI が実態と乖離してしまう(fail-closed)。
        if (measure.Status != MeasureStatus.Completed)
        {
            // 未完了なら保存せず警告を出して詳細画面へ戻す
            TempData["Warning"] = "対策が完了していないため、有効性評価は登録できません。先に対策を完了してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // 評価値・コメント・再発有無・評価日時を設定
        measure.EffectivenessRating = effectivenessRating;
        measure.EffectivenessNote = effectivenessNote;
        measure.RecurrenceObserved = recurrenceObserved;
        measure.EffectivenessReviewedAt = _clock.Now;

        // 同時編集検知トークンを設定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // DB へ反映を試行(衝突時はログを残してユーザーに再読み込みを促す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict rating PreventiveMeasure {MeasureId}", id))
        {
            TempData["Warning"] = "他のユーザが先に更新したため、有効性評価は保存されませんでした。最新の状態を読み直してから再度登録してください。";
            return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
        }

        // 再発が確認された場合は警告、されていなければ成功通知(直前の null チェックで非 null 確定済み)
        if (recurrenceObserved == true)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を登録しました。";

        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }
}
