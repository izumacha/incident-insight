// 部署スコープ拡張メソッド
using IncidentInsight.Web.Authorization;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(PreventiveMeasure など)を使う
using IncidentInsight.Web.Models;
// enum(MeasureStatus)を使う
using IncidentInsight.Web.Models.Enums;
// ViewModel 群を使う
using IncidentInsight.Web.Models.ViewModels;
// 時刻源サービスを使う
using IncidentInsight.Web.Services;
// 認可 API(IAuthorizationService)を使う
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底を使う
using Microsoft.AspNetCore.Mvc;
// EF Core 拡張を使う
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// 再発防止策のカンバン・編集・完了・評価を担当するコントローラ
[Authorize]
public class PreventiveMeasuresController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // リソース認可評価用サービス(Policy を使って判定)
    private readonly IAuthorizationService _auth;
    // 時刻源(現在日時取得 + テスト差し替え)
    private readonly IClock _clock;
    // ログ出力用(並行編集衝突などの警告を記録)
    private readonly ILogger<PreventiveMeasuresController> _logger;

    // コンストラクタ: DI で依存を受け取る
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
    // カンバンボード画面。絞り込み条件でクエリを組み立ててビューに渡す
    public async Task<IActionResult> Index(MeasureStatus? status, string? responsible,
        string? responsibleDepartment, DateTime? dateFrom, DateTime? dateTo)
    {
        // Incident を同時取得し、ユーザー部署スコープで絞り込むベースクエリ
        var query = _db.PreventiveMeasures
            .Include(m => m.Incident)
            .AsQueryable()
            .ScopedByUser(User);

        // ステータス指定があれば絞る
        if (status.HasValue)
            query = query.Where(m => m.Status == status.Value);
        // 担当者キーワードが指定されていれば氏名/部署名で部分一致検索
        if (!string.IsNullOrEmpty(responsible))
            query = query.Where(m => m.ResponsiblePerson.Contains(responsible) || m.ResponsibleDepartment.Contains(responsible));
        // 担当部署が指定されていれば完全一致で絞る
        if (!string.IsNullOrEmpty(responsibleDepartment))
            query = query.Where(m => m.ResponsibleDepartment == responsibleDepartment);
        // 期限日の下限指定があれば絞る
        if (dateFrom.HasValue)
            query = query.Where(m => m.DueDate >= dateFrom.Value);
        // 期限日の上限指定があれば絞る(当日を含める)
        if (dateTo.HasValue)
            query = query.Where(m => m.DueDate < dateTo.Value.Date.AddDays(1));

        // 期限日の昇順で取得
        var measures = await query.OrderBy(m => m.DueDate).ToListAsync();

        // カンバン3レーン分に分割(計画中/進行中/完了)
        var planned = measures.Where(m => m.Status == MeasureStatus.Planned).OrderBy(m => m.DueDate).ToList();
        var inProgress = measures.Where(m => m.Status == MeasureStatus.InProgress).OrderBy(m => m.DueDate).ToList();
        var completed = measures.Where(m => m.Status == MeasureStatus.Completed).OrderByDescending(m => m.CompletedAt).ToList();

        // 各レーンをビューで参照できるよう ViewBag に格納
        ViewBag.Planned = planned;
        ViewBag.InProgress = inProgress;
        ViewBag.Completed = completed;
        // 画面に戻すフィルタ値も ViewBag に載せる
        ViewBag.FilterStatus = status;
        ViewBag.FilterResponsible = responsible;
        ViewBag.FilterResponsibleDepartment = responsibleDepartment;
        ViewBag.DateFrom = dateFrom;
        ViewBag.DateTo = dateTo;

        // Stats
        // 統計値(総数・期限超過数・完了率・失敗件数)を計算してビューに渡す
        ViewBag.TotalCount = measures.Count;
        ViewBag.OverdueCount = measures.Count(m => m.IsOverdue);
        ViewBag.CompletionRate = measures.Count == 0 ? 0
            : Math.Round((double)completed.Count / measures.Count * 100, 1);
        ViewBag.FailedCount = measures.Count(m => m.RecurrenceObserved == true);

        // 主モデルとしては全件を渡す(カンバン表示は ViewBag の分割版を参照)
        return View(measures);
    }

    // GET /PreventiveMeasures/Create?incidentId=3
    // 新規対策の登録画面を表示
    public async Task<IActionResult> Create(int? incidentId)
    {
        // incidentId 未指定は不正リクエスト
        if (incidentId == null) return BadRequest();
        // 対象インシデントを取得
        var incident = await _db.Incidents.FindAsync(incidentId);
        // 見つからなければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // ビュー側で表示する親インシデント情報を積む
        ViewBag.Incident = incident;
        // 期限の既定値として 30 日後を入れたフォームモデル
        var vm = new MeasureFormViewModel
        {
            IncidentId = incidentId.Value,
            DueDate = _clock.Today.AddDays(30)
        };
        return View(vm);
    }

    // POST /PreventiveMeasures/Create
    // 新規対策のフォーム送信を受け取って保存
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(MeasureFormViewModel vm)
    {
        // 対象インシデントを取り出す
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        // 見つからなければ 404
        if (incident == null) return NotFound();
        // 編集権限の確認
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // バリデーション NG の場合は入力値を残してフォーム再描画
        if (!ModelState.IsValid)
        {
            ViewBag.Incident = incident;
            return View(vm);
        }

        // ChangeTracker に新規レコードを登録
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
        // DB 保存(監査ログも自動挿入される)
        await _db.SaveChangesAsync();
        // 成功トーストを次リクエストへ渡す
        TempData["Success"] = "再発防止策を登録しました。";
        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = vm.IncidentId });
    }

    // GET /PreventiveMeasures/Edit/5
    // 対策編集画面
    public async Task<IActionResult> Edit(int id)
    {
        // 対象対策をインシデント付きで取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 見つからなければ 404
        if (measure == null) return NotFound();
        // 編集権限の確認
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // ビュー側で表示する親インシデント情報を積む
        ViewBag.Incident = measure.Incident;
        // 現在値でフォームを初期化
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
    // 対策更新フォームの受け取り
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, MeasureFormViewModel vm)
    {
        // 対象対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 無ければ 404
        if (measure == null) return NotFound();
        // 編集権限チェック
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // バリデーション NG なら入力値を残して再描画
        if (!ModelState.IsValid)
        {
            ViewBag.Incident = await _db.Incidents.FindAsync(vm.IncidentId);
            return View(vm);
        }

        // フォームの値をエンティティへ反映
        measure.Description = vm.Description;
        measure.MeasureType = vm.MeasureType;
        measure.ResponsiblePerson = vm.ResponsiblePerson;
        measure.ResponsibleDepartment = vm.ResponsibleDepartment;
        measure.DueDate = vm.DueDate;
        measure.Priority = vm.Priority;

        // 同時編集検知のため、クライアントが持っていた元トークンを OriginalValue に固定する
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            // 保存試行。トークンが合わなければ DbUpdateConcurrencyException が発生
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突発生: ログを残してユーザーに再試行を案内
            _logger.LogWarning(ex, "Concurrency conflict updating PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(Edit), new { id });
        }

        // 成功メッセージを次リクエストへ渡す
        TempData["Success"] = "再発防止策を更新しました。";
        // インシデント詳細へ戻す
        return RedirectToAction("Details", "Incidents", new { id = measure.IncidentId });
    }

    // POST /PreventiveMeasures/Complete/5
    // 対策を「完了」ステータスに変更するエンドポイント
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Complete(int id, string? completionNote, Guid concurrencyToken)
    {
        // 対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 見つからなければ 404
        if (measure == null) return NotFound();
        // 編集権限チェック
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // ステータス・完了日時・報告メモを更新
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = _clock.Now;
        measure.CompletionNote = completionNote;

        // 同時編集検知のためのトークンを固定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            // 保存試行
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突: ログ + 警告メッセージで一覧へ戻す
            _logger.LogWarning(ex, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、完了登録は保存されませんでした。画面を更新してから再度操作してください。";
            return RedirectToAction(nameof(Index));
        }

        // 成功メッセージ + 有効性評価の促し
        TempData["Success"] = "対策を完了しました。有効性評価も記録してください。";
        return RedirectToAction(nameof(Index));
    }

    // GET /PreventiveMeasures/Review/5
    // 有効性レビュー入力画面
    public async Task<IActionResult> Review(int id)
    {
        // 対象対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        // 見つからなければ 404
        if (measure == null) return NotFound();
        // 編集権限チェック
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // ビュー側で表示する対策本体の情報を積む
        ViewBag.Measure = measure;
        // 現在値(未入力時は 3 / 再発なし)でフォームを初期化
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
    // 有効性レビューのフォーム受け取り
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Review(int id, ReviewViewModel vm)
    {
        // 対象対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // バリデーション NG なら入力値を残して再描画
        if (!ModelState.IsValid)
        {
            ViewBag.Measure = measure;
            return View(vm);
        }

        // 評価内容をエンティティに反映
        measure.EffectivenessRating = vm.EffectivenessRating;
        measure.EffectivenessNote = vm.EffectivenessNote;
        measure.RecurrenceObserved = vm.RecurrenceObserved;
        measure.EffectivenessReviewedAt = _clock.Now;

        // 同時編集検知用のトークン固定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            // 保存試行
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突: ログ + 警告で再試行を案内
            _logger.LogWarning(ex, "Concurrency conflict reviewing PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、有効性評価は保存されませんでした。最新の状態を読み直してから再度登録してください。";
            return RedirectToAction(nameof(Review), new { id });
        }

        // 再発ありなら警告、なしなら成功メッセージを表示
        if (vm.RecurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を記録しました。";

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/UpdateStatus/5
    // カンバン上のドラッグ等からステータスだけを変更するエンドポイント
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateStatus(int id, MeasureStatus status, Guid concurrencyToken)
    {
        // 対象対策を取得
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

        // ステータスを更新。完了に遷移した場合は完了日時も記録
        measure.Status = status;
        if (status == MeasureStatus.Completed) measure.CompletedAt = _clock.Now;

        // 同時編集検知のトークン固定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        try
        {
            // 保存試行
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突: ログと警告だけ出して一覧画面に戻る(リダイレクト)
            _logger.LogWarning(ex, "Concurrency conflict changing status of PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、ステータス変更は保存されませんでした。画面を更新してから再度操作してください。";
        }

        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/Delete/5
    // 対策の削除(管理者/リスクマネージャー限定)
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = Policies.CanDeleteIncident)]
    public async Task<IActionResult> Delete(int id)
    {
        // Incident を Include して部署スコープの認可判定(SameDepartmentHandler)に
        // 必要なナビゲーションを確実にロードする。
        // 対象対策をインシデント付きで取得(認可判定に Incident が必要)
        var measure = await _db.PreventiveMeasures
            .Include(m => m.Incident)
            .FirstOrDefaultAsync(m => m.Id == id);
        if (measure == null) return NotFound();
        // 削除権限(部署一致/管理者系)の確認
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanDeleteIncident)) return Forbid();

        // 削除対象に追加して保存(監査ログへも自動で記録される)
        _db.PreventiveMeasures.Remove(measure);
        await _db.SaveChangesAsync();
        TempData["Success"] = "再発防止策を削除しました。";
        return RedirectToAction(nameof(Index));
    }

    // リソース（Incident）に対する Policy 評価。Admin/RiskManager は通過、Staff は部署一致で通過。
    // 指定ポリシーでユーザーがそのインシデントを操作できるか判定するヘルパー
    private async Task<bool> IsAuthorizedFor(Incident? incident, string policy)
    {
        // インシデントが無ければ一律拒否
        if (incident == null) return false;
        // リソース認可を実行
        var result = await _auth.AuthorizeAsync(User, incident, policy);
        // 成功したかどうかを返す
        return result.Succeeded;
    }
}
