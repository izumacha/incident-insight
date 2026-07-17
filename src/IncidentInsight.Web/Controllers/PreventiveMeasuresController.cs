// 部署スコープ拡張メソッド
using IncidentInsight.Web.Authorization;
// 共通ヘルパ(自由記述の文字数検証など)
using IncidentInsight.Web.Controllers.Internal;
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
// トランザクションの分離レベル(IsolationLevel.Serializable)を指定するために使う
using System.Data;
// プロバイダ非依存の DB 例外基底型(Serializable分離レベルでの直列化エラーを
// SQLite/SQL Server/PostgreSQL のいずれでも同じ型で捕捉するために使う)
using System.Data.Common;

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
    // カンバン画面で1回に取得する対策の上限件数。
    // このビューは IncidentsController/AuditLogsController と異なりページングではなく
    // 計画中/進行中/完了の3レーン+統計値を1画面にまとめて表示する構造のため、
    // Skip/Take によるページ分割は3レーンの内訳や KPI を壊してしまう。そのため
    // ここでは「絞り込み条件で対象を絞ってもらう」運用を前提に、単純な上限(§8: 一覧取得は
    // 必ず上限を持たせる)としてこの定数を設ける。上限を超えた場合は Truncated フラグで
    // ビューに通知し、KPI が全件ではなく上限分のみを反映していることを利用者に明示する。
    // Views/PreventiveMeasures/Index.cshtml が案内文中の件数表示にも参照するため public にしている
    public const int MaxKanbanRows = 1000;

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

        // 絞り込み後・上限適用前の総件数(KPI の「全対策数」と、上限に達したかどうかの判定に使う)
        var totalMatchingCount = await query.CountAsync();
        // 期限日の昇順で取得。MaxKanbanRows で上限を設け、際限のない取得を防ぐ(§8/§9)
        var measures = await query.OrderBy(m => m.DueDate).Take(MaxKanbanRows).ToListAsync();
        // 上限に達して切り詰められたかどうか(true の場合、以下で算出する期限超過数・
        // 再発確認数・完了率は上限分のみを反映し全件の値ではなくなる)
        var truncated = totalMatchingCount > MaxKanbanRows;

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
        // 上限に達し切り詰められたかどうか。true ならビューで注意書きを表示する
        ViewBag.Truncated = truncated;

        // Stats
        // 統計値(総数・期限超過数・完了率・失敗件数)を計算してビューに渡す。
        // 全対策数だけは Take 前の totalMatchingCount(全件)を使い、上限に達しても
        // 正しい総数を表示する。他の KPI は上限適用後の measures から算出するため、
        // truncated が true の間は近似値になる(上の Truncated フラグで利用者に明示する)
        ViewBag.TotalCount = totalMatchingCount;
        // IsOverdueOn に _clock.Today を渡して期限超過数を計算する(DateTime.Today を直接使わない)
        ViewBag.OverdueCount = measures.Count(m => m.IsOverdueOn(_clock.Today));
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
            // 立案根拠メモも保存する(詳細ページからの登録と挙動を揃える)
            AnalysisNote = vm.AnalysisNote,
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
            Priority = measure.Priority,
            // 立案根拠メモも現在値で初期化する(編集画面が空欄にならないように)
            AnalysisNote = measure.AnalysisNote
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
            // 再描画用の親インシデントには、上で取得・認可済みの measure.Incident を使う。
            // クライアントが hidden field で送る vm.IncidentId をそのまま FindAsync に渡すと、
            // 値を改ざんされたとき認可チェックなしで他部署のインシデント情報が表示されてしまう
            ViewBag.Incident = measure.Incident;
            return View(vm);
        }

        // フォームの値をエンティティへ反映
        measure.Description = vm.Description;
        measure.MeasureType = vm.MeasureType;
        measure.ResponsiblePerson = vm.ResponsiblePerson;
        measure.ResponsibleDepartment = vm.ResponsibleDepartment;
        measure.DueDate = vm.DueDate;
        measure.Priority = vm.Priority;
        // 立案根拠メモも反映する(編集ビューに入力欄があるため保存漏れを防ぐ)
        measure.AnalysisNote = vm.AnalysisNote;

        // 同時編集検知のため、クライアントが持っていた元トークンを OriginalValue に固定する
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        // 保存試行(トークンが合わなければ DbUpdateConcurrencyException を捕捉してログに残す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict updating PreventiveMeasure {MeasureId}", id))
        {
            // 衝突発生: ユーザーに再試行を案内
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

        // 完了報告メモの長さを検証する。この経路は ViewModel を介さず生の文字列を
        // 直接受け取るため、共通ヘルパー(IncidentControllerHelpers.ValidateFreeTextLength)で
        // 他の自由記述欄(Description/AnalysisNote 等)と同じ上限を検証する
        // (§9 入力は信用しない / EF Core は保存時に DataAnnotations を自動検証しない)。
        // 検証失敗時は、このアクションの他の失敗経路(同時編集衝突など)と同じく
        // TempData["Warning"] + リダイレクトで通知する(生の BadRequest はカンバン画面の
        // コンテキストを失わせ、無装飾のプレーンテキストのみが表示されてしまうため)。
        var completionNoteError = IncidentControllerHelpers.ValidateFreeTextLength(completionNote, "完了報告内容");
        if (completionNoteError != null)
        {
            TempData["Warning"] = completionNoteError;
            return RedirectToAction(nameof(Index));
        }

        // ステータス・完了日時・報告メモを更新
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = _clock.Now;
        measure.CompletionNote = completionNote;

        // 同時編集検知のためのトークンを固定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // 保存試行(衝突時はログ + 警告メッセージで一覧へ戻す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict completing PreventiveMeasure {MeasureId}", id))
        {
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

        // ライフサイクル(Planned → InProgress → Completed → 有効性評価)を強制する。
        // 完了していない対策は「実施していない」ため有効性評価の対象外。フォーム改ざんや、
        // カンバンでの完了差し戻し(UpdateStatus)後の再送で未完了の対策へ再発フラグを書き込むと、
        // 再発/効果なし KPI が実態と乖離するため、ここで fail-closed に拒否する。
        if (measure.Status != MeasureStatus.Completed)
        {
            // 未完了なら保存せず警告を出してカンバン一覧へ戻す
            TempData["Warning"] = "対策が完了していないため、有効性評価は登録できません。先に対策を完了してください。";
            return RedirectToAction(nameof(Index));
        }

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

        // 保存試行(衝突時はログ + 警告で再試行を案内する共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict reviewing PreventiveMeasure {MeasureId}", id))
        {
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

        // 受け取った status が enum の定義値(Planned/InProgress/Completed)かを検証する。
        // ASP.NET のモデルバインドは未定義の整数(例: 99)もそのまま (MeasureStatus)99 として束縛してしまうため、
        // ここで弾かないと未定義値が DB に保存され、カンバンの振り分けやラベル表示が壊れる。
        // 「不明なら拒否」(fail-closed)の原則で、定義外の値は 400 で拒否する。
        if (!Enum.IsDefined(typeof(MeasureStatus), status))
            return BadRequest("不正なステータス値です。");

        // ステータスを更新。完了に遷移した場合は完了日時を記録し、
        // 完了から差し戻した場合は完了日時をクリアする(古い完了日が残らないように)
        measure.Status = status;
        if (status == MeasureStatus.Completed)
        {
            // 完了へ遷移: 完了日時を記録する
            measure.CompletedAt = _clock.Now;
        }
        else
        {
            // 完了以外へ差し戻し: 完了日時をクリアする(古い完了日が残らないように)
            measure.CompletedAt = null;
            // 効果評価は「完了済みの対策」だけに存在してよいデータ(Review/RateMeasure が
            // 未完了への書き込みを fail-closed で拒否している)。ここで差し戻したのに評価値を
            // 残すと、未完了の対策が再発/効果なし KPI に計上され実態と乖離するため、
            // 完了日時と一緒に評価4項目もクリアして不変条件を保つ。
            measure.EffectivenessRating = null;        // 有効性評価(1〜5)をクリア
            measure.EffectivenessNote = null;          // 有効性評価コメントをクリア
            measure.RecurrenceObserved = null;         // 再発確認フラグをクリア
            measure.EffectivenessReviewedAt = null;    // 有効性評価日時をクリア
        }

        // 同時編集検知のトークン固定
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // 保存試行(衝突時はログと警告だけ出して一覧画面に戻る共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict changing status of PreventiveMeasure {MeasureId}", id))
        {
            TempData["Warning"] = "他のユーザが先に更新したため、ステータス変更は保存されませんでした。画面を更新してから再度操作してください。";
            return RedirectToAction(nameof(Index));
        }

        // 成功メッセージを表示して一覧へ戻る(他のミューテーション系アクションと同じ TempData["Success"] 規約)
        TempData["Success"] = "ステータスを更新しました。";
        return RedirectToAction(nameof(Index));
    }

    // POST /PreventiveMeasures/Delete/5
    // 対策の削除(管理者/リスクマネージャー限定)
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = Policies.CanDeleteIncident)]
    public async Task<IActionResult> Delete(int id, Guid concurrencyToken)
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

        // 同時編集検知のトークン固定(画面表示後に他ユーザーが更新した内容を
        // 気づかず削除してしまわないよう、クライアントが保持していた表示時点の
        // トークンを DB の現在値と突き合わせる)
        _db.Entry(measure).Property(nameof(PreventiveMeasure.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // 業務ルール: インシデントは再発防止策が最低1件ないと登録できない
        // (IncidentsController.Create の HasAtLeastOneValidMeasure と同じ不変条件)。
        // 削除でこの不変条件が崩れないよう、削除対象を除いた残り件数を数えて確認する。
        //
        // 「残数を数える」→「削除する」の2ステップは、既定の分離レベルのままだと
        // 同一インシデントの兄弟対策を同時に削除する2つのリクエストの間で
        // TOCTOU(check-then-act)競合状態になり得る: ちょうど2件の対策があるとき
        // 両リクエストが同時に「自分以外の残数=1」を見て通過し、両方が成功すると
        // 対策0件になり不変条件が破れる。Serializable 分離レベルのトランザクションで
        // 包むことで、SQLite(単一ライタロックで後続を直列化)・SQL Server/PostgreSQL
        // (直列化エラーで後続をコミット時に検知)のいずれでも、2つ目のリクエストが
        // 古い(削除前の)残数を見たまま削除を確定させることを防ぐ。
        await using var transaction = await _db.Database.BeginTransactionAsync(IsolationLevel.Serializable);

        // Serializable の直列化エラーは PostgreSQL の仕様上コミット時点に限らず
        // トランザクション中の任意のステートメント(この下の CountAsync 含む)で
        // 発生しうる。SaveChangesAsync 経由の失敗も、行の ConcurrencyToken 不一致
        // (DbUpdateConcurrencyException、下のヘルパーが内部で処理し false を返す)
        // とは別に、直列化エラー由来の素の DbUpdateException として飛んでくる
        // ことがある。そのためコミット時だけでなく、残数確認〜削除〜コミットの
        // 一連の処理全体を1つの try で囲み、どのステートメントで直列化エラーが
        // 起きても同じ「安全側に倒す」経路に落とす。
        try
        {
            var remainingMeasureCount = await _db.PreventiveMeasures
                .CountAsync(m => m.IncidentId == measure.IncidentId && m.Id != measure.Id);
            if (remainingMeasureCount == 0)
            {
                // 残り0件になる削除は拒否し、理由を警告トーストで伝えて一覧へ戻す
                TempData["Warning"] = "この対策はインシデントに残る唯一の再発防止策のため削除できません。先に別の対策を追加してから削除してください。";
                return RedirectToAction(nameof(Index));
            }

            // 削除対象に追加して保存(監査ログへも自動で記録される)
            _db.PreventiveMeasures.Remove(measure);
            // 保存試行(ConcurrencyToken 不一致による衝突時はログを残し、
            // ユーザーに再読み込みを促す共通処理。直列化エラーはここでは
            // 捕捉されずこの try 全体の catch まで伝播する)
            if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                    _db, _logger, "Concurrency conflict deleting PreventiveMeasure {MeasureId}", id))
            {
                TempData["Warning"] = "他のユーザが先に更新したため、削除できませんでした。画面を更新してから再度操作してください。";
                return RedirectToAction(nameof(Index));
            }

            // コミット時点でも Serializable の直列化エラーが起きうる
            // (SQL Server/PostgreSQL: 同時実行の兄弟削除と衝突した場合)
            await transaction.CommitAsync();
        }
        catch (Exception ex) when (ex is DbException or DbUpdateException)
        {
            // プロバイダ固有の例外型に依存しない共通基底型(DbException)、および
            // SaveChangesAsync がそれをラップして投げる DbUpdateException の
            // いずれで捕捉しても、安全側(削除を確定させない)に倒す。
            // ロールバックは transaction の Dispose(await using)時に自動で行われる。
            _logger.LogWarning(ex, "Serialization conflict deleting PreventiveMeasure {MeasureId}", id);
            TempData["Warning"] = "他のユーザが同時に操作したため、削除できませんでした。画面を更新してから再度操作してください。";
            return RedirectToAction(nameof(Index));
        }

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
