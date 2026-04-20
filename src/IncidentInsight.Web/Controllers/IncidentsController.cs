// 部署スコープ拡張メソッド(ScopedByUser)を使う
using IncidentInsight.Web.Authorization;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(Incident / CauseAnalysis など)を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別など)を使う
using IncidentInsight.Web.Models.Enums;
// フォーム用 ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// 時刻源 / 再発サービスを使う
using IncidentInsight.Web.Services;
// 認可 API(IAuthorizationService)を使う
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底を使う
using Microsoft.AspNetCore.Mvc;
// SelectListItem / SelectListGroup(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張を使う
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// インシデントの登録・編集・削除・関連操作(原因分析/対策)を担当するコントローラ
[Authorize]
public class IncidentsController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // リソース認可評価用サービス
    private readonly IAuthorizationService _auth;
    // 再発検出サービス(同部署×同種別×原因カテゴリ一致)
    private readonly IRecurrenceService _recurrence;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;
    // ログ出力用(同時編集衝突などの警告)
    private readonly ILogger<IncidentsController> _logger;
    // 一覧の 1 ページあたりの件数
    private const int PageSize = 20;

    // コンストラクタ: DI で依存を受け取る
    public IncidentsController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IRecurrenceService recurrence,
        IClock clock,
        ILogger<IncidentsController> logger)
    {
        _db = db;
        _auth = auth;
        _recurrence = recurrence;
        _clock = clock;
        _logger = logger;
    }

    // GET /Incidents
    // 一覧画面。検索・絞り込み・並び替え・ページングを行う
    public async Task<IActionResult> Index(string? search, string? department,
        IncidentTypeKind? incidentType, IncidentSeverity? severity, DateTime? dateFrom, DateTime? dateTo,
        int? causeCategoryId, string? sortBy, int page = 1)
    {
        // 関連(対策・原因分析)込みで、ユーザー部署スコープに絞ったクエリを用意
        var query = _db.Incidents
            .Include(i => i.PreventiveMeasures)
            .Include(i => i.CauseAnalyses)
            .AsQueryable()
            .ScopedByUser(User);

        // フリーワード検索(状況または報告者名を部分一致)
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(i => i.Description.Contains(search) || i.ReporterName.Contains(search));
        // 部署で絞り込み
        if (!string.IsNullOrWhiteSpace(department))
            query = query.Where(i => i.Department == department);
        // インシデント種別で絞り込み
        if (incidentType.HasValue)
            query = query.Where(i => i.IncidentType == incidentType.Value);
        // 重症度で絞り込み
        if (severity.HasValue)
            query = query.Where(i => i.Severity == severity.Value);
        // 発生日下限で絞り込み
        if (dateFrom.HasValue)
            query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 発生日上限で絞り込み(当日を含める)
        if (dateTo.HasValue)
            query = query.Where(i => i.OccurredAt < dateTo.Value.AddDays(1));
        // 原因カテゴリで絞り込み(親カテゴリ指定時は子カテゴリも拾う)
        if (causeCategoryId.HasValue)
            query = query.Where(i => i.CauseAnalyses.Any(ca =>
                ca.CauseCategoryId == causeCategoryId.Value ||
                ca.CauseCategory.ParentId == causeCategoryId.Value));

        // Sort
        // 並び替え: severity=重症度降順、overdue=期限超過あり優先、既定=発生日の新しい順
        query = sortBy switch
        {
            "severity" => query.OrderByDescending(i => i.Severity),
            "overdue"  => query.OrderByDescending(i => i.PreventiveMeasures
                              .Any(m => m.Status != MeasureStatus.Completed && m.DueDate < _clock.Today)),
            _          => query.OrderByDescending(i => i.OccurredAt)
        };

        // 総件数(ページング計算用)
        var total = await query.CountAsync();
        // 現在ページ分のレコードだけ取得
        var incidents = await query
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        // Build cause category options (parent categories only)
        // 原因カテゴリの絞り込みドロップダウン用に親カテゴリのみ取得
        var parentCats = await _db.CauseCategories
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            .ToListAsync();

        // ビューに渡す ViewModel を組み立てる
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

        // 一覧ビューへ ViewModel を渡して描画
        return View(vm);
    }

    // GET /Incidents/Details/5
    // 詳細画面。原因分析・対策・類似インシデントを併せて表示
    public async Task<IActionResult> Details(int id)
    {
        // 原因分析 → カテゴリ → 親カテゴリまで、および対策一覧を eager-load で取得
        var incident = await _db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory).ThenInclude(cc => cc!.Parent)
            .Include(i => i.PreventiveMeasures)
            .FirstOrDefaultAsync(i => i.Id == id);

        // レコードが無ければ 404
        if (incident == null) return NotFound();
        // 閲覧権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanViewIncident)) return Forbid();

        // 再発検出はサービスに集約(HomeController と同じマッチングルールを共有)。
        // 類似インシデント一覧を取得(期間無制限)
        var similar = await _recurrence.FindRecurrencesForIncidentAsync(incident, _db.Incidents);

        // 原因カテゴリのドロップダウン選択肢(親カテゴリでグルーピング)
        var causeOptions = await BuildCauseCategoryOptions();

        // 画面用 ViewModel を組み立てる
        var vm = new IncidentDetailViewModel
        {
            Incident = incident,
            SimilarIncidents = similar,
            CauseCategoryOptions = causeOptions,
            NewCauseAnalysis = new CauseAnalysisFormViewModel { IncidentId = id },
            NewMeasure = new MeasureFormViewModel { IncidentId = id }
        };

        // 詳細ビューを描画
        return View(vm);
    }

    // GET /Incidents/Create
    // 登録画面の初期表示
    public async Task<IActionResult> Create()
    {
        // 発生日時の既定値を「現在時刻」にして空の ViewModel を用意
        var vm = new IncidentCreateEditViewModel
        {
            OccurredAt = _clock.Now,
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        // 登録フォームを描画
        return View(vm);
    }

    // POST /Incidents/Create
    // 登録フォーム送信を受けてインシデント・原因分析・対策をまとめて保存
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(IncidentCreateEditViewModel vm)
    {
        // Remove sub-form validation noise from ModelState
        // サブフォーム側のドロップダウン選択肢バリデーションは不要なので除外
        ModelState.Remove("CauseAnalysis.CauseCategoryOptions");

        // 業務ルール: 再発防止策が1件も無ければ登録不可
        if (!HasAtLeastOneValidMeasure(vm.Measures))
            ModelState.AddModelError(nameof(vm.Measures), "再発防止策を1件以上入力してください。");

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        // 入力値から新しい Incident を作成
        var incident = new Incident
        {
            OccurredAt = vm.OccurredAt,
            Department = vm.Department,
            IncidentType = vm.IncidentType,
            Severity = vm.Severity,
            Description = vm.Description,
            ImmediateActions = vm.ImmediateActions,
            ReporterName = vm.ReporterName,
            ReportedAt = _clock.Now
        };

        // ChangeTracker に追加して Id を得るため一旦保存
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // Save cause analysis
        // カテゴリが選択され Why1 が入力されていれば原因分析を保存
        if (vm.CauseAnalysis.CauseCategoryId > 0 && !string.IsNullOrWhiteSpace(vm.CauseAnalysis.Why1))
        {
            // 入力値から CauseAnalysis を組み立てる
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
                AnalyzedAt = _clock.Now,
                AdditionalNotes = vm.CauseAnalysis.AdditionalNotes
            };
            // ChangeTracker に追加(実 INSERT は下の SaveChanges で)
            _db.CauseAnalyses.Add(analysis);
        }

        // Save measures
        // 内容が空でない対策のみ保存
        foreach (var m in vm.Measures.Where(m => !string.IsNullOrWhiteSpace(m.Description)))
        {
            // 新しい PreventiveMeasure を ChangeTracker に追加
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

        // 原因分析+対策をまとめて DB に反映
        await _db.SaveChangesAsync();

        // 成功通知をセット(画面上のトースト表示用)
        TempData["Success"] = "インシデントを登録しました。";
        // 詳細画面にリダイレクト
        return RedirectToAction(nameof(Details), new { id = incident.Id });
    }

    // 「少なくとも1件の有効な対策が入力されているか」を判定するヘルパー
    private static bool HasAtLeastOneValidMeasure(IEnumerable<MeasureFormViewModel>? measures)
        => measures?.Any(m => !string.IsNullOrWhiteSpace(m.Description)) == true;

    // GET /Incidents/Edit/5
    // 編集画面の初期表示
    public async Task<IActionResult> Edit(int id)
    {
        // 指定 ID のインシデントを取得
        var incident = await _db.Incidents.FindAsync(id);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // 編集フォーム用 ViewModel に現在値と同時実行トークンを詰める
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
        // 編集ビューを描画
        return View(vm);
    }

    // POST /Incidents/Edit/5
    // 編集フォーム送信を受けて Incident 本体を更新
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, IncidentCreateEditViewModel vm)
    {
        // 対象エンティティを再取得
        var incident = await _db.Incidents.FindAsync(id);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // Remove sub-form keys from ModelState
        // 原因分析・対策のサブフォーム由来の ModelState キーをまとめて除外
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith("CauseAnalysis.") || k.StartsWith("Measures["))
            .ToList())
        {
            ModelState.Remove(key);
        }

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        // 入力値を本体に反映
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
            // DB に反映(この時点で衝突があれば例外に分岐)
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突発生: ログを残し、ユーザーに再読み込みを促す
            _logger.LogWarning(ex, "Concurrency conflict updating Incident {IncidentId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(Edit), new { id });
        }
        // 成功通知
        TempData["Success"] = "インシデントを更新しました。";
        // 詳細画面へリダイレクト
        return RedirectToAction(nameof(Details), new { id });
    }

    // POST /Incidents/Delete/5
    // インシデント削除(管理者/リスクマネージャー限定)
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
        // 無ければ 404
        if (incident == null) return NotFound();
        // 削除権限がなければ 403(部署スコープも考慮)
        if (!await IsAuthorizedFor(incident, Policies.CanDeleteIncident)) return Forbid();

        // 削除マークを付けて DB へ反映(子エンティティも監査対象になる)
        _db.Incidents.Remove(incident);
        await _db.SaveChangesAsync();
        // 成功通知
        TempData["Success"] = "インシデントを削除しました。";
        // 一覧へリダイレクト
        return RedirectToAction(nameof(Index));
    }

    // GET /Incidents/EditCauseAnalysis/5
    // 原因分析(なぜなぜ分析)の編集画面
    public async Task<IActionResult> EditCauseAnalysis(int id)
    {
        // 対象の分析をカテゴリ・親インシデントと一緒に取得
        var analysis = await _db.CauseAnalyses
            .Include(a => a.CauseCategory)
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        // 無ければ 404
        if (analysis == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        // 編集フォーム用 ViewModel を組み立てる
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
        // 編集ビューを返す
        return View(vm);
    }

    // POST /Incidents/EditCauseAnalysis/5
    // 原因分析の編集送信を受けて更新
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditCauseAnalysis(int id, CauseAnalysisFormViewModel vm)
    {
        // ドロップダウン選択肢はサーバーで補完するのでバリデーション対象外
        ModelState.Remove("CauseCategoryOptions");
        // バリデーション NG なら入力値を残して再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }
        // 対象分析を再取得
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        // 無ければ 404
        if (analysis == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        // 入力値で各フィールドを更新
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
        analysis.AnalyzedAt = _clock.Now;

        // 同時編集検知: クライアント保持トークンを OriginalValue にセット
        _db.Entry(analysis).Property(nameof(CauseAnalysis.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        try
        {
            // DB 反映
            await _db.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突発生: ログを残してユーザーに再読み込みを促す
            _logger.LogWarning(ex, "Concurrency conflict updating CauseAnalysis {AnalysisId}", id);
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(EditCauseAnalysis), new { id });
        }
        // 成功通知
        TempData["Success"] = "原因分析を更新しました。";
        // 親インシデントの詳細画面へリダイレクト
        return RedirectToAction(nameof(Details), new { id = analysis.IncidentId });
    }

    // POST /Incidents/AddCauseAnalysis
    // 詳細画面から原因分析を追加する
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddCauseAnalysis(CauseAnalysisFormViewModel vm)
    {
        // 親インシデントを取得
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // ドロップダウン選択肢はバリデーション対象外
        ModelState.Remove("CauseCategoryOptions");
        // 入力が妥当なら保存
        if (ModelState.IsValid)
        {
            // 新しい原因分析を ChangeTracker に追加
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
                AnalyzedAt = _clock.Now,
                AdditionalNotes = vm.AdditionalNotes
            });
            // DB に反映
            await _db.SaveChangesAsync();
            // 成功通知
            TempData["Success"] = "原因分析を追加しました。";
        }
        // 詳細画面へ戻す
        return RedirectToAction(nameof(Details), new { id = vm.IncidentId });
    }

    // POST /Incidents/DeleteCauseAnalysis/5
    // 原因分析の削除
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteCauseAnalysis(int id)
    {
        // 対象の分析を親インシデントとともに取得
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        // 無ければ 404
        if (analysis == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IsAuthorizedFor(analysis.Incident, Policies.CanEditIncident)) return Forbid();

        // リダイレクト先のインシデント ID を先に控える
        var incidentId = analysis.IncidentId;
        // 削除マークして DB に反映
        _db.CauseAnalyses.Remove(analysis);
        await _db.SaveChangesAsync();
        // 成功通知
        TempData["Success"] = "原因分析を削除しました。";
        // 詳細画面へ戻す
        return RedirectToAction(nameof(Details), new { id = incidentId });
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
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

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
        return RedirectToAction(nameof(Details), new { id = vm.IncidentId });
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
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

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
            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }
        // 成功通知(次ステップの有効性評価を促す)
        TempData["Success"] = "対策を完了しました。有効性評価を忘れずに行ってください。";
        // 詳細画面へ戻す
        return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
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
        if (!await IsAuthorizedFor(measure.Incident, Policies.CanEditIncident)) return Forbid();

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
            return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
        }

        // 再発が確認された場合は警告、されていなければ成功通知
        if (recurrenceObserved)
            TempData["Warning"] = "再発が確認されました。根本原因の再分析と追加対策を検討してください。";
        else
            TempData["Success"] = "有効性評価を登録しました。";

        // 詳細画面へ戻す
        return RedirectToAction(nameof(Details), new { id = measure.IncidentId });
    }

    // リソース（Incident）に対する Policy 評価。Admin/RiskManager は通過、Staff は部署一致で通過。
    private async Task<bool> IsAuthorizedFor(Incident? incident, string policy)
    {
        // null は認可不可として扱う(fail-closed)
        if (incident == null) return false;
        // 認可サービスに Incident をリソースとして渡して判定
        var result = await _auth.AuthorizeAsync(User, incident, policy);
        // 判定結果を返す
        return result.Succeeded;
    }

    // 原因カテゴリのドロップダウン用に、親カテゴリでグルーピングした子カテゴリ一覧を作る
    private async Task<List<SelectListItem>> BuildCauseCategoryOptions()
    {
        // 親カテゴリと子カテゴリをまとめて取得(表示順付き)
        var cats = await _db.CauseCategories
            .Include(c => c.Children)
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            .ToListAsync();

        // 生成するアイテム一覧
        var items = new List<SelectListItem>();
        // 親ごとにループして <optgroup> を作る
        foreach (var parent in cats)
        {
            // <optgroup> として表示される親カテゴリのグループ
            var group = new SelectListGroup { Name = parent.Name };
            // 子カテゴリを表示順に並べて追加
            foreach (var child in parent.Children.OrderBy(c => c.DisplayOrder))
            {
                // 1 行の <option> を作って追加
                items.Add(new SelectListItem
                {
                    Value = child.Id.ToString(),
                    Text = child.Name,
                    Group = group
                });
            }
        }
        // 完成した選択肢リストを返す
        return items;
    }
}
