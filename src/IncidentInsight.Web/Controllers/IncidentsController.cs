// 部署スコープ拡張メソッド(ScopedByUser)を使う
using IncidentInsight.Web.Authorization;
// 共通ヘルパ(原因カテゴリ一覧 / 認可判定)を使う
using IncidentInsight.Web.Controllers.Internal;
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

// インシデントの登録・編集・削除を担当するコントローラ。
// 原因分析(なぜなぜ)のネスト操作は CauseAnalysesController、
// 対策追加・完了・有効性評価は IncidentMeasuresController が担う。
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
    // Create 登録画面で対策の実施期限の初期値として使う日数（今日から30日後）
    private const int DefaultMeasureDueDays = 30;

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
        // IClock から現在時刻を取得する(DateTime.Now を ViewModel 内で使わないための委譲)
        var now = _clock.Now;
        // 発生日時と対策の実施期限の既定値をクロックから設定して空の ViewModel を用意
        var vm = new IncidentCreateEditViewModel
        {
            // 発生日時の初期値: 現在時刻(JST ベースの IClock 経由)
            OccurredAt = now,
            // 対策リストの最初の行: 実施期限を30日後に設定する
            Measures = new List<MeasureFormViewModel>
            {
                new MeasureFormViewModel { DueDate = now.AddDays(DefaultMeasureDueDays) }
            },
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
        // なぜなぜ分析サブフォーム由来の ModelState キーを除外する。
        // Why2–5 などの任意項目やドロップダウン選択肢(CauseCategoryOptions)が
        // 未送信のときに残る不要な Required エラーを取り除く。原因分析は
        // CauseCategoryId と Why1 が揃ったときだけ保存するため、ここで一括除外してよい。
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith("CauseAnalysis."))
            .ToList())
        {
            // 原因分析サブフォーム由来の各キーを ModelState から除去する
            ModelState.Remove(key);
        }

        // 対策サブフォームの ModelState は「行ごと」に整理する。
        // Edit POST は対策を永続化しないため Measures[*] を一括削除して問題ないが、
        // Create POST は下の Where(Description 非空)で残った対策行を実際に保存する。
        // そのため一括削除はせず、保存されない空行(対策内容が未入力の行)だけ
        // Required エラーを取り除き、保存される行(対策内容あり)の担当者・担当部署・
        // 実施期限などのフィールド検証は残してデータ整合性を守る。
        // (一括削除すると DueDate=default(0001-01-01) のまま保存され IsOverdue が
        //  常に true になる等の不正データを生む。)
        for (int i = 0; vm.Measures != null && i < vm.Measures.Count; i++)
        {
            // この行が保存対象か(対策内容が入力されているか)を判定する
            if (!string.IsNullOrWhiteSpace(vm.Measures[i].Description))
                // 保存される行はフィールド検証を残すのでスキップ
                continue;

            // 保存されない空行のキー(Measures[i].*)だけをまとめて除去する。
            // 末尾に "]." まで含めてプレフィックス照合する。"Measures[1]" のように
            // 角括弧で止めると "Measures[10]." 等の別の行にも誤一致してしまうため。
            var rowPrefix = $"Measures[{i}].";
            foreach (var key in ModelState.Keys.Where(k => k.StartsWith(rowPrefix)).ToList())
            {
                // 空行由来の各キーを ModelState から除去する
                ModelState.Remove(key);
            }
        }

        // 部署スコープを強制する: Staff は自分の所属部署にしか登録できない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

        // 業務ルール: 再発防止策が1件も無ければ登録不可
        if (!HasAtLeastOneValidMeasure(vm.Measures))
            ModelState.AddModelError(nameof(vm.Measures), "再発防止策を1件以上入力してください。");

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        // Incident と関連エンティティを単一トランザクションで保存する。
        // トランザクションがないと、Incident は保存されたが対策がまだ保存されていない
        // 中間状態が生じ、「最低1件の対策が必要」という業務ルールが DB 上で破れる。
        await using var transaction = await _db.Database.BeginTransactionAsync();

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

        // ChangeTracker に追加して Id を採番するため一旦保存(まだコミットしない)
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

        // すべて正常に保存できたのでトランザクションをコミットする
        await transaction.CommitAsync();

        // 成功通知をセット(画面上のトースト表示用)
        TempData["Success"] = "インシデントを登録しました。";
        // 詳細画面にリダイレクト
        return RedirectToAction(nameof(Details), new { id = incident.Id });
    }

    // 「少なくとも1件の有効な対策が入力されているか」を判定するヘルパー
    private static bool HasAtLeastOneValidMeasure(IEnumerable<MeasureFormViewModel>? measures)
        => measures?.Any(m => !string.IsNullOrWhiteSpace(m.Description)) == true;

    // Staff(全件アクセス権を持たない役割)が登録・編集するインシデントの部署を、
    // フォーム入力ではなく本人の所属部署クレームに固定する(issue #63)。
    // 画面で他部署を選んでもサーバ側で上書きするため、他部署のキュー・ダッシュボード・
    // 再発統計への誤投入やなりすまし、編集での部署付け替えを防ぐ。閲覧側の
    // DepartmentScope.ScopedByUser と同じ判定(Admin/RiskManager は全件)で整合させる。
    private void EnforceOwnDepartmentForStaff(IncidentCreateEditViewModel vm)
    {
        // Admin / RiskManager は全部署を扱えるので、フォームの値をそのまま使う
        if (User.IsInRole(AppRoles.Admin) || User.IsInRole(AppRoles.RiskManager))
            return;

        // ログインユーザー(Staff)の所属部署クレームを取り出す
        var ownDepartment = User.FindFirst(AppClaimTypes.Department)?.Value;

        // 所属部署が未設定の Staff は自部署を特定できないので操作を拒否する(fail-closed)
        if (string.IsNullOrWhiteSpace(ownDepartment))
        {
            // 入力画面に戻すためのエラーを積む(Department 欄に紐づける)
            ModelState.AddModelError(
                nameof(vm.Department),
                "所属部署が設定されていないため、この操作は行えません。管理者に連絡してください。");
            return;
        }

        // フォームの値を無視し、必ず本人の所属部署に固定する(他部署への投入/付け替え防止)
        vm.Department = ownDepartment;

        // model binding が先に「Department が空」と判定した [Required] エラーを取り除く。
        // この時点では vm.Department に正しい値を設定済みなのでエラーは無効となる。
        // これを除去しないと ModelState.IsValid が false のままになり、
        // Staff がフォームを送信しても常にバリデーションエラーになってしまう(issue #63)。
        ModelState.Remove(nameof(vm.Department));
    }

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

        // 部署スコープを強制する: Staff は自部署のインシデントしか編集できず、
        // 他部署への付け替えもできない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

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

    // リソース(Incident)に対する Policy 評価をヘルパに委譲する小ラッパ。
    // 既存の呼び出し箇所(Details / Edit / Delete)から使うためインスタンスメソッドのまま残す。
    private Task<bool> IsAuthorizedFor(Incident? incident, string policy)
        => IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, incident, policy);

    // 原因カテゴリのドロップダウン用にヘルパへ委譲する小ラッパ
    private Task<List<SelectListItem>> BuildCauseCategoryOptions()
        => IncidentControllerHelpers.BuildCauseCategoryOptionsAsync(_db);
}
