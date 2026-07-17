// 共通ヘルパ(原因カテゴリ一覧 / 認可判定)
using IncidentInsight.Web.Controllers.Internal;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(CauseAnalysis / Incident)
using IncidentInsight.Web.Models;
// ViewModel(CauseAnalysisFormViewModel)
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
/// なぜなぜ分析(CauseAnalysis)の追加・編集・削除を担当するコントローラ。
///
/// 互換性のため URL は従来の /Incidents/{Action}/{id?} を維持する。
/// 例: /Incidents/EditCauseAnalysis/5 → このコントローラが処理する。
/// View 側のフォームは asp-controller="CauseAnalyses" を指定すること。
/// </summary>
[Authorize]
[Route("Incidents/[action]/{id?}")]
public class CauseAnalysesController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // リソース認可評価用サービス
    private readonly IAuthorizationService _auth;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;
    // 再発検知サービス(AddCauseAnalysis がバリデーション失敗時に Details ビューモデルを
    // 組み立て直す際、IncidentsController.Details と同じ内容にするために必要)
    private readonly IRecurrenceService _recurrence;
    // ログ出力用(同時編集衝突などの警告)
    private readonly ILogger<CauseAnalysesController> _logger;

    // コンストラクタ: DI で依存を受け取る
    public CauseAnalysesController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IClock clock,
        IRecurrenceService recurrence,
        ILogger<CauseAnalysesController> logger)
    {
        _db = db;
        _auth = auth;
        _clock = clock;
        _recurrence = recurrence;
        _logger = logger;
    }

    // GET /Incidents/EditCauseAnalysis/5
    // 原因分析(なぜなぜ分析)の編集画面
    [HttpGet]
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
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, analysis.Incident, Policies.CanEditIncident))
            return Forbid();

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
            CauseCategoryOptions = await IncidentControllerHelpers.BuildCauseCategoryOptionsAsync(_db)
        };
        // 編集ビューを返す。Views/Incidents/EditCauseAnalysis.cshtml を流用するため明示指定する。
        return View("~/Views/Incidents/EditCauseAnalysis.cshtml", vm);
    }

    // POST /Incidents/EditCauseAnalysis/5
    // 原因分析の編集送信を受けて更新
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditCauseAnalysis(int id, CauseAnalysisFormViewModel vm)
    {
        // 対象分析を再取得(認可判定のため Incident を eager-load)
        // 認可チェックを ModelState 検証より先に行うことで、未認可ユーザが無効入力でも 403 を受け取れるようにする（防御的設計）
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        // 無ければ 404
        if (analysis == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403（バリデーション前にチェックして認可バイパスを防ぐ）
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, analysis.Incident, Policies.CanEditIncident))
            return Forbid();

        // ドロップダウン選択肢はサーバーで補完するのでバリデーション対象外
        ModelState.Remove("CauseCategoryOptions");
        // 選択された原因カテゴリが実在しない場合は入力不備として扱い、存在しない外部キーによる
        // INSERT 失敗(未捕捉の DbUpdateException = HTTP 500)を未然に防ぐ
        if (vm.CauseCategoryId > 0
            && !await IncidentControllerHelpers.CauseCategoryExistsAsync(_db, vm.CauseCategoryId))
        {
            ModelState.AddModelError(nameof(vm.CauseCategoryId), "選択された原因カテゴリが存在しません。");
        }
        // バリデーション NG なら入力値を残して再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await IncidentControllerHelpers.BuildCauseCategoryOptionsAsync(_db);
            return View("~/Views/Incidents/EditCauseAnalysis.cshtml", vm);
        }

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

        // DB 反映を試行(衝突時はログを残してユーザーに再読み込みを促す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict updating CauseAnalysis {AnalysisId}", id))
        {
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(EditCauseAnalysis), new { id });
        }
        // 成功通知
        TempData["Success"] = "原因分析を更新しました。";
        // 親インシデントの詳細画面へリダイレクト
        return RedirectToAction("Details", "Incidents", new { id = analysis.IncidentId });
    }

    // POST /Incidents/AddCauseAnalysis
    // 詳細画面から原因分析を追加する
    // 注: 詳細画面のフォームは IncidentDetailViewModel.NewCauseAnalysis 経由で描画されるため、
    //     フィールド名は「NewCauseAnalysis.Why1」のように prefix 付きで POST される。
    //     Bind(Prefix) を指定しないとバインダが空 prefix にフォールバックして
    //     IncidentId が 0 のままになり、常に 404 になる。
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddCauseAnalysis(
        [Bind(Prefix = nameof(IncidentDetailViewModel.NewCauseAnalysis))] CauseAnalysisFormViewModel vm)
    {
        // 親インシデントを取得
        var incident = await _db.Incidents.FindAsync(vm.IncidentId);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, incident, Policies.CanEditIncident))
            return Forbid();

        // ドロップダウン選択肢はバリデーション対象外
        // (prefix バインドのため ModelState 上のキーも「NewCauseAnalysis.」付きになる)
        ModelState.Remove($"{nameof(IncidentDetailViewModel.NewCauseAnalysis)}.{nameof(vm.CauseCategoryOptions)}");
        // 選択された原因カテゴリが実在しない場合は入力不備として扱い、存在しない外部キーによる
        // INSERT 失敗(未捕捉の DbUpdateException = HTTP 500)を未然に防ぐ
        if (vm.CauseCategoryId > 0
            && !await IncidentControllerHelpers.CauseCategoryExistsAsync(_db, vm.CauseCategoryId))
        {
            ModelState.AddModelError(nameof(vm.CauseCategoryId), "選択された原因カテゴリが存在しません。");
        }
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
            // 詳細画面へ戻す
            return RedirectToAction("Details", "Incidents", new { id = vm.IncidentId });
        }

        // バリデーション失敗: 黙って飲み込まずユーザーに入力不備を通知する。
        // このアクションは成功時は Details へリダイレクトするが、失敗時に同じ redirect を
        // 使うと入力済みの値が失われてしまう。TempData(既定はクッキーに乗る
        // CookieTempDataProvider)へ入力値そのものを退避する方式は、自由記述欄
        // (なぜなぜ分析の各項目等、PHI を含みうる)をクライアント側のクッキーへ丸ごと
        // 載せてしまう上、Cookie の実質的なサイズ上限(多くのブラウザで 4KB 程度)を
        // 超える恐れもあるため採用しない(IncidentMeasuresController.AddMeasure と同じ理由)。
        // 代わりに Details と同じ ViewModel をこの場でサーバー側だけで組み立て、入力済みの
        // 値を保持したまま Details ビューをそのまま再描画する(データはクライアントを経由しない)。
        TempData["Warning"] = "入力内容に不備があります。原因分析フォームの項目を確認してください。";
        var detailVm = await IncidentControllerHelpers.BuildIncidentDetailViewModelAsync(
            _db, _recurrence, _clock, vm.IncidentId, newCauseAnalysisOverride: vm);
        return View("~/Views/Incidents/Details.cshtml", detailVm);
    }

    // POST /Incidents/DeleteCauseAnalysis/5
    // 原因分析の削除
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteCauseAnalysis(int id, Guid concurrencyToken)
    {
        // 対象の分析を親インシデントとともに取得
        var analysis = await _db.CauseAnalyses
            .Include(a => a.Incident)
            .FirstOrDefaultAsync(a => a.Id == id);
        // 無ければ 404
        if (analysis == null) return NotFound();
        // 親インシデントへの編集権限がなければ 403
        if (!await IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, analysis.Incident, Policies.CanEditIncident))
            return Forbid();

        // 同時編集検知のトークン固定(画面表示後に他ユーザーが更新した内容を
        // 気づかず削除してしまわないよう、クライアントが保持していた表示時点の
        // トークンを DB の現在値と突き合わせる)
        _db.Entry(analysis).Property(nameof(CauseAnalysis.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // リダイレクト先のインシデント ID を先に控える
        var incidentId = analysis.IncidentId;
        // 削除マークして DB に反映
        _db.CauseAnalyses.Remove(analysis);
        // 保存試行(この時点で他ユーザーの更新と衝突していれば共通処理がログを残す)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict deleting CauseAnalysis {AnalysisId}", id))
        {
            TempData["Warning"] = "他のユーザが先に更新したため、削除できませんでした。画面を更新してから再度操作してください。";
            return RedirectToAction("Details", "Incidents", new { id = incidentId });
        }
        // 成功通知
        TempData["Success"] = "原因分析を削除しました。";
        // 詳細画面へ戻す
        return RedirectToAction("Details", "Incidents", new { id = incidentId });
    }
}
