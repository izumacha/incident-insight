// DbContext を使う
using IncidentInsight.Web.Data;
// Incident エンティティを使う
using IncidentInsight.Web.Models;
// ViewModel(IncidentDetailViewModel / MeasureFormViewModel / CauseAnalysisFormViewModel)を使う
using IncidentInsight.Web.Models.ViewModels;
// 時刻源(IClock)・再発検知サービス(IRecurrenceService)を使う
using IncidentInsight.Web.Services;
// 認可サービスのインタフェース
using Microsoft.AspNetCore.Authorization;
// ClaimsPrincipal を扱う
using System.Security.Claims;
// SelectListItem / SelectListGroup(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張(Include / ToListAsync / DbUpdateConcurrencyException)
using Microsoft.EntityFrameworkCore;
// ILogger を使う(同時編集衝突のログ出力)
using Microsoft.Extensions.Logging;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// IncidentsController / CauseAnalysesController / IncidentMeasuresController が
/// 共有する小さなヘルパ群。テストを増やすほどの責務は持たず、純粋な再利用関数のみ置く。
/// 業務ルール(例: 「対策が1件以上」)は Controller 側に残し、ここには持ち込まない。
/// </summary>
internal static class IncidentControllerHelpers
{
    /// <summary>
    /// 原因カテゴリのドロップダウン用に、親カテゴリでグルーピングした子カテゴリ一覧を作る。
    /// </summary>
    public static async Task<List<SelectListItem>> BuildCauseCategoryOptionsAsync(ApplicationDbContext db)
    {
        // 親カテゴリと子カテゴリをまとめて取得(表示順付き)
        var cats = await db.CauseCategories
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

    /// <summary>
    /// 指定された原因カテゴリ Id が実在するかを返す。CauseAnalysis を保存する前に
    /// 外部キー(CauseCategoryId)の存在を確認し、存在しない Id による INSERT 失敗
    /// (未捕捉の DbUpdateException = HTTP 500)を未然に防ぐためのバリデーション用。
    /// </summary>
    public static Task<bool> CauseCategoryExistsAsync(ApplicationDbContext db, int causeCategoryId)
    {
        // 指定 Id の原因カテゴリが 1 件でも存在するかを問い合わせて返す
        return db.CauseCategories.AnyAsync(c => c.Id == causeCategoryId);
    }

    /// <summary>
    /// リソース(Incident)に対する Policy 評価。fail-closed: incident が null の場合は拒否する。
    /// SameDepartmentHandler が判定する都合上、呼び出し側は Incident を eager-load しておくこと。
    /// </summary>
    public static async Task<bool> IsAuthorizedForAsync(
        IAuthorizationService auth,
        ClaimsPrincipal user,
        Incident? incident,
        string policy)
    {
        // null は認可不可として扱う
        if (incident == null) return false;
        // 認可サービスに Incident をリソースとして渡して判定
        var result = await auth.AuthorizeAsync(user, incident, policy);
        return result.Succeeded;
    }

    /// <summary>
    /// 自由記述欄(Description/AnalysisNote/CompletionNote/EffectivenessNote 等)の共通文字数上限。
    /// ViewModel を介さず生の文字列を直接受け取る POST アクション(CompleteMeasure/RateMeasure/
    /// PreventiveMeasuresController.Complete)が、この定数を参照して手動検証する。
    /// </summary>
    public const int FreeTextMaxLength = 500;

    /// <summary>
    /// 生の文字列を直接受け取る POST アクション用の自由記述文字数チェック。EF Core は保存時に
    /// DataAnnotations を自動検証しないため、ViewModel を経由しない入力はここで明示的に検証する
    /// (§9 入力は信用しない)。null(未入力)は許容し、上限を超えたときだけメッセージを返す。
    /// </summary>
    public static string? ValidateFreeTextLength(string? value, string fieldLabel)
    {
        // 未入力、または上限内ならエラーなし
        if (value == null || value.Length <= FreeTextMaxLength) return null;
        // 上限超過なら呼び出し側がそのまま BadRequest に渡せるメッセージを返す
        return $"{fieldLabel}は{FreeTextMaxLength}文字以内で入力してください。";
    }

    /// <summary>
    /// 楽観的排他制御の保存試行を共通化するヘルパー。CauseAnalysesController /
    /// IncidentMeasuresController / IncidentsController / PreventiveMeasuresController の
    /// 各アクションで重複していた「SaveChangesAsync → DbUpdateConcurrencyException 捕捉 →
    /// ログ出力」の定型処理をここに集約する(CLAUDE.md §6 DRY)。
    /// クライアントの編集前トークンを OriginalValue にピンする行(1 行で完結し呼び出し側の
    /// エンティティ型ごとに異なるため、ここには含めない)は呼び出し側で事前に行っておくこと。
    /// 戻り値が false のとき、呼び出し側は TempData["Warning"] とリダイレクト先(アクションごとに
    /// 異なる)を決めて処理を続ける。
    /// </summary>
    public static async Task<bool> TrySaveChangesHandlingConcurrencyAsync(
        ApplicationDbContext db,
        ILogger logger,
        string conflictLogMessage,
        params object[] logArgs)
    {
        try
        {
            // 保存試行。事前にピンした OriginalValue と DB の現在値が食い違えば例外が飛ぶ
            await db.SaveChangesAsync();
            // 成功: 呼び出し側は通常どおり成功メッセージ・リダイレクトへ進んでよい
            return true;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突発生: ログを残す(呼び出し側ごとに異なるメッセージ/引数をそのまま使う)
            logger.LogWarning(ex, conflictLogMessage, logArgs);
            // 失敗を呼び出し側へ伝える(TempData["Warning"] とリダイレクトは呼び出し側の責務)
            return false;
        }
    }

    /// <summary>
    /// インシデント詳細画面(Details)用の <see cref="IncidentDetailViewModel"/> を組み立てる。
    /// <see cref="Controllers.IncidentsController.Details"/> の GET 本来の呼び出しに加え、
    /// AddMeasure/AddCauseAnalysis がバリデーション失敗時に(別コントローラから)同じ詳細画面を
    /// 入力済みの値を保持したまま再描画するためにも使う(CLAUDE.md §6 DRY)。
    ///
    /// AddMeasure/AddCauseAnalysis は成功時は Details へリダイレクトするが、失敗時に同じ
    /// redirect を使うと入力済みの値が失われる。TempData(既定はクッキーに乗る
    /// CookieTempDataProvider)へ入力値そのものを退避する方式は、自由記述欄(なぜなぜ分析・
    /// 対策内容等、PHI を含みうる)をクライアント側のクッキーへ丸ごと載せてしまう上、Cookie の
    /// 実質的なサイズ上限(多くのブラウザで 4KB 程度)を超える恐れもあるため採用しない。代わりに
    /// 呼び出し側がこのメソッドで Details と同じ ViewModel をサーバー側だけで組み立て直し、
    /// <c>newMeasureOverride</c>/<c>newCauseAnalysisOverride</c> にバリデーション失敗した入力値を
    /// 渡すことで、それを保持したまま Details ビューをそのまま再描画できる(データはクライアントを
    /// 経由しない)。両パラメータを省略した場合は通常の GET と同じ空の ViewModel になる。
    ///
    /// 呼び出し側は事前に認可チェック(CanView/CanEditIncident)を済ませておくこと(ここでは行わない)。
    /// </summary>
    /// <returns>インシデントが存在しなければ null(呼び出し側は 404 として扱う)。</returns>
    public static async Task<IncidentDetailViewModel?> BuildIncidentDetailViewModelAsync(
        ApplicationDbContext db,
        IRecurrenceService recurrence,
        IClock clock,
        int incidentId,
        MeasureFormViewModel? newMeasureOverride = null,
        CauseAnalysisFormViewModel? newCauseAnalysisOverride = null)
    {
        // 原因分析 → カテゴリ → 親カテゴリまで、および対策一覧を eager-load で取得
        // (IncidentsController.Details と同じクエリ)
        var incident = await db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory).ThenInclude(cc => cc!.Parent)
            .Include(i => i.PreventiveMeasures)
            .FirstOrDefaultAsync(i => i.Id == incidentId);
        // レコードが無ければ呼び出し側で 404 にできるよう null を返す
        if (incident == null) return null;

        // 再発検出(HomeController と同じマッチングルールを共有するサービスに委譲)。
        // 類似インシデント一覧を取得(期間無制限)
        var similar = await recurrence.FindRecurrencesForIncidentAsync(incident, db.Incidents);
        // 原因カテゴリのドロップダウン選択肢(親カテゴリでグルーピング)
        var causeOptions = await BuildCauseCategoryOptionsAsync(db);

        // 画面用 ViewModel を組み立てる。NewCauseAnalysis/NewMeasure は override が渡されて
        // いればそれを使い(バリデーション失敗した入力値の保持)、無ければ通常どおり空にする
        return new IncidentDetailViewModel
        {
            Incident = incident,
            SimilarIncidents = similar,
            CauseCategoryOptions = causeOptions,
            NewCauseAnalysis = newCauseAnalysisOverride ?? new CauseAnalysisFormViewModel { IncidentId = incidentId },
            // DueDate を IClock で既定の日数後に初期化する(IncidentsController.Details と同じ規約)
            NewMeasure = newMeasureOverride
                ?? new MeasureFormViewModel
                {
                    IncidentId = incidentId,
                    DueDate = clock.Today.AddDays(Controllers.IncidentsController.DefaultMeasureDueDays)
                }
        };
    }
}
