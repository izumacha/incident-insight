// DbContext を使う
using IncidentInsight.Web.Data;
// Incident エンティティを使う
using IncidentInsight.Web.Models;
// 認可サービスのインタフェース
using Microsoft.AspNetCore.Authorization;
// ClaimsPrincipal を扱う
using System.Security.Claims;
// SelectListItem / SelectListGroup(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張(Include / ToListAsync)
using Microsoft.EntityFrameworkCore;

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
}
