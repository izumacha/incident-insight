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
}
