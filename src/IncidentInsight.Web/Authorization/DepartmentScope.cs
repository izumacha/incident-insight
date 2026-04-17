using System.Security.Claims;
using IncidentInsight.Web.Models;

namespace IncidentInsight.Web.Authorization;

/// <summary>
/// 一覧クエリに対する「自部署だけ」のフィルタを注入する拡張メソッド。
/// Admin / RiskManager はフィルタを掛けず全件を返す。
/// </summary>
public static class DepartmentScope
{
    /// <summary>
    /// Staff の場合、<see cref="ApplicationUser.Department"/> クレームで
    /// <see cref="Incident.Department"/> を絞り込む。
    /// Admin / RiskManager および部署クレーム未設定の場合は何もしない。
    /// </summary>
    public static IQueryable<Incident> ScopedByUser(this IQueryable<Incident> query, ClaimsPrincipal user)
    {
        if (HasFullAccess(user)) return query;

        var dept = user.FindFirst(AppClaimTypes.Department)?.Value;
        if (string.IsNullOrWhiteSpace(dept))
        {
            // 部署不明の Staff は自分のデータに辿り着けないよう空集合を返す
            return query.Where(_ => false);
        }
        return query.Where(i => i.Department == dept);
    }

    /// <summary>
    /// <see cref="PreventiveMeasure"/> を紐づく Incident の部署で絞り込む。
    /// </summary>
    public static IQueryable<PreventiveMeasure> ScopedByUser(
        this IQueryable<PreventiveMeasure> query, ClaimsPrincipal user)
    {
        if (HasFullAccess(user)) return query;

        var dept = user.FindFirst(AppClaimTypes.Department)?.Value;
        if (string.IsNullOrWhiteSpace(dept))
            return query.Where(_ => false);
        return query.Where(m => m.Incident.Department == dept);
    }

    private static bool HasFullAccess(ClaimsPrincipal user)
        => user.IsInRole(AppRoles.Admin) || user.IsInRole(AppRoles.RiskManager);
}
