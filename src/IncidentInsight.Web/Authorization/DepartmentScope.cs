// Claim(ClaimsPrincipal)を使うためのライブラリ
using System.Security.Claims;
// 自プロジェクトのモデル(Incident / PreventiveMeasure など)を使う
using IncidentInsight.Web.Models;

// この型の名前空間(置き場所)
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
    // Incident のクエリに対して、ログインユーザーの部署で絞り込む拡張メソッド
    public static IQueryable<Incident> ScopedByUser(this IQueryable<Incident> query, ClaimsPrincipal user)
    {
        // 管理者系は全件アクセス可能なのでそのまま返す
        if (HasFullAccess(user)) return query;

        // ユーザーの「部署」クレームを取り出す
        var dept = user.FindFirst(AppClaimTypes.Department)?.Value;
        // 部署情報が見つからなければ安全側に倒して空集合を返す
        if (string.IsNullOrWhiteSpace(dept))
        {
            // 部署不明の Staff は自分のデータに辿り着けないよう空集合を返す
            return query.Where(_ => false);
        }
        // 発生部署が自分の部署と一致するもののみに絞り込む
        return query.Where(i => i.Department == dept);
    }

    /// <summary>
    /// <see cref="PreventiveMeasure"/> を紐づく Incident の部署で絞り込む。
    /// </summary>
    // 再発防止策のクエリを、紐づくインシデントの発生部署で絞り込む拡張メソッド
    public static IQueryable<PreventiveMeasure> ScopedByUser(
        this IQueryable<PreventiveMeasure> query, ClaimsPrincipal user)
    {
        // 管理者系は全件アクセス可能
        if (HasFullAccess(user)) return query;

        // ユーザーの「部署」クレームを取り出す
        var dept = user.FindFirst(AppClaimTypes.Department)?.Value;
        // 部署クレームが無ければ空集合を返す(fail-closed)
        if (string.IsNullOrWhiteSpace(dept))
            return query.Where(_ => false);
        // インシデントの発生部署で絞り込む(対策自体の担当部署ではない点に注意)
        return query.Where(m => m.Incident.Department == dept);
    }

    // 全件アクセス可能な役割かどうかを判定するヘルパー
    private static bool HasFullAccess(ClaimsPrincipal user)
        => user.IsInRole(AppRoles.Admin) || user.IsInRole(AppRoles.RiskManager);
}
