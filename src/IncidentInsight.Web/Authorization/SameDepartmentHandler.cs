using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Authorization;

namespace IncidentInsight.Web.Authorization;

/// <summary>
/// <see cref="SameDepartmentRequirement"/> をリソース型別に検証するハンドラ。
/// Admin / RiskManager は常に許可。Staff は <see cref="ApplicationUser.Department"/>
/// クレームとリソースの Department が一致した場合のみ許可。
/// </summary>
/// <remarks>
/// 認可の判定基準は **インシデントの発生部署** (<c>Incident.Department</c>)。
/// <see cref="PreventiveMeasure"/> / <see cref="CauseAnalysis"/> をリソースに渡す場合は、
/// 呼び出し側で <c>.Include(x =&gt; x.Incident)</c> を付けてナビゲーションを eager-load すること。
/// <see cref="PreventiveMeasure.ResponsibleDepartment"/> は「対策を担当する部署」であって
/// 発生部署とは別概念のため、認可基準に混入してはならない
/// (フォールバックすると silent な認可バグになる — Issue #29)。
/// Incident が未ロードの場合は fail-closed で拒否する。
/// </remarks>
public sealed class SameDepartmentHandler : AuthorizationHandler<SameDepartmentRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SameDepartmentRequirement requirement)
    {
        // 管理者・リスクマネージャーは全部署横断で許可
        if (context.User.IsInRole(AppRoles.Admin) || context.User.IsInRole(AppRoles.RiskManager))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var userDept = context.User.FindFirst(AppClaimTypes.Department)?.Value;
        if (string.IsNullOrWhiteSpace(userDept))
        {
            // 部署不明の Staff は他部署にアクセスできない
            return Task.CompletedTask;
        }

        // Incident が未ロードのケースは null のままとし、下流で fail-closed で弾く。
        // ResponsibleDepartment へのフォールバックは意図的に行わない (Issue #29)。
        var resourceDept = context.Resource switch
        {
            Incident inc              => inc.Department,
            PreventiveMeasure measure => measure.Incident?.Department,
            CauseAnalysis analysis    => analysis.Incident?.Department,
            string deptString         => deptString,
            _                         => null
        };

        if (!string.IsNullOrWhiteSpace(resourceDept)
            && string.Equals(resourceDept, userDept, StringComparison.Ordinal))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
