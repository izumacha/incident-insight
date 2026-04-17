using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Authorization;

namespace IncidentInsight.Web.Authorization;

/// <summary>
/// <see cref="SameDepartmentRequirement"/> をリソース型別に検証するハンドラ。
/// Admin / RiskManager は常に許可。Staff は <see cref="ApplicationUser.Department"/>
/// クレームとリソースの Department が一致した場合のみ許可。
/// </summary>
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

        var resourceDept = context.Resource switch
        {
            Incident inc              => inc.Department,
            PreventiveMeasure measure => measure.Incident?.Department ?? measure.ResponsibleDepartment,
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
