using Microsoft.AspNetCore.Authorization;

namespace IncidentInsight.Web.Authorization;

/// <summary>
/// リソース（Incident / PreventiveMeasure）が現在のユーザーと同じ部署に属することを要求する。
/// Admin / RiskManager ロールは部署に関わらず許可される。
/// </summary>
public sealed class SameDepartmentRequirement : IAuthorizationRequirement
{
}
