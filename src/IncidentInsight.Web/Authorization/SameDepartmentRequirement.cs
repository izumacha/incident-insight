// 認可要件の基底インタフェースを使う
using Microsoft.AspNetCore.Authorization;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Authorization;

/// <summary>
/// リソース（Incident / PreventiveMeasure）が現在のユーザーと同じ部署に属することを要求する。
/// Admin / RiskManager ロールは部署に関わらず許可される。
/// </summary>
// 認可の「部署一致」要件を表すマーカークラス(判定処理は SameDepartmentHandler 側に書く)
public sealed class SameDepartmentRequirement : IAuthorizationRequirement
{
}
