namespace IncidentInsight.Web.Authorization;

/// <summary>
/// 認可ポリシー名の定数。
/// コントローラでは <c>[Authorize(Policy = Policies.CanEditIncident)]</c> のように利用する。
/// </summary>
public static class Policies
{
    /// <summary>インシデント一覧・詳細の閲覧（自部署スコープ、Admin/RiskManager は全件）</summary>
    public const string CanViewIncident = nameof(CanViewIncident);

    /// <summary>インシデント・原因分析・再発防止策の編集（自部署スコープ、Admin/RiskManager は全件）</summary>
    public const string CanEditIncident = nameof(CanEditIncident);

    /// <summary>インシデント・再発防止策の削除（Admin / RiskManager 限定）</summary>
    public const string CanDeleteIncident = nameof(CanDeleteIncident);

    /// <summary>分析ダッシュボード（Admin / RiskManager 限定）</summary>
    public const string CanViewAnalytics = nameof(CanViewAnalytics);
}

/// <summary>
/// <see cref="System.Security.Claims.ClaimsPrincipal"/> に付与するカスタムクレームの種別。
/// </summary>
public static class AppClaimTypes
{
    /// <summary>ログインユーザーの所属部署 (<see cref="Models.ApplicationUser.Department"/>)</summary>
    public const string Department = "department";
}
