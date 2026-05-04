// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Authorization;

/// <summary>
/// 認可ポリシー名の定数。
/// コントローラでは <c>[Authorize(Policy = Policies.CanEditIncident)]</c> のように利用する。
/// </summary>
public static class Policies
{
    /// <summary>インシデント一覧・詳細の閲覧（自部署スコープ、Admin/RiskManager は全件）</summary>
    // インシデント閲覧用のポリシー名
    public const string CanViewIncident = nameof(CanViewIncident);

    /// <summary>インシデント・原因分析・再発防止策の編集（自部署スコープ、Admin/RiskManager は全件）</summary>
    // インシデント編集用のポリシー名
    public const string CanEditIncident = nameof(CanEditIncident);

    /// <summary>インシデント・再発防止策の削除（Admin / RiskManager 限定）</summary>
    // インシデント削除用のポリシー名(役割で制限)
    public const string CanDeleteIncident = nameof(CanDeleteIncident);

    /// <summary>分析ダッシュボード（Admin / RiskManager 限定）</summary>
    // 分析画面閲覧用のポリシー名
    public const string CanViewAnalytics = nameof(CanViewAnalytics);

    /// <summary>監査ログ閲覧（Admin 限定 — 規制対応のため最小権限で運用）</summary>
    // 監査ログ閲覧用のポリシー名(管理者のみ)
    public const string CanViewAuditLog = nameof(CanViewAuditLog);
}

/// <summary>
/// <see cref="System.Security.Claims.ClaimsPrincipal"/> に付与するカスタムクレームの種別。
/// </summary>
public static class AppClaimTypes
{
    /// <summary>ログインユーザーの所属部署 (<see cref="Models.ApplicationUser.Department"/>)</summary>
    // カスタムクレーム名「department」
    public const string Department = "department";
}
