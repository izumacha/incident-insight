using Microsoft.AspNetCore.Identity;

namespace IncidentInsight.Web.Models;

/// <summary>
/// アプリケーションユーザー — ASP.NET Core Identity 拡張
/// </summary>
public class ApplicationUser : IdentityUser
{
    /// <summary>表示名（フルネーム）</summary>
    public string? DisplayName { get; set; }

    /// <summary>所属部署</summary>
    public string? Department { get; set; }
}

/// <summary>
/// システムロール定数
/// </summary>
public static class AppRoles
{
    /// <summary>管理者 — 全機能 + ユーザー管理</summary>
    public const string Admin = "Admin";

    /// <summary>リスクマネージャー — 全インシデント閲覧・編集・分析</summary>
    public const string RiskManager = "RiskManager";

    /// <summary>スタッフ — 自部署インシデント閲覧 + 登録</summary>
    public const string Staff = "Staff";

    public static readonly string[] All = { Admin, RiskManager, Staff };
}
