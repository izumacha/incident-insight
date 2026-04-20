// ASP.NET Core Identity(認証機能)を使うためのライブラリを取り込む
using Microsoft.AspNetCore.Identity;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

/// <summary>
/// アプリケーションユーザー — ASP.NET Core Identity 拡張
/// </summary>
// Identity 標準の IdentityUser に自社独自の項目を付け足したユーザークラス
public class ApplicationUser : IdentityUser
{
    /// <summary>表示名（フルネーム）</summary>
    // 画面に表示する名前(苗字+名前など)。入っていない場合もあるので ? 付き
    public string? DisplayName { get; set; }

    /// <summary>所属部署</summary>
    // このユーザーがどの部署に所属しているかの文字列
    public string? Department { get; set; }
}

/// <summary>
/// システムロール定数
/// </summary>
// 役割名を文字列で持ちたいときに使う定数のまとめクラス(タイプミス防止のため)
public static class AppRoles
{
    /// <summary>管理者 — 全機能 + ユーザー管理</summary>
    // 管理者役割の名前定数
    public const string Admin = "Admin";

    /// <summary>リスクマネージャー — 全インシデント閲覧・編集・分析</summary>
    // リスクマネージャー役割の名前定数
    public const string RiskManager = "RiskManager";

    /// <summary>スタッフ — 自部署インシデント閲覧 + 登録</summary>
    // 一般スタッフ役割の名前定数
    public const string Staff = "Staff";

    // 全ての役割をまとめた配列(初期化時に一括でロールを作る場面で使う)
    public static readonly string[] All = { Admin, RiskManager, Staff };
}
