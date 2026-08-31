// ASP.NET Core Identity(認証機能)を使うためのライブラリを取り込む
using Microsoft.AspNetCore.Identity;
// [MaxLength] 属性を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 文字数上限の唯一の真実の源(FieldLengths)を使うために取り込む
using IncidentInsight.Web.Models.Validation;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

/// <summary>
/// アプリケーションユーザー — ASP.NET Core Identity 拡張
/// </summary>
// Identity 標準の IdentityUser に自社独自の項目を付け足したユーザークラス
public class ApplicationUser : IdentityUser
{
    /// <summary>表示名（フルネーム）</summary>
    // 画面に表示する名前(苗字+名前など)。入っていない場合もあるので ? 付き。
    // 上限は氏名と同じ FieldLengths.ShortText。Identity が列長を決めるのは Identity 自身が
    // 宣言した列(UserName / Email など)だけで、この 2 列はこのリポジトリが足した業務列なので
    // 上限も自分たちで持つ。無いままだと SQL Server では nvarchar(max)、PostgreSQL では text の
    // 無制限列になる(§8 の資源枯渇防止・§9 の DoS 防止に反する)
    [MaxLength(FieldLengths.ShortText)]
    public string? DisplayName { get; set; }

    /// <summary>所属部署</summary>
    // このユーザーがどの部署に所属しているかの文字列。
    // Incident.Department と同じ語彙なので上限も同じ FieldLengths.ShortText に揃える
    [MaxLength(FieldLengths.ShortText)]
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
