// 属性(Requiredなど)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

/// <summary>
/// 医療規制対応の監査ログ。SaveChangesInterceptor によって
/// Incident / CauseAnalysis / PreventiveMeasure の Add / Modify / Delete を自動記録する。
/// どの EF Core プロバイダでも動作するようにアプリ層で生成している。
/// </summary>
public class AuditLog
{
    // 監査ログの主キー(自動採番。件数が増えても桁溢れしない long 型)
    public long Id { get; set; }

    // 変更が起きた日時(必須項目)
    [Required]
    public DateTime ChangedAt { get; set; }

    // 変更を行ったユーザー名(最大256文字まで)
    [MaxLength(256)]
    public string ChangedBy { get; set; } = "";

    // 変更対象のエンティティ(テーブル)名。必須で100文字まで
    [Required, MaxLength(100)]
    public string EntityName { get; set; } = "";

    // 変更対象の主キー値を文字列化したもの(複合キーにも対応できるよう文字列で保持)
    [Required, MaxLength(64)]
    public string EntityKey { get; set; } = "";

    // 操作種別。Added / Modified / Deleted のいずれかが入る
    [Required, MaxLength(16)]
    public string Operation { get; set; } = "";  // Added / Modified / Deleted

    /// <summary>
    /// 変更されたプロパティを {name: {old, new}} 形式の JSON でシリアライズして保持。
    /// 全プロバイダで TEXT / nvarchar(max) 相当にマップされる。
    /// </summary>
    // 変更内容の詳細(JSON文字列)。新規作成や削除では null のこともある
    public string? ChangesJson { get; set; }
}
