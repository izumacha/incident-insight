using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

/// <summary>
/// 医療規制対応の監査ログ。SaveChangesInterceptor によって
/// Incident / CauseAnalysis / PreventiveMeasure の Add / Modify / Delete を自動記録する。
/// どの EF Core プロバイダでも動作するようにアプリ層で生成している。
/// </summary>
public class AuditLog
{
    public long Id { get; set; }

    [Required]
    public DateTime ChangedAt { get; set; }

    [MaxLength(256)]
    public string ChangedBy { get; set; } = "";

    [Required, MaxLength(100)]
    public string EntityName { get; set; } = "";

    [Required, MaxLength(64)]
    public string EntityKey { get; set; } = "";

    [Required, MaxLength(16)]
    public string Operation { get; set; } = "";  // Added / Modified / Deleted

    /// <summary>
    /// 変更されたプロパティを {name: {old, new}} 形式の JSON でシリアライズして保持。
    /// 全プロバイダで TEXT / nvarchar(max) 相当にマップされる。
    /// </summary>
    public string? ChangesJson { get; set; }
}
