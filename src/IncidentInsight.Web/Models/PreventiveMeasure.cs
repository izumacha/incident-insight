using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

/// <summary>
/// 再発防止策エンティティ — 評価最重要
/// 対策の実施状況・有効性・再発確認まで一貫して追跡する
/// </summary>
public class PreventiveMeasure
{
    public int Id { get; set; }

    [Required]
    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    [Required(ErrorMessage = "対策内容を入力してください")]
    [MaxLength(500)]
    [Display(Name = "対策内容")]
    public string Description { get; set; } = "";

    [Required(ErrorMessage = "対策種別を選択してください")]
    [MaxLength(20)]
    [Display(Name = "対策種別")]
    public string MeasureType { get; set; } = Types.ShortTerm; // ShortTerm | LongTerm

    [Required(ErrorMessage = "担当者を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当者")]
    public string ResponsiblePerson { get; set; } = "";

    [Required(ErrorMessage = "担当部署を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当部署")]
    public string ResponsibleDepartment { get; set; } = "";

    [Required(ErrorMessage = "実施期限を入力してください")]
    [Display(Name = "実施期限")]
    public DateTime DueDate { get; set; } = DateTime.Now.AddDays(30);

    [MaxLength(500)]
    [Display(Name = "立案根拠・背景メモ")]
    public string? AnalysisNote { get; set; }

    // Status lifecycle: Planned → InProgress → Completed
    [MaxLength(20)]
    [Display(Name = "ステータス")]
    public string Status { get; set; } = Statuses.Planned;

    [Display(Name = "完了日")]
    public DateTime? CompletedAt { get; set; }

    [Display(Name = "完了報告内容")]
    public string? CompletionNote { get; set; }

    // Effectiveness review (post-implementation)
    [Range(1, 5)]
    [Display(Name = "有効性評価（1〜5）")]
    public int? EffectivenessRating { get; set; }

    [Display(Name = "有効性評価コメント")]
    public string? EffectivenessNote { get; set; }

    [Display(Name = "有効性評価日")]
    public DateTime? EffectivenessReviewedAt { get; set; }

    /// <summary>
    /// 再発確認フラグ: true=対策後も再発あり(追加対策必要), false=再発なし(効果あり)
    /// </summary>
    [Display(Name = "再発を確認したか")]
    public bool? RecurrenceObserved { get; set; }

    [Range(1, 3)]
    [Display(Name = "優先度")]
    public int Priority { get; set; } = 2; // 1=高, 2=中, 3=低

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// </summary>
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Computed helpers
    // DueDate の .Date を使うことで、期限日当日は「期限超過」にならない。
    public bool IsOverdue => Status != Statuses.Completed && DueDate.Date < DateTime.Today;

    public string StatusLabel => Status switch
    {
        Statuses.Planned => "計画中",
        Statuses.InProgress => "進行中",
        Statuses.Completed => "完了",
        _ => Status
    };

    public string StatusColor => Status switch
    {
        Statuses.Planned => IsOverdue ? "danger" : "warning",
        Statuses.InProgress => IsOverdue ? "danger" : "primary",
        Statuses.Completed => "success",
        _ => "secondary"
    };

    public string MeasureTypeLabel => MeasureType == Types.LongTerm ? "長期対策" : "短期対策";
    public string MeasureTypeColor => MeasureType == Types.LongTerm ? "info" : "success";

    public string PriorityLabel => Priority switch
    {
        1 => "高",
        2 => "中",
        3 => "低",
        _ => "-"
    };

    public string PriorityColor => Priority switch
    {
        1 => "danger",
        2 => "warning",
        3 => "secondary",
        _ => "secondary"
    };

    public string EffectivenessStars => EffectivenessRating.HasValue
        ? new string('★', EffectivenessRating.Value) + new string('☆', 5 - EffectivenessRating.Value)
        : "未評価";

    /// <summary>ステータスの値定数 (永続化キー)。</summary>
    public static class Statuses
    {
        public const string Planned = "Planned";
        public const string InProgress = "InProgress";
        public const string Completed = "Completed";
    }

    /// <summary>対策種別の値定数 (永続化キー)。</summary>
    public static class Types
    {
        public const string ShortTerm = "ShortTerm";
        public const string LongTerm = "LongTerm";
    }

    public static readonly string[] MeasureTypes = { Types.ShortTerm, Types.LongTerm };
    public static readonly string[] StatusValues = { Statuses.Planned, Statuses.InProgress, Statuses.Completed };
}
