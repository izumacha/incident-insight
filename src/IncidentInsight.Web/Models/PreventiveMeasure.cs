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
    public string MeasureType { get; set; } = "ShortTerm"; // ShortTerm | LongTerm

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

    // Status lifecycle: Planned → InProgress → Completed
    [MaxLength(20)]
    [Display(Name = "ステータス")]
    public string Status { get; set; } = "Planned";

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

    // Computed helpers
    public bool IsOverdue => Status != "Completed" && DueDate < DateTime.Today;

    public string StatusLabel => Status switch
    {
        "Planned" => "計画中",
        "InProgress" => "進行中",
        "Completed" => "完了",
        _ => Status
    };

    public string StatusColor => Status switch
    {
        "Planned" => IsOverdue ? "danger" : "warning",
        "InProgress" => IsOverdue ? "danger" : "primary",
        "Completed" => "success",
        _ => "secondary"
    };

    public string MeasureTypeLabel => MeasureType == "LongTerm" ? "長期対策" : "短期対策";
    public string MeasureTypeColor => MeasureType == "LongTerm" ? "info" : "success";

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

    public static readonly string[] MeasureTypes = { "ShortTerm", "LongTerm" };
    public static readonly string[] StatusValues = { "Planned", "InProgress", "Completed" };
}
