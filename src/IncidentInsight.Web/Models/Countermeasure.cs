using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

public class Countermeasure
{
    public int Id { get; set; }

    public int IncidentReportId { get; set; }

    [Required]
    [StringLength(1000)]
    [Display(Name = "再発防止策")]
    public string ActionPlan { get; set; } = string.Empty;

    [StringLength(120)]
    [Display(Name = "担当者")]
    public string Owner { get; set; } = string.Empty;

    [Display(Name = "完了予定日")]
    public DateOnly? DueDate { get; set; }

    [Display(Name = "完了済み")]
    public bool IsCompleted { get; set; }

    [Range(1, 5)]
    [Display(Name = "有効性評価(1-5)")]
    public int EffectivenessScore { get; set; } = 3;

    [Display(Name = "評価日")]
    public DateOnly? ReviewDate { get; set; }

    [StringLength(1000)]
    [Display(Name = "評価コメント")]
    public string ReviewNote { get; set; } = string.Empty;

    public IncidentReport? IncidentReport { get; set; }
}
