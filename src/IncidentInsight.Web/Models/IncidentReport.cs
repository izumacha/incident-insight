using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

public class IncidentReport
{
    public int Id { get; set; }

    [Required]
    [StringLength(120)]
    public string Title { get; set; } = string.Empty;

    [Required]
    [StringLength(80)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = string.Empty;

    [Required]
    [StringLength(2000)]
    public string Description { get; set; } = string.Empty;

    [Display(Name = "発生日時")]
    public DateTime OccurredAt { get; set; } = DateTime.UtcNow;

    [Display(Name = "原因分類")]
    public CauseCategory CauseCategory { get; set; }

    [Range(1, 5)]
    [Display(Name = "重症度(1-5)")]
    public int Severity { get; set; } = 3;

    [Range(1, 5)]
    [Display(Name = "再発リスク(1-5)")]
    public int RecurrenceRisk { get; set; } = 3;

    [StringLength(2000)]
    [Display(Name = "初期対応")]
    public string InitialResponse { get; set; } = string.Empty;

    [StringLength(1200)]
    [Display(Name = "根本原因サマリ(5Why/要因分析)")]
    public string RootCauseSummary { get; set; } = string.Empty;

    [StringLength(1000)]
    [Display(Name = "潜在影響")]
    public string PotentialImpact { get; set; } = string.Empty;

    [Display(Name = "対応ステータス")]
    public IncidentLifecycleStatus LifecycleStatus { get; set; } = IncidentLifecycleStatus.Reported;

    public ICollection<Countermeasure> Countermeasures { get; set; } = new List<Countermeasure>();
}
