using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

public class IncidentReport
{
    public int Id { get; set; }

    [Required]
    [StringLength(120)]
    public string Title { get; set; } = string.Empty;

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

    [StringLength(2000)]
    [Display(Name = "初期対応")]
    public string InitialResponse { get; set; } = string.Empty;

    public ICollection<Countermeasure> Countermeasures { get; set; } = new List<Countermeasure>();
}
