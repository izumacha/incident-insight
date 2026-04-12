using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

public class CauseCategory
{
    public int Id { get; set; }

    [Required]
    [MaxLength(100)]
    [Display(Name = "分類名")]
    public string Name { get; set; } = "";

    [Display(Name = "説明")]
    public string? Description { get; set; }

    [Display(Name = "親分類")]
    public int? ParentId { get; set; }

    [Display(Name = "表示順")]
    public int DisplayOrder { get; set; }

    // Navigation
    public CauseCategory? Parent { get; set; }
    public ICollection<CauseCategory> Children { get; set; } = new List<CauseCategory>();
    public ICollection<CauseAnalysis> CauseAnalyses { get; set; } = new List<CauseAnalysis>();

    public bool IsParent => ParentId == null;
    public string FullName => Parent != null ? $"{Parent.Name} > {Name}" : Name;
}
