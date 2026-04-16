using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

/// <summary>
/// なぜなぜ分析 (5 Whys) エンティティ
/// Why1〜5を独立カラムで保持することで根本原因パターンのSQL検索が可能
/// </summary>
public class CauseAnalysis
{
    public int Id { get; set; }

    [Required]
    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    [Required(ErrorMessage = "原因分類を選択してください")]
    [Display(Name = "原因分類")]
    public int CauseCategoryId { get; set; }
    public CauseCategory CauseCategory { get; set; } = null!;

    // 5 Whys chain
    [Required(ErrorMessage = "なぜ1（表面的な原因）を入力してください")]
    [MaxLength(500)]
    [Display(Name = "なぜ1（何が起きたか）")]
    public string Why1 { get; set; } = "";

    [MaxLength(500)]
    [Display(Name = "なぜ2")]
    public string? Why2 { get; set; }

    [MaxLength(500)]
    [Display(Name = "なぜ3")]
    public string? Why3 { get; set; }

    [MaxLength(500)]
    [Display(Name = "なぜ4")]
    public string? Why4 { get; set; }

    [MaxLength(500)]
    [Display(Name = "なぜ5（根本原因）")]
    public string? Why5 { get; set; }

    [MaxLength(500)]
    [Display(Name = "根本原因まとめ")]
    public string? RootCauseSummary { get; set; }

    [MaxLength(100)]
    [Display(Name = "分析者")]
    public string? AnalystName { get; set; }

    [Display(Name = "分析日")]
    public DateTime? AnalyzedAt { get; set; }

    [Display(Name = "補足メモ")]
    public string? AdditionalNotes { get; set; }

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// </summary>
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Computed
    public string DeepestWhy => Why5 ?? Why4 ?? Why3 ?? Why2 ?? Why1;
    public int WhyDepth => Why5 != null ? 5 : Why4 != null ? 4 : Why3 != null ? 3 : Why2 != null ? 2 : 1;
}
