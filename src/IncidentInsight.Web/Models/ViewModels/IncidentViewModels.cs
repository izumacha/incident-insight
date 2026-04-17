using System.ComponentModel.DataAnnotations;
using IncidentInsight.Web.Models.Enums;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IncidentInsight.Web.Models.ViewModels;

public class IncidentListViewModel
{
    public List<Incident> Incidents { get; set; } = new();
    public int TotalCount { get; set; }
    public int Page { get; set; } = 1;
    public int PageSize { get; set; } = 20;
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);

    // Filter state
    public string? Search { get; set; }
    public string? Department { get; set; }
    public IncidentTypeKind? IncidentType { get; set; }
    public IncidentSeverity? Severity { get; set; }
    public DateTime? DateFrom { get; set; }
    public DateTime? DateTo { get; set; }
    public int? CauseCategoryId { get; set; }
    public string? SortBy { get; set; }   // "latest" | "severity" | "overdue"

    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();
}

public class IncidentDetailViewModel
{
    public Incident Incident { get; set; } = null!;
    public List<Incident> SimilarIncidents { get; set; } = new();
    public bool HasRecurrenceWarning => SimilarIncidents.Any();

    // For inline cause analysis form
    public CauseAnalysisFormViewModel NewCauseAnalysis { get; set; } = new();
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    // For inline measure form
    public MeasureFormViewModel NewMeasure { get; set; } = new();
}

public class IncidentCreateEditViewModel
{
    public int Id { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    // hidden field でクライアントに渡して POST 時に戻ってきたものを OriginalValue に設定する。
    public Guid ConcurrencyToken { get; set; }

    [Required(ErrorMessage = "発生日時は必須です")]
    [Display(Name = "発生日時")]
    public DateTime OccurredAt { get; set; } = DateTime.Now;

    [Required(ErrorMessage = "部署は必須です")]
    [MaxLength(100)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = "";

    [Required(ErrorMessage = "インシデント種別は必須です")]
    [Display(Name = "インシデント種別")]
    public IncidentTypeKind IncidentType { get; set; } = IncidentTypeKind.Other;

    [Required(ErrorMessage = "重症度は必須です")]
    [Display(Name = "重症度")]
    public IncidentSeverity Severity { get; set; } = IncidentSeverity.Level0;

    [Required(ErrorMessage = "状況・経緯を入力してください")]
    [Display(Name = "状況・経緯")]
    public string Description { get; set; } = "";

    [Display(Name = "発生直後の対応")]
    public string? ImmediateActions { get; set; }

    [Required(ErrorMessage = "報告者名は必須です")]
    [MaxLength(100)]
    [Display(Name = "報告者")]
    public string ReporterName { get; set; } = "";

    // Tab 2: Cause Analysis
    public CauseAnalysisFormViewModel CauseAnalysis { get; set; } = new();
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    // Tab 3: Preventive Measures (at least one required)
    public List<MeasureFormViewModel> Measures { get; set; } = new() { new MeasureFormViewModel() };
}

public class CauseAnalysisFormViewModel
{
    public int Id { get; set; }
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    [Required(ErrorMessage = "原因分類を選択してください")]
    [Display(Name = "原因分類")]
    public int CauseCategoryId { get; set; }

    [Required(ErrorMessage = "なぜ1を入力してください")]
    [MaxLength(500)]
    [Display(Name = "なぜ1（何が起きたか・直接原因）")]
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

    [Display(Name = "補足メモ")]
    public string? AdditionalNotes { get; set; }

    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();
}

public class MeasureFormViewModel
{
    public int Id { get; set; }
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    [Required(ErrorMessage = "対策内容を入力してください")]
    [MaxLength(500)]
    [Display(Name = "対策内容")]
    public string Description { get; set; } = "";

    [Required(ErrorMessage = "対策種別を選択してください")]
    [Display(Name = "対策種別")]
    public MeasureTypeKind MeasureType { get; set; } = MeasureTypeKind.ShortTerm;

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

    [Display(Name = "優先度")]
    public int Priority { get; set; } = 2;

    [MaxLength(500)]
    [Display(Name = "立案根拠・背景メモ")]
    public string? AnalysisNote { get; set; }
}

public class CompleteViewModel
{
    public int Id { get; set; }
    [Display(Name = "完了報告内容")]
    public string? CompletionNote { get; set; }
}

public class ReviewViewModel
{
    public int Id { get; set; }

    // 楽観的同時実行制御トークン。
    public Guid ConcurrencyToken { get; set; }

    [Required]
    [Range(1, 5, ErrorMessage = "1〜5で評価してください")]
    [Display(Name = "有効性評価（1=効果なし〜5=非常に効果あり）")]
    public int EffectivenessRating { get; set; }

    [Display(Name = "有効性評価コメント")]
    public string? EffectivenessNote { get; set; }

    [Required]
    [Display(Name = "対策実施後に再発を確認したか")]
    public bool RecurrenceObserved { get; set; }
}
