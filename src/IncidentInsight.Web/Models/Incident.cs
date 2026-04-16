using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Web.Models;

public class Incident
{
    public int Id { get; set; }

    [Required(ErrorMessage = "発生日時は必須です")]
    [Display(Name = "発生日時")]
    public DateTime OccurredAt { get; set; } = DateTime.Now;

    [Required(ErrorMessage = "部署は必須です")]
    [MaxLength(100)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = "";

    [Required(ErrorMessage = "インシデント種別は必須です")]
    [MaxLength(50)]
    [Display(Name = "インシデント種別")]
    public string IncidentType { get; set; } = "";

    [Required(ErrorMessage = "重症度は必須です")]
    [MaxLength(20)]
    [Display(Name = "重症度")]
    public string Severity { get; set; } = "Level0";

    [Required(ErrorMessage = "インシデントの内容を入力してください")]
    [Display(Name = "状況・経緯")]
    public string Description { get; set; } = "";

    [Display(Name = "発生直後の対応")]
    public string? ImmediateActions { get; set; }

    [Required(ErrorMessage = "報告者名は必須です")]
    [MaxLength(100)]
    [Display(Name = "報告者")]
    public string ReporterName { get; set; } = "";

    [Display(Name = "報告日時")]
    public DateTime ReportedAt { get; set; } = DateTime.Now;

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// AuditSaveChangesInterceptor が更新時に新しい Guid を割り当てる。
    /// </summary>
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Navigation
    public ICollection<CauseAnalysis> CauseAnalyses { get; set; } = new List<CauseAnalysis>();
    public ICollection<PreventiveMeasure> PreventiveMeasures { get; set; } = new List<PreventiveMeasure>();

    // --- Static helper data ---
    public static readonly Dictionary<string, string> SeverityLevels = new()
    {
        ["Level0"] = "レベル0 (ヒヤリハット)",
        ["Level1"] = "レベル1 (患者への影響なし)",
        ["Level2"] = "レベル2 (観察強化)",
        ["Level3a"] = "レベル3a (軽微な処置)",
        ["Level3b"] = "レベル3b (濃厚な処置)",
        ["Level4"] = "レベル4 (永続的障害)",
        ["Level5"] = "レベル5 (死亡)"
    };

    public static readonly Dictionary<string, string> SeverityColors = new()
    {
        ["Level0"] = "secondary",
        ["Level1"] = "info",
        ["Level2"] = "primary",
        ["Level3a"] = "warning",
        ["Level3b"] = "warning",
        ["Level4"] = "danger",
        ["Level5"] = "dark"
    };

    public static readonly string[] IncidentTypes =
    {
        "転倒・転落",
        "投薬ミス",
        "検査ミス",
        "手術・処置関連",
        "医療機器関連",
        "チューブ・ライン関連",
        "感染予防",
        "患者確認ミス",
        "コミュニケーション",
        "その他"
    };

    public static readonly string[] Departments =
    {
        "内科病棟",
        "外科病棟",
        "ICU",
        "救急",
        "手術室",
        "外来",
        "薬剤部",
        "検査部",
        "放射線部",
        "リハビリ科",
        "その他"
    };

    // Computed helpers
    public string SeverityLabel => SeverityLevels.TryGetValue(Severity, out var s) ? s : Severity;
    public string SeverityColor => SeverityColors.TryGetValue(Severity, out var c) ? c : "secondary";

    public string MeasureStatusSummary
    {
        get
        {
            if (!PreventiveMeasures.Any()) return "未登録";
            if (PreventiveMeasures.All(m => m.Status == "Completed")) return "完了";
            if (PreventiveMeasures.Any(m => m.IsOverdue)) return "期限超過";
            if (PreventiveMeasures.Any(m => m.Status == "InProgress")) return "進行中";
            return "計画中";
        }
    }

    public string MeasureStatusColor => MeasureStatusSummary switch
    {
        "完了" => "success",
        "期限超過" => "danger",
        "進行中" => "primary",
        "計画中" => "warning",
        _ => "secondary"
    };
}
