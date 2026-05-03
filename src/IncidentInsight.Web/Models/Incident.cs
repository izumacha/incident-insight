// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 監査ログ用の Sensitive 属性(PHI マスキング指示)を使う
using IncidentInsight.Web.Models.Auditing;
// 自プロジェクトの enum 群(重症度などの定義)を使えるようにする
using IncidentInsight.Web.Models.Enums;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

// インシデント(医療事故・ヒヤリハット)を表すルートエンティティ
public class Incident
{
    // 主キー(自動採番)
    public int Id { get; set; }

    // インシデント発生日時。必須で、初期値は現在時刻
    [Required(ErrorMessage = "発生日時は必須です")]
    [Display(Name = "発生日時")]
    public DateTime OccurredAt { get; set; } = DateTime.Now;

    // 発生部署名。必須で最大100文字まで
    [Required(ErrorMessage = "部署は必須です")]
    [MaxLength(100)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = "";

    // インシデントの種別。必須で、初期値は「その他」
    [Required(ErrorMessage = "インシデント種別は必須です")]
    [Display(Name = "インシデント種別")]
    public IncidentTypeKind IncidentType { get; set; } = IncidentTypeKind.Other;

    // 重症度レベル。必須で、初期値は「ヒヤリハット(レベル0)」
    [Required(ErrorMessage = "重症度は必須です")]
    [Display(Name = "重症度")]
    public IncidentSeverity Severity { get; set; } = IncidentSeverity.Level0;

    // 発生状況や経緯の説明。必須
    // 患者情報が混入する可能性があるため監査ログでは必ず伏せる
    [Required(ErrorMessage = "インシデントの内容を入力してください")]
    [Display(Name = "状況・経緯")]
    [Sensitive(Mask.Redact)]
    public string Description { get; set; } = "";

    // 発生直後に行った応急対応(省略可)
    // 自由記述のため PHI 混入リスクあり。監査ログでは伏せる
    [Display(Name = "発生直後の対応")]
    [Sensitive(Mask.Redact)]
    public string? ImmediateActions { get; set; }

    // 報告者の名前。必須で最大100文字まで
    // 個人名なので監査ログではハッシュ化(同一人物による報告かどうかの監査だけ可能)
    [Required(ErrorMessage = "報告者名は必須です")]
    [MaxLength(100)]
    [Display(Name = "報告者")]
    [Sensitive(Mask.Hash)]
    public string ReporterName { get; set; } = "";

    // 報告を登録した日時。初期値は現在時刻
    [Display(Name = "報告日時")]
    public DateTime ReportedAt { get; set; } = DateTime.Now;

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// AuditSaveChangesInterceptor が更新時に新しい Guid を割り当てる。
    /// </summary>
    // 編集衝突を検知するためのトークン。初期値はランダムなGuid
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Navigation
    // このインシデントに紐づく「なぜなぜ分析」のリスト
    public ICollection<CauseAnalysis> CauseAnalyses { get; set; } = new List<CauseAnalysis>();
    // このインシデントに紐づく「再発防止策」のリスト
    public ICollection<PreventiveMeasure> PreventiveMeasures { get; set; } = new List<PreventiveMeasure>();

    // --- Static helper data ---
    // 部署名の選択肢(画面のドロップダウン等で共通利用する)
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
    // 重症度の日本語ラベル(例: 「レベル3a (軽微な処置)」)
    public string SeverityLabel => EnumLabels.Japanese(Severity);
    // 重症度に対応する Bootstrap のカラー名(バッジの色分けに使う)
    public string SeverityColor => EnumLabels.Color(Severity);
    // インシデント種別の日本語ラベル
    public string IncidentTypeLabel => IncidentTypeMapping.JapaneseLabel(IncidentType);

    // 再発防止策の全体状況を日本語の一言で返す
    public string MeasureStatusSummary
    {
        get
        {
            // 対策が1件もなければ「未登録」
            if (!PreventiveMeasures.Any()) return "未登録";
            // 全ての対策が完了していれば「完了」
            if (PreventiveMeasures.All(m => m.Status == Enums.MeasureStatus.Completed)) return "完了";
            // 1件でも期限超過があれば「期限超過」
            if (PreventiveMeasures.Any(m => m.IsOverdue)) return "期限超過";
            // 進行中のものがあれば「進行中」
            if (PreventiveMeasures.Any(m => m.Status == Enums.MeasureStatus.InProgress)) return "進行中";
            // どれにも当てはまらなければ「計画中」
            return "計画中";
        }
    }

    // 状況サマリ文字列から Bootstrap のカラー名に変換(バッジ色分け用)
    public string MeasureStatusColor => MeasureStatusSummary switch
    {
        "完了" => "success",
        "期限超過" => "danger",
        "進行中" => "primary",
        "計画中" => "warning",
        _ => "secondary"
    };
}
