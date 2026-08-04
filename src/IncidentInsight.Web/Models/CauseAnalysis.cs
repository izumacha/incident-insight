// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 文字数上限の唯一の真実の源(FieldLengths)を使う
using IncidentInsight.Web.Models.Validation;
// 監査ログ用の Sensitive 属性(PHI マスキング指示)を使う
using IncidentInsight.Web.Models.Auditing;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

/// <summary>
/// なぜなぜ分析 (5 Whys) エンティティ
/// Why1〜5を独立カラムで保持することで根本原因パターンのSQL検索が可能
/// </summary>
public class CauseAnalysis
{
    // 主キー(自動採番)
    public int Id { get; set; }

    // 紐づくインシデントのID(必須)
    [Required]
    public int IncidentId { get; set; }
    // インシデント本体への参照(nullは想定していないので null! を付けている)
    public Incident Incident { get; set; } = null!;

    // 原因分類のID。画面で必ず選択が必要
    [Required(ErrorMessage = "原因分類を選択してください")]
    [Display(Name = "原因分類")]
    public int CauseCategoryId { get; set; }
    // 原因分類オブジェクトへの参照(EF Core が自動でロードする)
    public CauseCategory CauseCategory { get; set; } = null!;

    // 5 Whys chain
    // Why1〜Why5 と RootCauseSummary は患者情報が混入し得る自由記述。
    // 監査ログでは伏せる(マスキングは AuditSaveChangesInterceptor が適用する)
    // 「なぜ」1段階目。必ず入力が必要で、上限は FieldLengths.FreeText
    [Required(ErrorMessage = "なぜ1（表面的な原因）を入力してください")]
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "なぜ1（何が起きたか）")]
    [Sensitive(Mask.Redact)]
    public string Why1 { get; set; } = "";

    // 「なぜ」2段階目。省略可
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "なぜ2")]
    [Sensitive(Mask.Redact)]
    public string? Why2 { get; set; }

    // 「なぜ」3段階目。省略可
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "なぜ3")]
    [Sensitive(Mask.Redact)]
    public string? Why3 { get; set; }

    // 「なぜ」4段階目。省略可
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "なぜ4")]
    [Sensitive(Mask.Redact)]
    public string? Why4 { get; set; }

    // 「なぜ」5段階目(根本原因)。省略可
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "なぜ5（根本原因）")]
    [Sensitive(Mask.Redact)]
    public string? Why5 { get; set; }

    // 根本原因をまとめた文章(省略可)
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "根本原因まとめ")]
    [Sensitive(Mask.Redact)]
    public string? RootCauseSummary { get; set; }

    // 分析を行った人の名前(省略可)
    // 個人名なので監査ログではハッシュ化
    [MaxLength(FieldLengths.ShortText)]
    [Display(Name = "分析者")]
    [Sensitive(Mask.Hash)]
    public string? AnalystName { get; set; }

    // 分析を行った日時(省略可)
    [Display(Name = "分析日")]
    public DateTime? AnalyzedAt { get; set; }

    // 追加の補足メモ(省略可、上限は FieldLengths.FreeText)
    // 入力経路(CauseAnalysisFormViewModel)は同じ自由記述上限(FieldLengths.FreeText)を検証済みだが、EF Core は保存時に
    // DataAnnotations を自動検証しないため、Why1〜Why5/RootCauseSummary と同様にエンティティ側にも
    // [MaxLength] を明示しておく(将来別経路で書き込む実装が追加された際の検証漏れを防ぐ多層防御)
    // 自由記述のため PHI 混入リスクあり。監査ログでは伏せる
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "補足メモ")]
    [Sensitive(Mask.Redact)]
    public string? AdditionalNotes { get; set; }

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// </summary>
    // 同時編集を検知するためのトークン。初期値はランダムなGuid
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Computed
    // 5段階の中で最も深く掘り下げられた「なぜ」を返す(Why5→Why4→…の順)
    public string DeepestWhy => Why5 ?? Why4 ?? Why3 ?? Why2 ?? Why1;
    // 何段階まで「なぜ」を掘り下げたかの深さ(1〜5)
    public int WhyDepth => Why5 != null ? 5 : Why4 != null ? 4 : Why3 != null ? 3 : Why2 != null ? 2 : 1;
}
