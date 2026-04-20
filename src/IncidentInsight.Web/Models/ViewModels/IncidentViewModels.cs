// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// enum(重症度・種別など)を使えるようにする
using IncidentInsight.Web.Models.Enums;
// ドロップダウン用の SelectListItem を使えるようにする
using Microsoft.AspNetCore.Mvc.Rendering;

// ViewModel 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// インシデント一覧画面のモデル(絞り込み条件とページング情報を持つ)
public class IncidentListViewModel
{
    // 表示対象のインシデント行リスト
    public List<Incident> Incidents { get; set; } = new();
    // 絞り込み後の総件数(ページングの計算に使う)
    public int TotalCount { get; set; }
    // 現在表示中のページ番号(1始まり)
    public int Page { get; set; } = 1;
    // 1ページに表示する件数
    public int PageSize { get; set; } = 20;
    // 総ページ数(総件数÷ページサイズを切り上げ)
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);

    // Filter state
    // フリーワード検索キーワード
    public string? Search { get; set; }
    // 部署フィルタ
    public string? Department { get; set; }
    // インシデント種別フィルタ
    public IncidentTypeKind? IncidentType { get; set; }
    // 重症度フィルタ
    public IncidentSeverity? Severity { get; set; }
    // 発生日 絞り込み(開始日)
    public DateTime? DateFrom { get; set; }
    // 発生日 絞り込み(終了日)
    public DateTime? DateTo { get; set; }
    // 原因分類フィルタ(原因分類IDで絞り込み)
    public int? CauseCategoryId { get; set; }
    // 並び順の指定(最新/重症度/期限超過など)
    public string? SortBy { get; set; }   // "latest" | "severity" | "overdue"

    // 原因分類ドロップダウンの選択肢
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();
}

// インシデント詳細画面のモデル
public class IncidentDetailViewModel
{
    // 表示対象のインシデント本体
    public Incident Incident { get; set; } = null!;
    // 再発検知で見つかった類似インシデントのリスト
    public List<Incident> SimilarIncidents { get; set; } = new();
    // 再発警告を表示すべきか(類似が1件以上あれば true)
    public bool HasRecurrenceWarning => SimilarIncidents.Any();

    // For inline cause analysis form
    // 詳細画面から直接追加する「なぜなぜ分析」のフォーム用モデル
    public CauseAnalysisFormViewModel NewCauseAnalysis { get; set; } = new();
    // なぜなぜ分析フォーム用の原因分類ドロップダウン選択肢
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    // For inline measure form
    // 詳細画面から直接追加する「再発防止策」のフォーム用モデル
    public MeasureFormViewModel NewMeasure { get; set; } = new();
}

// インシデント登録/編集ウィザード用のモデル
public class IncidentCreateEditViewModel
{
    // ID(新規=0、編集時=既存ID)
    public int Id { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    // hidden field でクライアントに渡して POST 時に戻ってきたものを OriginalValue に設定する。
    public Guid ConcurrencyToken { get; set; }

    // 発生日時。必須で初期値は現在時刻
    [Required(ErrorMessage = "発生日時は必須です")]
    [Display(Name = "発生日時")]
    public DateTime OccurredAt { get; set; } = DateTime.Now;

    // 発生部署。必須で最大100文字
    [Required(ErrorMessage = "部署は必須です")]
    [MaxLength(100)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = "";

    // インシデント種別。必須で初期値「その他」
    [Required(ErrorMessage = "インシデント種別は必須です")]
    [Display(Name = "インシデント種別")]
    public IncidentTypeKind IncidentType { get; set; } = IncidentTypeKind.Other;

    // 重症度。必須で初期値「レベル0」
    [Required(ErrorMessage = "重症度は必須です")]
    [Display(Name = "重症度")]
    public IncidentSeverity Severity { get; set; } = IncidentSeverity.Level0;

    // 状況・経緯の記述(必須)
    [Required(ErrorMessage = "状況・経緯を入力してください")]
    [Display(Name = "状況・経緯")]
    public string Description { get; set; } = "";

    // 発生直後の応急対応(省略可)
    [Display(Name = "発生直後の対応")]
    public string? ImmediateActions { get; set; }

    // 報告者の名前。必須で最大100文字
    [Required(ErrorMessage = "報告者名は必須です")]
    [MaxLength(100)]
    [Display(Name = "報告者")]
    public string ReporterName { get; set; } = "";

    // Tab 2: Cause Analysis
    // ウィザードのなぜなぜ分析タブ用モデル
    public CauseAnalysisFormViewModel CauseAnalysis { get; set; } = new();
    // 原因分類のドロップダウン選択肢
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    // Tab 3: Preventive Measures (at least one required)
    // 再発防止策リスト(最低1件は必須)。初期値として空の対策フォームを1件入れておく
    public List<MeasureFormViewModel> Measures { get; set; } = new() { new MeasureFormViewModel() };
}

// なぜなぜ分析フォーム用のモデル
public class CauseAnalysisFormViewModel
{
    // 分析ID(新規=0)
    public int Id { get; set; }
    // 対応するインシデントID
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    // 原因分類。必須で画面から選択する
    [Required(ErrorMessage = "原因分類を選択してください")]
    [Display(Name = "原因分類")]
    public int CauseCategoryId { get; set; }

    // なぜ1。必須入力で最大500文字
    [Required(ErrorMessage = "なぜ1を入力してください")]
    [MaxLength(500)]
    [Display(Name = "なぜ1（何が起きたか・直接原因）")]
    public string Why1 { get; set; } = "";

    // なぜ2(任意)
    [MaxLength(500)]
    [Display(Name = "なぜ2")]
    public string? Why2 { get; set; }

    // なぜ3(任意)
    [MaxLength(500)]
    [Display(Name = "なぜ3")]
    public string? Why3 { get; set; }

    // なぜ4(任意)
    [MaxLength(500)]
    [Display(Name = "なぜ4")]
    public string? Why4 { get; set; }

    // なぜ5(根本原因、任意)
    [MaxLength(500)]
    [Display(Name = "なぜ5（根本原因）")]
    public string? Why5 { get; set; }

    // 根本原因まとめ(任意)
    [MaxLength(500)]
    [Display(Name = "根本原因まとめ")]
    public string? RootCauseSummary { get; set; }

    // 分析者の名前(任意)
    [MaxLength(100)]
    [Display(Name = "分析者")]
    public string? AnalystName { get; set; }

    // 補足メモ(任意)
    [Display(Name = "補足メモ")]
    public string? AdditionalNotes { get; set; }

    // 原因分類ドロップダウンの選択肢
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();
}

// 再発防止策フォーム用のモデル
public class MeasureFormViewModel
{
    // 対策ID(新規=0)
    public int Id { get; set; }
    // 対応するインシデントID
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    // 対策内容(必須で最大500文字)
    [Required(ErrorMessage = "対策内容を入力してください")]
    [MaxLength(500)]
    [Display(Name = "対策内容")]
    public string Description { get; set; } = "";

    // 対策種別(短期/長期、必須)
    [Required(ErrorMessage = "対策種別を選択してください")]
    [Display(Name = "対策種別")]
    public MeasureTypeKind MeasureType { get; set; } = MeasureTypeKind.ShortTerm;

    // 担当者(必須で最大100文字)
    [Required(ErrorMessage = "担当者を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当者")]
    public string ResponsiblePerson { get; set; } = "";

    // 担当部署(必須で最大100文字)
    [Required(ErrorMessage = "担当部署を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当部署")]
    public string ResponsibleDepartment { get; set; } = "";

    // 実施期限(必須、初期値は30日後)
    [Required(ErrorMessage = "実施期限を入力してください")]
    [Display(Name = "実施期限")]
    public DateTime DueDate { get; set; } = DateTime.Now.AddDays(30);

    // 優先度(1=高/2=中/3=低、初期値2)
    [Display(Name = "優先度")]
    public int Priority { get; set; } = 2;

    // 立案根拠・背景メモ(任意)
    [MaxLength(500)]
    [Display(Name = "立案根拠・背景メモ")]
    public string? AnalysisNote { get; set; }
}

// 対策を「完了」にするときのモデル
public class CompleteViewModel
{
    // 対象対策のID
    public int Id { get; set; }
    // 完了報告内容(任意)
    [Display(Name = "完了報告内容")]
    public string? CompletionNote { get; set; }
}

// 対策の有効性レビュー画面のモデル
public class ReviewViewModel
{
    // 対象対策のID
    public int Id { get; set; }

    // 楽観的同時実行制御トークン。
    public Guid ConcurrencyToken { get; set; }

    // 有効性評価(1〜5、必須)
    [Required]
    [Range(1, 5, ErrorMessage = "1〜5で評価してください")]
    [Display(Name = "有効性評価（1=効果なし〜5=非常に効果あり）")]
    public int EffectivenessRating { get; set; }

    // 有効性評価のコメント(任意)
    [Display(Name = "有効性評価コメント")]
    public string? EffectivenessNote { get; set; }

    // 対策後の再発有無(必須)
    [Required]
    [Display(Name = "対策実施後に再発を確認したか")]
    public bool RecurrenceObserved { get; set; }
}
