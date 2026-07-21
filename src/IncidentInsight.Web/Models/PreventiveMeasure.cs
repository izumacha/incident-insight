// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 「期限超過」を式ツリー(Expression)で表し EF が SQL へ翻訳できるようにするため取り込む
using System.Linq.Expressions;
// 監査ログ用の Sensitive 属性(PHI マスキング指示)を使う
using IncidentInsight.Web.Models.Auditing;
// 自プロジェクトの enum 群(対策種別・状態など)を使えるようにする
using IncidentInsight.Web.Models.Enums;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

/// <summary>
/// 再発防止策エンティティ — 評価最重要
/// 対策の実施状況・有効性・再発確認まで一貫して追跡する
/// </summary>
public class PreventiveMeasure
{
    // 主キー(自動採番)
    public int Id { get; set; }

    // 紐づくインシデントのID(必須)
    [Required]
    public int IncidentId { get; set; }
    // インシデント本体への参照
    public Incident Incident { get; set; } = null!;

    // 対策の内容(具体的に何をするか)。必須で最大500文字まで
    // 業務記述のためマスキング対象外でも問題は少ないが、表現に患者情報が
    // 含まれる可能性があるため監査ログでは伏せる
    [Required(ErrorMessage = "対策内容を入力してください")]
    [MaxLength(500)]
    [Display(Name = "対策内容")]
    [Sensitive(Mask.Redact)]
    public string Description { get; set; } = "";

    // 短期 or 長期の区分。必須で、初期値は「短期対策」
    [Required(ErrorMessage = "対策種別を選択してください")]
    [Display(Name = "対策種別")]
    public MeasureTypeKind MeasureType { get; set; } = MeasureTypeKind.ShortTerm;

    // 対策を担当する人の名前。必須で最大100文字まで
    // 個人名のため監査ログではハッシュ化(担当者単位の追跡だけ可能)
    [Required(ErrorMessage = "担当者を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当者")]
    [Sensitive(Mask.Hash)]
    public string ResponsiblePerson { get; set; } = "";

    // 対策を担当する部署。必須で最大100文字まで
    // Incident.Department（static 辞書に縛られたドロップダウン値）とは異なり自由記述の
    // <input> のため、誤って個人名や補足メモが混入する余地がある。他の自由記述列
    // (Description/AnalysisNote)と同様に監査ログでは伏せる
    [Required(ErrorMessage = "担当部署を入力してください")]
    [MaxLength(100)]
    [Display(Name = "担当部署")]
    [Sensitive(Mask.Redact)]
    public string ResponsibleDepartment { get; set; } = "";

    // 実施期限。必須。初期値はコントローラが IClock 経由で設定する(ここでは DateTime.Now を使わない)
    [Required(ErrorMessage = "実施期限を入力してください")]
    [Display(Name = "実施期限")]
    public DateTime DueDate { get; set; }

    // 対策立案の根拠や背景メモ(省略可、最大500文字)
    // 自由記述のため PHI 混入リスクあり。監査ログでは伏せる
    [MaxLength(500)]
    [Display(Name = "立案根拠・背景メモ")]
    [Sensitive(Mask.Redact)]
    public string? AnalysisNote { get; set; }

    // Status lifecycle: Planned → InProgress → Completed
    // 対策の進行状況。初期値は「計画中」
    [Display(Name = "ステータス")]
    public MeasureStatus Status { get; set; } = MeasureStatus.Planned;

    // 完了した日付(省略可)
    [Display(Name = "完了日")]
    public DateTime? CompletedAt { get; set; }

    // 完了報告の内容(省略可、最大500文字)
    // ViewModel を経由せず生の文字列を直接受け取る POST アクション(CompleteMeasure/
    // PreventiveMeasuresController.Complete)が IncidentControllerHelpers.ValidateFreeTextLength
    // で同じ500文字上限を手動検証済みのため実害は無いが、Description/AnalysisNote と同様に
    // エンティティ側にも [MaxLength] を明示しておく(将来別経路で書き込む実装が追加された際の
    // 検証漏れを防ぐ多層防御)。自由記述のため PHI 混入リスクあり。監査ログでは伏せる
    [MaxLength(500)]
    [Display(Name = "完了報告内容")]
    [Sensitive(Mask.Redact)]
    public string? CompletionNote { get; set; }

    // Effectiveness review (post-implementation)
    // 実施後の有効性評価。1〜5の範囲で、評価前はnull
    [Range(1, 5)]
    [Display(Name = "有効性評価(1〜5)")]
    public int? EffectivenessRating { get; set; }

    // 有効性評価のコメント(省略可、最大500文字)
    // ViewModel を経由せず生の文字列を直接受け取る POST アクション(RateMeasure)が
    // IncidentControllerHelpers.ValidateFreeTextLength で同じ500文字上限を手動検証済みのため
    // 実害は無いが、Description/AnalysisNote と同様にエンティティ側にも [MaxLength] を
    // 明示しておく(将来別経路で書き込む実装が追加された際の検証漏れを防ぐ多層防御)。
    // 自由記述のため PHI 混入リスクあり。監査ログでは伏せる
    [MaxLength(500)]
    [Display(Name = "有効性評価コメント")]
    [Sensitive(Mask.Redact)]
    public string? EffectivenessNote { get; set; }

    // 有効性評価を行った日時(省略可)
    [Display(Name = "有効性評価日")]
    public DateTime? EffectivenessReviewedAt { get; set; }

    /// <summary>
    /// 再発確認フラグ: true=対策後も再発あり(追加対策必要), false=再発なし(効果あり)
    /// </summary>
    // 対策後も再発があったかどうか(評価前はnull)
    [Display(Name = "再発を確認したか")]
    public bool? RecurrenceObserved { get; set; }

    // 優先度。1=高 / 2=中 / 3=低 の3段階。初期値は中
    [Range(1, 3)]
    [Display(Name = "優先度")]
    public int Priority { get; set; } = 2; // 1=高, 2=中, 3=低

    /// <summary>
    /// 楽観的同時実行制御トークン(全プロバイダ共通の Guid ベース)。
    /// </summary>
    // 編集衝突を検知するためのトークン。初期値はランダムなGuid
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    // Computed helpers

    // 「期限超過」判定の唯一の定義(真実の源)。クエリ側(HomeController / AnalyticsController)は
    // この式を使い、判定ロジックが各所でコピーされてドリフトするのを防ぐ。
    // EF Core が SQL へ翻訳できるよう DueDate を切り捨てず today 未満で比較する
    // (DueDate の索引が効くサーバ側評価)。today には IClock.Today(JST の深夜0時)を渡す。
    // today が深夜0時である限り「DueDate < today」は「DueDate.Date < today.Date」と等価で、
    // 期限日当日は「期限超過」にならない。
    public static Expression<Func<PreventiveMeasure, bool>> OverdueOn(DateTime today) =>
        // 未完了 かつ 期限が today(深夜0時) より前
        m => m.Status != MeasureStatus.Completed && m.DueDate < today;

    // 上記 OverdueOn のインメモリ版(ビュー等で 1 件ずつ判定する用途)。
    // today が深夜0時である限り OverdueOn と同じ結果になる。.Date 比較にすることで、
    // 万一 today に時刻成分が混じっても当日を「期限超過」にしない頑健性を持たせている。
    // today は IClock 経由で取得した値をコントローラ/ビューから渡す(DateTime.Today を直接使わない)
    public bool IsOverdueOn(DateTime today) =>
        // 完了済みは「期限超過」にならない
        Status != MeasureStatus.Completed &&
        // DueDate の日付部分だけを today と比較(当日は超過とみなさない)
        DueDate.Date < today.Date;

    // ステータスの日本語ラベル(例: 「進行中」)
    public string StatusLabel => EnumLabels.Japanese(Status);

    // ステータスに応じた Bootstrap カラー名(期限超過なら danger に切り替え)
    // today は IClock 経由で取得した値をコントローラ/ビューから渡す
    public string StatusColorOn(DateTime today) => Status switch
    {
        // 計画中: 期限超過なら赤、そうでなければ黄
        MeasureStatus.Planned => IsOverdueOn(today) ? "danger" : "warning",
        // 進行中: 期限超過なら赤、そうでなければ青
        MeasureStatus.InProgress => IsOverdueOn(today) ? "danger" : "primary",
        // 完了は緑
        MeasureStatus.Completed => "success",
        // それ以外はグレー
        _ => "secondary"
    };

    // 対策種別の日本語ラベル(例: 「短期対策」)
    public string MeasureTypeLabel => EnumLabels.Japanese(MeasureType);
    // 対策種別に対応する Bootstrap カラー名
    public string MeasureTypeColor => EnumLabels.MeasureTypeColor(MeasureType);

    // 優先度の日本語1文字ラベル
    public string PriorityLabel => Priority switch
    {
        1 => "高",
        2 => "中",
        3 => "低",
        _ => "-"
    };

    // 優先度に対応する Bootstrap カラー名(高=赤/中=黄/低=グレー)
    public string PriorityColor => Priority switch
    {
        1 => "danger",
        2 => "warning",
        3 => "secondary",
        _ => "secondary"
    };

    // 有効性評価を ★★★☆☆ のような星記号で返す(未評価なら「未評価」)
    public string EffectivenessStars => EffectivenessRating.HasValue
        ? new string('★', EffectivenessRating.Value) + new string('☆', 5 - EffectivenessRating.Value)
        : "未評価";
}
