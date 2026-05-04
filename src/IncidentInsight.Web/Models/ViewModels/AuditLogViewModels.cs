// ドロップダウン用の SelectListItem を使えるようにする
using Microsoft.AspNetCore.Mvc.Rendering;

// ViewModel 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// 監査ログ一覧画面のモデル。絞り込み条件 / 検索結果 / ページ情報を保持する
public class AuditLogListViewModel
{
    // 表示対象の監査ログ行リスト
    public List<AuditLog> Logs { get; set; } = new();
    // 絞り込み後の総件数(ページングの計算に使う)
    public int TotalCount { get; set; }
    // 現在表示中のページ番号(1始まり)
    public int Page { get; set; } = 1;
    // 1ページに表示する件数
    public int PageSize { get; set; } = 50;
    // 総ページ数(総件数÷ページサイズを切り上げ)
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);

    // Filter state
    // エンティティ名フィルタ(Incident / CauseAnalysis / PreventiveMeasure)
    public string? EntityName { get; set; }
    // 操作種別フィルタ(Added / Modified / Deleted)
    public string? Operation { get; set; }
    // 変更者フィルタ(部分一致)
    public string? ChangedBy { get; set; }
    // 対象キー(エンティティの ID)で絞り込み
    public string? EntityKey { get; set; }
    // 変更日時 開始
    public DateTime? DateFrom { get; set; }
    // 変更日時 終了
    public DateTime? DateTo { get; set; }

    // エンティティ名ドロップダウンの選択肢
    public List<SelectListItem> EntityNameOptions { get; set; } = new();
    // 操作種別ドロップダウンの選択肢
    public List<SelectListItem> OperationOptions { get; set; } = new();
}

// 監査ログ詳細画面のモデル
public class AuditLogDetailViewModel
{
    // 表示対象の監査ログ本体
    public AuditLog Log { get; set; } = null!;

    // ChangesJson を 1 プロパティ単位にパースした結果(name -> (old, new))。
    // パースに失敗した場合は null。View ではフォールバックとして生 JSON を表示する。
    public List<AuditLogChangeRow>? Changes { get; set; }
}

// 監査ログの 1 プロパティの変更前後を保持する行モデル(ビュー描画用)
public class AuditLogChangeRow
{
    // 変更されたプロパティ名
    public string PropertyName { get; set; } = "";
    // 変更前の値の文字列表現(null は "(なし)" 相当として View で表示)
    public string? OldValue { get; set; }
    // 変更後の値の文字列表現
    public string? NewValue { get; set; }
}
