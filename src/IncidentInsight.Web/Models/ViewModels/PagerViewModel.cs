// ViewModel 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// 一覧画面共通のページネーション部品(Views/Shared/_Pager.cshtml)用モデル。
// Incidents 一覧と AuditLogs 一覧が同じ「±窓 + 先頭/末尾ジャンプ」方式のページャを
// それぞれ複製していたため、窓幅の定数とリンク生成ロジックをここへ一元化する(§6 DRY)。
public class PagerViewModel
{
    // 現在ページの前後に表示するページ番号の数(±5)。全ページ分のリンクを並べると
    // データが蓄積した環境で数百件のリンクが描画されてしまうため窓で制限する
    public const int WindowRadius = 5;

    // 現在表示中のページ番号(1始まり)
    public int Page { get; set; } = 1;
    // 総ページ数
    public int TotalPages { get; set; }
    // リンク先のアクション名(既定は一覧画面の Index。コントローラは描画元ビューに従う)
    public string Action { get; set; } = "Index";
    // ページ番号以外に URL へ引き継ぐ絞り込み条件(値が null の条件は URL から省く)
    public Dictionary<string, string?> RouteValues { get; set; } = new();

    // 窓の先頭ページ番号(1 未満にならないようにクランプ)
    public int First => Math.Max(1, Page - WindowRadius);
    // 窓の末尾ページ番号(総ページ数を超えないようにクランプ)
    public int Last => Math.Min(TotalPages, Page + WindowRadius);

    // 指定ページ番号向けのルート値(絞り込み条件 + page)を組み立てる。
    // asp-all-route-data は非 null の辞書しか受け取れないため、未指定(null)の条件は
    // ここで除外する(従来の asp-route-* が null を URL に出さないのと同じ挙動)
    public Dictionary<string, string> RouteValuesFor(int page)
    {
        // null 値を除いた絞り込み条件だけを新しい辞書へ写す
        var values = RouteValues
            .Where(kv => kv.Value != null)          // 値が入っている条件だけ残す
            .ToDictionary(kv => kv.Key, kv => kv.Value!); // 非 null 辞書へ変換する
        // 遷移先のページ番号を追加する
        values["page"] = page.ToString();
        // 完成したルート値を返す
        return values;
    }
}
