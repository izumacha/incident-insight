// このファイルで使う型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

// エラー画面に表示する情報をまとめる入れ物クラス
public class ErrorViewModel
{
    // リクエストを特定するためのID(nullのこともあるので ? を付けている)
    public string? RequestId { get; set; }

    // RequestId が空でない場合のみ true を返す(画面に出すかどうかの判断に使う)
    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
}
