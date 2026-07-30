// この enum の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 医療インシデント重症度 (国内標準レベル0〜5)。
/// enum 名を永続化キーとして DB の TEXT カラムに文字列で保存する。
///
/// 【注意】DB には HasConversion&lt;string&gt;() で enum 名の文字列が保存されるため、
/// SQL 側の ORDER BY(IncidentsController.Index の sortBy=severity 等)は
/// 辞書順(アルファベット順)の並びになる。現状は "Level0" &lt; "Level1" &lt; ... &lt; "Level5"
/// と辞書順が重症度順にたまたま一致しているだけなので、新しい重症度コードを追加する
/// ときは必ず「辞書順 = 重症度順」を保つ名前にすること(例: "Critical" のような名前は
/// 並びを壊す)。保てない名前が必要になった場合は、文字列ソートをやめて
/// 数値カラム化やマッピングテーブル等でソート方法自体を作り直すこと。
/// </summary>
public enum IncidentSeverity
{
    // レベル0: 患者に実害なし(ヒヤリハット)
    Level0 = 0,
    // レベル1: 患者への影響なし
    Level1 = 1,
    // レベル2: 観察強化が必要
    Level2 = 2,
    // レベル3a: 軽微な処置が必要
    Level3a = 3,
    // レベル3b: 濃厚な処置が必要
    Level3b = 4,
    // レベル4: 永続的な障害が残った
    Level4 = 5,
    // レベル5: 死亡
    Level5 = 6
}
