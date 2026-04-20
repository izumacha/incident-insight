// この enum の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 医療インシデント重症度 (国内標準レベル0〜5)。
/// enum 名を永続化キーとして DB の TEXT カラムに文字列で保存する。
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
