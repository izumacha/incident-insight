namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 医療インシデント重症度 (国内標準レベル0〜5)。
/// enum 名を永続化キーとして DB の TEXT カラムに文字列で保存する。
/// </summary>
public enum IncidentSeverity
{
    Level0 = 0,
    Level1 = 1,
    Level2 = 2,
    Level3a = 3,
    Level3b = 4,
    Level4 = 5,
    Level5 = 6
}
