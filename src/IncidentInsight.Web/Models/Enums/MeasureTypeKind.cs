namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策の種別。enum 名を DB の TEXT カラムに保存する。
/// </summary>
public enum MeasureTypeKind
{
    ShortTerm = 0,
    LongTerm = 1
}
