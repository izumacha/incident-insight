namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策のライフサイクル。enum 名を DB の TEXT カラムに保存する。
/// </summary>
public enum MeasureStatus
{
    Planned = 0,
    InProgress = 1,
    Completed = 2
}
