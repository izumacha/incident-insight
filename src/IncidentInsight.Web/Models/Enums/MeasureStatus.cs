// この enum の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策のライフサイクル。enum 名を DB の TEXT カラムに保存する。
/// </summary>
public enum MeasureStatus
{
    // 計画中(まだ着手していない)
    Planned = 0,
    // 進行中(実施中)
    InProgress = 1,
    // 完了(対策を終えた)
    Completed = 2
}
