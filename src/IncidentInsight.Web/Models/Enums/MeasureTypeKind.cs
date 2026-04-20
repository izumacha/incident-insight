// この enum の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策の種別。enum 名を DB の TEXT カラムに保存する。
/// </summary>
public enum MeasureTypeKind
{
    // 短期対策(すぐに実施できるもの)
    ShortTerm = 0,
    // 長期対策(仕組み変更など時間がかかるもの)
    LongTerm = 1
}
