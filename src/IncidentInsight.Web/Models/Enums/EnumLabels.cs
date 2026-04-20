// この enum 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// enum → 日本語ラベル / Bootstrap カラー名の一元解決。
/// Views / Controllers / Analytics API がすべてここを経由する。
/// </summary>
public static class EnumLabels
{
    // 重症度 → 日本語ラベルへの変換表
    private static readonly Dictionary<IncidentSeverity, string> SeverityJa = new()
    {
        [IncidentSeverity.Level0] = "レベル0 (ヒヤリハット)",
        [IncidentSeverity.Level1] = "レベル1 (患者への影響なし)",
        [IncidentSeverity.Level2] = "レベル2 (観察強化)",
        [IncidentSeverity.Level3a] = "レベル3a (軽微な処置)",
        [IncidentSeverity.Level3b] = "レベル3b (濃厚な処置)",
        [IncidentSeverity.Level4] = "レベル4 (永続的障害)",
        [IncidentSeverity.Level5] = "レベル5 (死亡)"
    };

    // 重症度 → Bootstrap カラー名への変換表(バッジ色分け用)
    private static readonly Dictionary<IncidentSeverity, string> SeverityColor = new()
    {
        [IncidentSeverity.Level0] = "secondary",
        [IncidentSeverity.Level1] = "info",
        [IncidentSeverity.Level2] = "primary",
        [IncidentSeverity.Level3a] = "warning",
        [IncidentSeverity.Level3b] = "warning",
        [IncidentSeverity.Level4] = "danger",
        [IncidentSeverity.Level5] = "dark"
    };

    // 対策ステータス → 日本語ラベルへの変換表
    private static readonly Dictionary<MeasureStatus, string> StatusJa = new()
    {
        [MeasureStatus.Planned] = "計画中",
        [MeasureStatus.InProgress] = "進行中",
        [MeasureStatus.Completed] = "完了"
    };

    // 対策種別 → 日本語ラベルへの変換表
    private static readonly Dictionary<MeasureTypeKind, string> MeasureTypeJa = new()
    {
        [MeasureTypeKind.ShortTerm] = "短期対策",
        [MeasureTypeKind.LongTerm] = "長期対策"
    };

    // 重症度を日本語ラベルに変換(辞書にない場合は enum 名をそのまま返す)
    public static string Japanese(IncidentSeverity v) =>
        SeverityJa.TryGetValue(v, out var s) ? s : v.ToString();

    // 重症度を Bootstrap カラー名に変換(見つからなければグレー)
    public static string Color(IncidentSeverity v) =>
        SeverityColor.TryGetValue(v, out var c) ? c : "secondary";

    // 対策ステータスを日本語ラベルに変換
    public static string Japanese(MeasureStatus v) =>
        StatusJa.TryGetValue(v, out var s) ? s : v.ToString();

    // 対策種別を日本語ラベルに変換
    public static string Japanese(MeasureTypeKind v) =>
        MeasureTypeJa.TryGetValue(v, out var s) ? s : v.ToString();

    // 対策種別に対応する Bootstrap カラー名を返す(長期は青、短期は緑)
    public static string MeasureTypeColor(MeasureTypeKind v) =>
        v == MeasureTypeKind.LongTerm ? "info" : "success";

    // 重症度 enum の全ての値を列挙して返す(ドロップダウン選択肢の生成などに使う)
    public static IEnumerable<IncidentSeverity> AllSeverities =>
        Enum.GetValues<IncidentSeverity>();

    // 対策ステータス enum の全ての値を列挙して返す
    public static IEnumerable<MeasureStatus> AllStatuses =>
        Enum.GetValues<MeasureStatus>();

    // 対策種別 enum の全ての値を列挙して返す
    public static IEnumerable<MeasureTypeKind> AllMeasureTypes =>
        Enum.GetValues<MeasureTypeKind>();
}
