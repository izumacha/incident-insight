namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// enum → 日本語ラベル / Bootstrap カラー名の一元解決。
/// Views / Controllers / Analytics API がすべてここを経由する。
/// </summary>
public static class EnumLabels
{
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

    private static readonly Dictionary<MeasureStatus, string> StatusJa = new()
    {
        [MeasureStatus.Planned] = "計画中",
        [MeasureStatus.InProgress] = "進行中",
        [MeasureStatus.Completed] = "完了"
    };

    private static readonly Dictionary<MeasureTypeKind, string> MeasureTypeJa = new()
    {
        [MeasureTypeKind.ShortTerm] = "短期対策",
        [MeasureTypeKind.LongTerm] = "長期対策"
    };

    public static string Japanese(IncidentSeverity v) =>
        SeverityJa.TryGetValue(v, out var s) ? s : v.ToString();

    public static string Color(IncidentSeverity v) =>
        SeverityColor.TryGetValue(v, out var c) ? c : "secondary";

    public static string Japanese(MeasureStatus v) =>
        StatusJa.TryGetValue(v, out var s) ? s : v.ToString();

    public static string Japanese(MeasureTypeKind v) =>
        MeasureTypeJa.TryGetValue(v, out var s) ? s : v.ToString();

    public static string MeasureTypeColor(MeasureTypeKind v) =>
        v == MeasureTypeKind.LongTerm ? "info" : "success";

    public static IEnumerable<IncidentSeverity> AllSeverities =>
        Enum.GetValues<IncidentSeverity>();

    public static IEnumerable<MeasureStatus> AllStatuses =>
        Enum.GetValues<MeasureStatus>();

    public static IEnumerable<MeasureTypeKind> AllMeasureTypes =>
        Enum.GetValues<MeasureTypeKind>();
}
