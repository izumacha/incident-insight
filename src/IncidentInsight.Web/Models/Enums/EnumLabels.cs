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

    // 監査ログのエンティティ名(string) → 日本語ラベルへの変換表
    // (AuditLog.EntityName は EF 由来の文字列なので enum ではなく string をキーにする)
    private static readonly Dictionary<string, string> AuditEntityJa = new()
    {
        // インシデント本体
        ["Incident"] = "インシデント",
        // なぜなぜ分析(原因分析)
        ["CauseAnalysis"] = "原因分析",
        // 再発防止策
        ["PreventiveMeasure"] = "再発防止策"
    };

    // 監査ログの操作種別(string) → 日本語ラベルへの変換表
    private static readonly Dictionary<string, string> AuditOperationJa = new()
    {
        // レコード追加
        ["Added"] = "追加",
        // レコード更新
        ["Modified"] = "更新",
        // レコード削除
        ["Deleted"] = "削除"
    };

    // 監査ログの操作種別 → Bootstrap カラー名への変換表(バッジ色分け用)
    private static readonly Dictionary<string, string> AuditOperationColorMap = new()
    {
        // 追加は緑(中立的に新規追加を示す)
        ["Added"] = "success",
        // 更新は青(注意喚起だが警告レベルではない)
        ["Modified"] = "primary",
        // 削除は赤(取り消しできない操作なので強調)
        ["Deleted"] = "danger"
    };

    // Bootstrap カラー名 → 16進カラーコードの変換表。
    // Chart.js のように CSS クラス(badge bg-warning 等)を使えない描画で、
    // バッジと同じ配色を再現するために使う(Bootstrap 5.3 の既定テーマ色)。
    private static readonly Dictionary<string, string> BootstrapHexMap = new()
    {
        ["primary"] = "#0d6efd",
        ["secondary"] = "#6c757d",
        ["success"] = "#198754",
        ["danger"] = "#dc3545",
        ["warning"] = "#ffc107",
        ["info"] = "#0dcaf0",
        ["dark"] = "#212529"
    };

    // 重症度を日本語ラベルに変換(辞書にない場合は enum 名をそのまま返す)
    public static string Japanese(IncidentSeverity v) =>
        SeverityJa.TryGetValue(v, out var s) ? s : v.ToString();

    // Bootstrap カラー名を16進カラーコードに変換(見つからなければグレー)
    public static string Hex(string bootstrapColorName) =>
        BootstrapHexMap.TryGetValue(bootstrapColorName, out var hex) ? hex : "#6c757d";

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

    // 監査ログのエンティティ名を日本語ラベルに変換(辞書にない場合は元の名前をそのまま返す)
    public static string JapaneseAuditEntity(string name) =>
        AuditEntityJa.TryGetValue(name, out var s) ? s : name;

    // 監査ログの操作種別を日本語ラベルに変換(辞書にない場合は元の値をそのまま返す)
    public static string JapaneseAuditOperation(string op) =>
        AuditOperationJa.TryGetValue(op, out var s) ? s : op;

    // 監査ログの操作種別に対応する Bootstrap カラー名を返す(見つからなければグレー)
    public static string AuditOperationColor(string op) =>
        AuditOperationColorMap.TryGetValue(op, out var c) ? c : "secondary";

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
