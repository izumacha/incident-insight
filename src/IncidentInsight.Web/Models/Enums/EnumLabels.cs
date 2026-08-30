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

    // 「期限超過」バケットの日本語ラベル。MeasureStatus enum には存在しない派生状態
    // (未完了 かつ 期限日が今日より前 = PreventiveMeasure.OverdueOn の条件)なので
    // StatusJa には入れられないが、分析画面のドーナツグラフでは他の 3 ステータスと
    // 同列のバケットとして表示される。AnalyticsController(集計側)と
    // Views/Analytics/Index.cshtml(サマリー欄がこのラベルでバケットを引き当てる側)の
    // 2 箇所が同じ文字列を必要とするため、他の enum ラベルと同じくここを唯一の源にする(§6)
    public const string MeasureOverdueLabel = "期限超過";

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

    /// <summary>
    /// 監査ログのエンティティ名ラベルが定義済みのキー一覧。
    ///
    /// 網羅性の検査(<c>AuditEntityLabelCoverageTests</c>)が使う。変換結果と入力の一致で
    /// 判定すると、ラベルを意図的に型名と同じにしたときに「未定義」と区別できず、
    /// 実在するのに直しようのない失敗になるため、キーそのものを公開する。
    /// </summary>
    public static IReadOnlyCollection<string> AuditEntityLabelKeys => AuditEntityJa.Keys;

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
        ["dark"] = "#212529",
        // Bootstrap 5.3 の拡張パレット($orange)。テーマ色ではないためバッジのクラス名としては
        // 使えないが、有効性評価グラフ(EffectivenessScale.ColorName)が「赤→黄」の中間色として
        // 参照する。16進値をグラフ側に直書きさせないため、他の色と同じくここを源にする(§6)
        ["orange"] = "#fd7e14"
    };

    // Bootstrap 5.3 が .bg-* / .text-bg-* クラスを用意しているテーマ色の許可リスト。
    //
    // 上の BootstrapHexMap は「Chart.js で使う色の 16 進」を引くための表で、テーマ色ではない
    // 拡張パレット(orange 等)も載せる前提になっている。そのため「変換表にあるか」で
    // バッジ可否を判定すると、グラフ用の色を 1 つ足すたびにバッジ用途でも黙って通ってしまい
    // (fail-open)、.bg-teal のような存在しないクラスで背景色の付かないバッジが描画される。
    // 逆に light は .bg-light が実在するのに変換表には無い(グラフで使わないため)。
    // 取り違えを防ぐため、判定は許可リスト方式にして「知らない色名は拒否」に倒す
    // (CLAUDE.md §9 fail-closed)。
    //
    // 収録するのは「.bg-* クラスが実在し、かつ BootstrapHexMap にも 16 進を持つ」色に限る。
    // 片方にしか無い色を許すと、バッジは正しく塗られるのに同じ色名を Chart.js へ回したときだけ
    // Hex() のフォールバックで別の色(グレー)になる、という画面間のズレが生まれる
    // (.bg-light は実在するが、グラフで使わないため変換表に無い。だからここにも入れない)。
    // バッジで使える色を増やすときは、BootstrapHexMap と両方へ追加すること
    private static readonly HashSet<string> BadgeUsableColorNames = new(StringComparer.Ordinal)
    {
        "primary",
        "secondary",
        "success",
        "danger",
        "warning",
        "info",
        "dark"
    };

    /// <summary>
    /// 指定の Bootstrap カラー名が、バッジの <c>bg-*</c> クラスとして使えるかを返す。
    /// 許可リストに無い色名(綴り間違い・テーマ色ではない拡張パレットの色)はすべて false。
    /// </summary>
    // 許可リストに載っている色名だけを使用可とする(未知は拒否)
    public static bool IsBadgeUsable(string bootstrapColorName) =>
        BadgeUsableColorNames.Contains(bootstrapColorName);

    /// <summary>
    /// バッジで使える色名の一覧(テスト専用)。「許可リストの色は BootstrapHexMap にも
    /// 16 進を持つ」という上の不変条件を、テストが機械的に検査できるようにするために公開する。
    /// コメントで宣言しただけでは、許可リストにだけ色を足して変換表を直し忘れても
    /// 全テストが緑のまま通ってしまう。
    /// </summary>
    // 中身を書き換えられないよう読み取り専用の列挙として返す
    public static IEnumerable<string> BadgeUsableColorNamesForTesting => BadgeUsableColorNames;

    // 重症度を日本語ラベルに変換(辞書にない場合は enum 名をそのまま返す)
    public static string Japanese(IncidentSeverity v) =>
        SeverityJa.TryGetValue(v, out var s) ? s : v.ToString();

    // Bootstrap カラー名を16進カラーコードに変換。
    // 見つからなければグレー(secondary)へフォールバックする。フォールバック値も
    // 変換表から引くことで、secondary の色を変えたときにここだけ古い色が残るのを防ぐ(§6)
    public static string Hex(string bootstrapColorName) =>
        BootstrapHexMap.TryGetValue(bootstrapColorName, out var hex) ? hex : BootstrapHexMap["secondary"];

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
