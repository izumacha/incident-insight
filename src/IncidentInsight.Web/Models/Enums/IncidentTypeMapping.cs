// この enum 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// <see cref="IncidentTypeKind"/> と DB/UI で使用する日本語文字列の
/// 双方向マッピング。既存 DB の日本語値 (例: "転倒・転落") を壊さないため、
/// enum 名と DB 値は分離している。
/// 追加 / 改称時はここの両辞書を必ず同時に更新すること。
/// </summary>
public static class IncidentTypeMapping
{
    // enum 値 → DB/UI に使う日本語文字列 への変換表
    private static readonly Dictionary<IncidentTypeKind, string> ToDb = new()
    {
        [IncidentTypeKind.Fall] = "転倒・転落",
        [IncidentTypeKind.Medication] = "投薬ミス",
        [IncidentTypeKind.Exam] = "検査ミス",
        [IncidentTypeKind.SurgeryOrProcedure] = "手術・処置関連",
        [IncidentTypeKind.MedicalDevice] = "医療機器関連",
        [IncidentTypeKind.TubeOrLine] = "チューブ・ライン関連",
        [IncidentTypeKind.InfectionControl] = "感染予防",
        [IncidentTypeKind.PatientIdentification] = "患者確認ミス",
        [IncidentTypeKind.Communication] = "コミュニケーション",
        [IncidentTypeKind.Other] = "その他"
    };

    // 日本語文字列 → enum 値 への逆引き表(上の ToDb を自動で反転して作成)
    private static readonly Dictionary<string, IncidentTypeKind> FromDb =
        ToDb.ToDictionary(kv => kv.Value, kv => kv.Key);

    // enum → DB 保存用文字列 に変換(対応がなければ enum 名をそのまま返す)
    public static string ToDbString(IncidentTypeKind kind) =>
        ToDb.TryGetValue(kind, out var s) ? s : kind.ToString();

    // DB 文字列 → enum に変換(対応がなければ Other にフォールバック)
    public static IncidentTypeKind FromDbString(string value) =>
        FromDb.TryGetValue(value, out var k) ? k : IncidentTypeKind.Other;

    // 画面表示用のラベル取得(現状は DB 文字列と同じ値を使う)
    public static string JapaneseLabel(IncidentTypeKind kind) => ToDbString(kind);

    // 辞書定義順で全ての種別を列挙(ドロップダウンの並び順にそのまま使える)
    public static IEnumerable<IncidentTypeKind> AllInDisplayOrder => ToDb.Keys;
}
