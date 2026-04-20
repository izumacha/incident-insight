// この enum の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// インシデント種別。enum 名と DB 永続化文字列(日本語)は
/// <see cref="IncidentTypeMapping"/> で双方向マッピングする。
/// </summary>
public enum IncidentTypeKind
{
    // 転倒・転落
    Fall = 1,
    // 投薬ミス
    Medication = 2,
    // 検査ミス
    Exam = 3,
    // 手術・処置関連
    SurgeryOrProcedure = 4,
    // 医療機器関連
    MedicalDevice = 5,
    // チューブ・ライン関連
    TubeOrLine = 6,
    // 感染予防
    InfectionControl = 7,
    // 患者確認ミス
    PatientIdentification = 8,
    // コミュニケーション由来
    Communication = 9,
    // その他(どれにも当てはまらないもの)
    Other = 99
}
