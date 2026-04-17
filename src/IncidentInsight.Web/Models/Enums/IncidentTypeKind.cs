namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// インシデント種別。enum 名と DB 永続化文字列(日本語)は
/// <see cref="IncidentTypeMapping"/> で双方向マッピングする。
/// </summary>
public enum IncidentTypeKind
{
    Fall = 1,
    Medication = 2,
    Exam = 3,
    SurgeryOrProcedure = 4,
    MedicalDevice = 5,
    TubeOrLine = 6,
    InfectionControl = 7,
    PatientIdentification = 8,
    Communication = 9,
    Other = 99
}
