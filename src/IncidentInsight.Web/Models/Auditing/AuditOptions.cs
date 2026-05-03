// この型の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Auditing;

/// <summary>
/// 監査ログ用の設定値。Audit セクション(appsettings.json / 環境変数 / User Secrets)
/// から束縛され、AuditSaveChangesInterceptor に DI される。
///
/// HashSalt は コミットしない値。User Secrets か環境変数 Audit__HashSalt で渡す。
/// 回転すると過去の Hash と突合不可になる点に注意。
/// </summary>
public class AuditOptions
{
    // 設定セクション名(Program.cs から bind するときに使う)
    public const string SectionName = "Audit";

    // [Sensitive(Mask.Hash)] のハッシュ計算に使う salt。空文字は許容するが
    // 本番環境では必ず設定する(空のままだと弱い決定的ハッシュになる)。
    public string HashSalt { get; set; } = "";
}
