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

    // [Sensitive(Mask.Hash)] の擬似匿名化に使う秘密鍵(salt)。
    // この値は HMAC-SHA256 の鍵として使われ、これを知らない限り氏名等のハッシュは
    // 逆算できない。Development では空でも動くが、本番では空だと擬似匿名化が破れるため
    // Program.cs が起動時に空をチェックして fail-fast する(issue #61)。
    public string HashSalt { get; set; } = "";
}
