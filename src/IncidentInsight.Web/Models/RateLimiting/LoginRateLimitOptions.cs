// この型の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.RateLimiting;

/// <summary>
/// ログイン試行のレート制限(回数制限)設定。RateLimit:Login セクション
/// (appsettings.json / 環境変数 RateLimit__Login__*)から束縛され、
/// Program.cs のレートリミッタ登録で使う。
///
/// Identity のアカウント単位ロックアウト(5 回失敗)だけでは、
/// (a) 多数アカウントに少しずつ試すパスワードスプレー攻撃、
/// (b) 既知メールアドレスへ故意に失敗を繰り返すロックアウト DoS
/// を止められないため、送信元 IP 単位の制限を多層防御として重ねる(CLAUDE.md §9)。
/// </summary>
public class LoginRateLimitOptions
{
    // 設定セクション名(Program.cs から bind するときに使う)
    public const string SectionName = "RateLimit:Login";

    // レート制限ポリシー名。Program.cs の AddRateLimiter(登録側)と
    // AccountController の [EnableRateLimiting](適用側)の両方が参照する
    // 唯一の定数(§6 マジック文字列の一元管理)。
    public const string PolicyName = "LoginRateLimit";

    // 既定値: 1 ウィンドウ(時間枠)あたりに同一 IP から許可するログイン試行回数
    public const int DefaultPermitLimit = 10;

    // 既定値: 固定ウィンドウ(時間枠)の長さ(秒)
    public const int DefaultWindowSeconds = 60;

    // クライアント IP が特定できない場合に使う共有パーティションキー。
    // IP 不明のリクエストを素通しにせず、全員で 1 つの制限枠を共有させる(fail-closed)。
    public const string UnknownClientPartitionKey = "unknown-client";

    // 1 ウィンドウ内に同一 IP から許可するログイン試行回数(0 以下は既定値へフォールバック)
    public int PermitLimit { get; set; } = DefaultPermitLimit;

    // 固定ウィンドウの長さ(秒)(0 以下は既定値へフォールバック)
    public int WindowSeconds { get; set; } = DefaultWindowSeconds;
}
