// この型の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Auditing;

/// <summary>
/// 監査ログ(AuditLog.ChangesJson)へ書き込む際に値をどう変換するかを示す。
/// 医療系で個人情報(PHI)が監査ログ平文に残るのを防ぐためのマスキング指定。
/// </summary>
public enum Mask
{
    // 値を完全に伏せる(JSON 上は "[REDACTED]" になる)
    Redact,
    // 値を鍵付き HMAC-SHA256 擬似匿名化の先頭 32 桁(128bit)に置換し "#xxxx" の形で残す。
    // 鍵は設定 Audit:HashSalt から取得する(AuditSaveChangesInterceptor.ComputePseudonym)。
    // 同値性の確認だけ可能で、鍵が無ければ元値を復元できない(旧 Salt 付き SHA-256 8 桁は
    // 反転・衝突が容易だったため廃止した。詳細は issue #61/#62)。
    Hash,
    // 値そのものは出さず、文字数だけ "[len=42]" のように残す
    LengthOnly
}

/// <summary>
/// プロパティに付けると、AuditSaveChangesInterceptor が ChangesJson に
/// 書き込む際にマスキングを適用する。Property 用のみで、Class には付けない。
///
/// 例: [Sensitive(Mask.Redact)] public string Description { get; set; } = "";
/// </summary>
// Property にだけ付けられる。重複指定は禁止
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class SensitiveAttribute : Attribute
{
    // どの方式でマスクするかを保持する
    public Mask Mask { get; }

    // 引数なしの既定値は Redact(最も安全側に倒す)
    public SensitiveAttribute(Mask mask = Mask.Redact)
    {
        // フィールドに保存
        this.Mask = mask;
    }
}
