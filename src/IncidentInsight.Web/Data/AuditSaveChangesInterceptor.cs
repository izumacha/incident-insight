// リフレクション(プロパティ属性の取得)を使う
using System.Reflection;
// SHA-256 ハッシュを計算するため
using System.Security.Cryptography;
// 文字列を UTF-8 バイト列にするため
using System.Text;
// JSON シリアライズを使う
using System.Text.Json;
// enum を文字列で JSON 化するコンバータ
using System.Text.Json.Serialization;
// 自プロジェクトのモデル(AuditLog / Incident など)を使う
using IncidentInsight.Web.Models;
// PHI マスキング属性 / 設定(Sensitive / Mask / AuditOptions)を使う
using IncidentInsight.Web.Models.Auditing;
// 時刻源サービスを使う
using IncidentInsight.Web.Services;
// HttpContext アクセサ(現在のユーザー取得用)
using Microsoft.AspNetCore.Http;
// EF Core 本体
using Microsoft.EntityFrameworkCore;
// 変更追跡 API(EntityEntry など)
using Microsoft.EntityFrameworkCore.ChangeTracking;
// インターセプタ関連の型
using Microsoft.EntityFrameworkCore.Diagnostics;
// IOptions(設定オブジェクトの DI)を使う
using Microsoft.Extensions.Options;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Data;

/// <summary>
/// Incident / CauseAnalysis / PreventiveMeasure の変更を AuditLog テーブルに記録する
/// EF Core インターセプタ。プロバイダ(SQLite / SQL Server / PostgreSQL)非依存で動作する。
///
/// 2 フェーズで動作する:
///   1. SavingChanges: 対象エントリをスナップショット化し、Modified エントリの
///      ConcurrencyToken を新しい Guid に更新する。
///   2. SavedChanges: DB 採番後の ID を取得して AuditLog テーブルへ記録する
///      (Added エントリは SavingChanges 時点で Id が未採番のため 2 フェーズ必要)。
/// </summary>
public class AuditSaveChangesInterceptor : SaveChangesInterceptor
{
    // 監査対象となるエンティティ名の集合
    private static readonly HashSet<string> AuditedEntities = new()
    {
        nameof(Incident),
        nameof(CauseAnalysis),
        nameof(PreventiveMeasure)
    };

    // 現在のユーザー名取得に使う HttpContext アクセサ(null 可)
    private readonly IHttpContextAccessor? _httpContextAccessor;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;
    // 監査ログ用設定(Hash の salt など)。null の場合は既定値で動かす
    private readonly AuditOptions _auditOptions;

    // DbContext インスタンスごとの保留監査エントリ。Scoped に一致するため競合しない。
    private readonly Dictionary<DbContext, List<PendingAudit>> _pending = new();

    // [Sensitive] 属性の検索結果をキャッシュ(プロパティ毎にリフレクションを毎回走らせないため)
    // キーは (CLR Type, プロパティ名)。null は属性なしを表す。
    private static readonly Dictionary<(Type, string), Mask?> _sensitiveCache = new();
    // キャッシュアクセスのロック(複数 SaveChanges が並行してもよいように)
    private static readonly object _cacheLock = new();

    // コンストラクタ: DI で IClock / HttpContextAccessor / AuditOptions を受け取る。
    // AuditOptions は省略可能(テストでは渡さなくても動く)
    public AuditSaveChangesInterceptor(
        IClock clock,
        IHttpContextAccessor? httpContextAccessor = null,
        IOptions<AuditOptions>? auditOptions = null)
    {
        _httpContextAccessor = httpContextAccessor;
        _clock = clock;
        // null の場合は規定値の AuditOptions を使う(salt が空のテスト用)
        _auditOptions = auditOptions?.Value ?? new AuditOptions();
    }

    // 同期版 SaveChanges の直前フック: スナップショットとトークン更新を行う
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        // DbContext があれば対象エントリをキャプチャしてトークンも更新
        if (eventData.Context is not null) CaptureAndBumpTokens(eventData.Context);
        // 基底処理へ委譲
        return base.SavingChanges(eventData, result);
    }

    // 非同期版 SaveChanges の直前フック
    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        // DbContext があれば対象エントリをキャプチャしてトークンも更新
        if (eventData.Context is not null) CaptureAndBumpTokens(eventData.Context);
        // 基底処理へ委譲
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    // 同期版 SaveChanges の直後フック: 監査ログを書き込む
    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        // DbContext があれば監査ログをフラッシュ(DB 書き込み)
        if (eventData.Context is not null) FlushAuditLogs(eventData.Context);
        // 基底処理へ委譲
        return base.SavedChanges(eventData, result);
    }

    // 非同期版 SaveChanges の直後フック
    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default)
    {
        // DbContext があれば監査ログを非同期で書き込む
        if (eventData.Context is not null) await FlushAuditLogsAsync(eventData.Context, cancellationToken);
        // 基底処理へ委譲
        return await base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    // 同期版: SaveChanges が失敗したときのフック
    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        // 失敗した場合は保留エントリを破棄(ゴミを残さない)
        if (eventData.Context is not null) _pending.Remove(eventData.Context);
        // 基底処理へ委譲
        base.SaveChangesFailed(eventData);
    }

    // 非同期版: SaveChanges が失敗したときのフック
    public override Task SaveChangesFailedAsync(
        DbContextErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        // 失敗時も保留エントリをクリア
        if (eventData.Context is not null) _pending.Remove(eventData.Context);
        // 基底処理へ委譲
        return base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    // 変更追跡から監査対象エントリを取り出し、ConcurrencyToken を更新してスナップショットを取る
    private void CaptureAndBumpTokens(DbContext context)
    {
        // 現在のログインユーザー名(不明なら "system")
        var user = _httpContextAccessor?.HttpContext?.User?.Identity?.Name ?? "system";
        // ビジネスタイムスタンプと揃えるため、監査ログも運用タイムゾーン(JST)で記録する
        // (Issue #31)。時刻源は IClock に集約され、将来 UTC に寄せる場合はここではなく
        // IClock 実装を差し替える。
        // 監査ログに記録する時刻(JST ベース)
        var now = _clock.Now;

        // この SaveChanges 呼び出しで書き込むべき監査エントリを溜めるリスト
        var captured = new List<PendingAudit>();

        // 変更追跡中のエントリから監査対象(Added/Modified/Deleted)だけ取り出す
        var entries = context.ChangeTracker.Entries()
            .Where(e => AuditedEntities.Contains(e.Entity.GetType().Name)
                        && (e.State == EntityState.Added
                            || e.State == EntityState.Modified
                            || e.State == EntityState.Deleted))
            .ToList();

        // 対象エントリを1件ずつ処理
        foreach (var entry in entries)
        {
            // Modified の場合のみ ConcurrencyToken を更新
            // 同時編集検知トークンを新しい Guid に差し替え(次回編集で衝突を検知するため)
            if (entry.State == EntityState.Modified)
            {
                // ConcurrencyToken プロパティを探す
                var tokenProp = entry.Properties.FirstOrDefault(p => p.Metadata.Name == "ConcurrencyToken");
                // あれば新しい Guid を割り当てる
                if (tokenProp is not null)
                {
                    tokenProp.CurrentValue = Guid.NewGuid();
                }
            }

            // この変更のスナップショットを作成して保留リストへ追加
            captured.Add(new PendingAudit(
                Entry: entry,
                State: entry.State,
                EntityName: entry.Entity.GetType().Name,
                // Modified/Deleted の ID は確定済み、Added は 0 (SavedChanges で再読込)
                PrekeyIfKnown: entry.State == EntityState.Added ? null : GetPrimaryKey(entry),
                ChangedAt: now,
                ChangedBy: user,
                ChangesJson: SerializeChanges(entry)));
        }

        // この DbContext の保留エントリとして保存
        _pending[context] = captured;
    }

    // 同期版: 保留中の監査エントリを実際に DB へ書き込む
    private void FlushAuditLogs(DbContext context)
    {
        // 書き込む必要が無ければ終了
        if (!BuildAuditLogs(context)) return;
        // AuditLog 自身は監査対象外なので、2 度目の SaveChanges で再帰的に
        // 監査レコードが増えることはない(_pending は既にクリア済み)。
        // 2 度目の SaveChanges で監査ログを DB へ保存
        context.SaveChanges();
    }

    // 非同期版: 保留中の監査エントリを DB へ書き込む
    private async Task FlushAuditLogsAsync(DbContext context, CancellationToken cancellationToken)
    {
        // 書き込み対象がなければ終了
        if (!BuildAuditLogs(context)) return;
        // 非同期で DB に保存
        await context.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// 保留中の監査エントリを AuditLog として ChangeTracker に追加する。
    /// 書き込むべき行があった場合のみ true を返す(呼び出し側が SaveChanges するかどうかの判定用)。
    /// </summary>
    private bool BuildAuditLogs(DbContext context)
    {
        // 保留が無ければ false を返して終了
        if (!_pending.TryGetValue(context, out var captured) || captured.Count == 0)
        {
            _pending.Remove(context);
            return false;
        }

        // 同じ DbContext に対する再入を防ぐため先にクリアしてから組み立て
        _pending.Remove(context);

        // 保留エントリを1件ずつ AuditLog に変換して追加
        foreach (var item in captured)
        {
            // Added 行はここで採番済みの ID を読む。Modified/Deleted は事前取得済み。
            var entityKey = item.PrekeyIfKnown ?? GetPrimaryKey(item.Entry);

            // AuditLog 行を ChangeTracker に追加(まだ DB には書かれない)
            context.Add(new AuditLog
            {
                ChangedAt = item.ChangedAt,
                ChangedBy = item.ChangedBy,
                EntityName = item.EntityName,
                EntityKey = entityKey,
                Operation = item.State.ToString(),
                ChangesJson = item.ChangesJson
            });
        }

        // 書き込み対象があることを呼び出し側に伝える
        return true;
    }

    // EntityEntry から主キー値を取り出し、複合キーならカンマ区切りの文字列で返す
    private static string GetPrimaryKey(EntityEntry entry)
    {
        // メタデータから主キー定義を取得
        var key = entry.Metadata.FindPrimaryKey();
        // 主キーが見つからない場合は空文字を返す
        if (key is null) return "";
        // キー列の現在値を文字列化して並べる
        var values = key.Properties.Select(p => entry.Property(p.Name).CurrentValue?.ToString() ?? "");
        // 複数列キーにも対応できるようカンマ区切りで結合
        return string.Join(",", values);
    }

    // enum を数値でなく名前で JSON シリアライズする。監査ログの可読性と、
    // 文字列値でコミット済みの過去ログとの整合性を保つため必須。
    // JSON シリアライザの共通設定(enum を文字列名で出力)
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    // マスキング適用後の置換文字列(Redact の固定値)
    private const string RedactedPlaceholder = "[REDACTED]";

    // 1 エントリの変更内容を {列名: {old, new}} の JSON 文字列に変換する。
    // [Sensitive] 属性の付いたプロパティは Mask 種別に応じて値を変換する。
    private string? SerializeChanges(EntityEntry entry)
    {
        // 変更内容を格納する辞書
        var dict = new Dictionary<string, object?>();

        // 全プロパティを走査
        foreach (var prop in entry.Properties)
        {
            // 主キー列は監査ログ本体で別枠に持つので除外
            if (prop.Metadata.IsPrimaryKey()) continue;

            // このプロパティに [Sensitive] が付いていれば Mask 種別を取得(無ければ null)
            var mask = LookupSensitiveMask(entry.Entity.GetType(), prop.Metadata.Name);

            // 状態ごとに「new のみ」「old のみ」「old/new 両方」を切り替え
            switch (entry.State)
            {
                // 新規追加: 新しい値だけ残す
                case EntityState.Added:
                    dict[prop.Metadata.Name] = new { @new = MaskValue(prop.CurrentValue, mask) };
                    break;
                // 削除: 元の値だけ残す(あとから何が消えたか追えるように)
                case EntityState.Deleted:
                    dict[prop.Metadata.Name] = new { old = MaskValue(prop.OriginalValue, mask) };
                    break;
                // 更新: 実際に値が変わった列だけ old/new を記録
                case EntityState.Modified:
                    if (prop.IsModified && !Equals(prop.OriginalValue, prop.CurrentValue))
                    {
                        dict[prop.Metadata.Name] = new
                        {
                            old = MaskValue(prop.OriginalValue, mask),
                            @new = MaskValue(prop.CurrentValue, mask)
                        };
                    }
                    break;
            }
        }

        // 記録すべき項目が無ければ null、あれば JSON 文字列を返す
        return dict.Count == 0 ? null : JsonSerializer.Serialize(dict, _jsonOptions);
    }

    // 値を Mask 種別に応じて変換する。null と Mask なし(=null)はそのまま返す。
    private object? MaskValue(object? value, Mask? mask)
    {
        // [Sensitive] が付いていなければ何もせず返す
        if (mask is null) return value;
        // null 値をマスクしても意味が無いのでそのまま
        if (value is null) return null;

        // Mask 種別ごとに変換
        switch (mask.Value)
        {
            // 完全に伏せる
            case Mask.Redact:
                return RedactedPlaceholder;
            // 文字数だけ残す
            case Mask.LengthOnly:
                // 値を文字列化してから長さを取る(数値などにも対応)
                return $"[len={value.ToString()?.Length ?? 0}]";
            // Salt 付き SHA-256 の先頭 8 桁
            case Mask.Hash:
                return ComputeShortHash(value.ToString() ?? "");
            // 想定外の Mask 値が来たら安全側に倒して REDACTED に
            default:
                return RedactedPlaceholder;
        }
    }

    // 入力文字列を Salt 付き SHA-256 でハッシュ化し、先頭 8 桁の hex を返す
    private string ComputeShortHash(string input)
    {
        // Salt + 入力 を UTF-8 バイト列に変換
        var bytes = Encoding.UTF8.GetBytes(_auditOptions.HashSalt + input);
        // SHA-256 で固定長(32 byte)のハッシュを計算
        var hash = SHA256.HashData(bytes);
        // hex 化して先頭 8 桁(4 byte 分)だけ採用(同値性確認には十分、衝突は許容)
        return $"#{Convert.ToHexString(hash)[..8].ToLowerInvariant()}";
    }

    // 指定 (型, プロパティ名) に対する [Sensitive] の Mask 種別をキャッシュ付きで取得
    private static Mask? LookupSensitiveMask(Type entityType, string propertyName)
    {
        // キャッシュキー
        var key = (entityType, propertyName);
        // ロックして辞書を確認(まれな初回時の競合のみガード)
        lock (_cacheLock)
        {
            // キャッシュ命中ならそのまま返す
            if (_sensitiveCache.TryGetValue(key, out var cached))
            {
                return cached;
            }
        }

        // CLR 上の PropertyInfo を取得(Shadow Property は対象外: PropertyInfo が無いので null)
        var propInfo = entityType.GetProperty(
            propertyName,
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic);
        // [Sensitive] 属性を取得(継承元クラスの属性も含めて検索)
        var attr = propInfo?.GetCustomAttribute<SensitiveAttribute>(inherit: true);
        // 属性が無ければ null、あれば Mask を取り出す
        var mask = attr?.Mask;

        // キャッシュへ書き戻す(同じキーが別スレッドで先に書かれていれば上書き)
        lock (_cacheLock)
        {
            _sensitiveCache[key] = mask;
        }

        return mask;
    }

    // 保留中の監査エントリを表す内部データ構造
    private record PendingAudit(
        EntityEntry Entry,
        EntityState State,
        string EntityName,
        string? PrekeyIfKnown,
        DateTime ChangedAt,
        string ChangedBy,
        string? ChangesJson);
}
