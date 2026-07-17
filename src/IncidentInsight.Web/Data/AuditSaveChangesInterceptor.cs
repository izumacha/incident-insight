// スレッドセーフなコレクション(ConcurrentDictionary)を使う
using System.Collections.Concurrent;
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
// トランザクション型(IDbContextTransaction)を使う
using Microsoft.EntityFrameworkCore.Storage;
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

    // HMAC の鍵バイト列をコンストラクタで一度だけ変換してキャッシュする。
    // ComputePseudonym が呼ばれるたびに Encoding.UTF8.GetBytes() を実行する無駄を避ける。
    private readonly byte[] _hmacKeyBytes;

    // DbContext インスタンスごとの保留監査エントリ。
    // このインターセプタは AddScoped で登録されるが、DbContext オプションの設定時に
    // sp.GetRequiredService<AuditSaveChangesInterceptor>() で取得するため、
    // DbContext と同一スコープ(1 HTTP リクエスト)につき 1 インスタンス生成される。
    // 理論上は 1 インスタンス:1 リクエストなので単純な Dictionary<> でも動くが、
    // 将来的に登録方式が変わってもスレッド安全になるよう ConcurrentDictionary<> を使う(issue #67)。
    private readonly ConcurrentDictionary<DbContext, List<PendingAudit>> _pending = new();

    // インターセプタ自身が開始したトランザクション(DbContext ごと)。
    // 業務変更(1 度目の SaveChanges)と監査ログ(2 度目の SaveChanges)は別々の
    // SaveChanges で書かれるため、そのままでは別トランザクションでコミットされ、
    // 「業務変更はコミット済みなのに監査行の INSERT だけ失敗した」という監査欠落
    // (規制対応の監査証跡としては許容できない)が起こりうる。呼び出し側が既に
    // トランザクションを張っていない場合に限り、ここで自前のトランザクションを開始し、
    // 監査行の書き込みまで完了した時点でコミットすることで両者を原子的にする。
    private readonly ConcurrentDictionary<DbContext, IDbContextTransaction> _ownedTransactions = new();

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
        // HMAC 鍵を一度だけバイト列に変換してキャッシュする
        // (ComputePseudonym が毎回 Encoding.UTF8.GetBytes を呼ぶ代わりにこの値を使う)
        _hmacKeyBytes = Encoding.UTF8.GetBytes(_auditOptions.HashSalt);
    }

    // 同期版 SaveChanges の直前フック: スナップショットとトークン更新を行う
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        // DbContext があれば対象エントリをキャプチャしてトークンも更新
        if (eventData.Context is not null)
        {
            // 監査対象の変更をスナップショット化する
            CaptureAndBumpTokens(eventData.Context);
            // 監査対象がある場合、業務変更+監査行を1トランザクションに束ねる準備をする
            if (ShouldBeginOwnedTransaction(eventData.Context))
            {
                // 自前トランザクションを開始して記録する(コミットは監査行の書き込み後)
                _ownedTransactions[eventData.Context] = eventData.Context.Database.BeginTransaction();
            }
        }
        // 基底処理へ委譲
        return base.SavingChanges(eventData, result);
    }

    // 非同期版 SaveChanges の直前フック
    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        // DbContext があれば対象エントリをキャプチャしてトークンも更新
        if (eventData.Context is not null)
        {
            // 監査対象の変更をスナップショット化する
            CaptureAndBumpTokens(eventData.Context);
            // 監査対象がある場合、業務変更+監査行を1トランザクションに束ねる準備をする
            if (ShouldBeginOwnedTransaction(eventData.Context))
            {
                // 自前トランザクションを非同期で開始して記録する
                _ownedTransactions[eventData.Context] =
                    await eventData.Context.Database.BeginTransactionAsync(cancellationToken);
            }
        }
        // 基底処理へ委譲
        return await base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    // 自前トランザクションを開始すべきかを判定する。
    // (a) 監査対象の変更が 1 件以上あり、(b) リレーショナル DB で(InMemory テストは
    //     トランザクション未対応のため従来どおり 2 回の SaveChanges)、
    // (c) 呼び出し側が既にトランザクションを張っていない(例: IncidentsController.Create は
    //     自前のトランザクションで括っているので二重に開始しない)場合のみ true。
    private bool ShouldBeginOwnedTransaction(DbContext context)
    {
        // 監査対象の変更が無ければトランザクションで束ねる必要は無い
        if (!_pending.TryGetValue(context, out var captured) || captured.Count == 0) return false;
        // InMemory 等の非リレーショナルプロバイダではトランザクションを使わない
        if (!context.Database.IsRelational()) return false;
        // 呼び出し側のトランザクションが既にあればそれに任せる
        return context.Database.CurrentTransaction is null;
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
        // 失敗した場合は保留エントリを破棄し、自前トランザクションもロールバック
        if (eventData.Context is not null)
        {
            // 保留中の監査エントリを破棄(ゴミを残さない)
            _pending.TryRemove(eventData.Context, out _);
            // 自前トランザクションが開いていれば巻き戻して破棄する
            RollbackOwnedTransaction(eventData.Context);
        }
        // 基底処理へ委譲
        base.SaveChangesFailed(eventData);
    }

    // 非同期版: SaveChanges が失敗したときのフック
    public override Task SaveChangesFailedAsync(
        DbContextErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        // 失敗時も保留エントリをクリアし、自前トランザクションをロールバック
        if (eventData.Context is not null)
        {
            // 保留中の監査エントリを破棄
            _pending.TryRemove(eventData.Context, out _);
            // 自前トランザクションが開いていれば巻き戻して破棄する
            RollbackOwnedTransaction(eventData.Context);
        }
        // 基底処理へ委譲
        return base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    // 自前トランザクションをコミットして破棄する(無ければ何もしない)
    private void CommitOwnedTransaction(DbContext context)
    {
        // このコンテキスト用の自前トランザクションを取り出す(2 重コミット防止のため先に除去)
        if (!_ownedTransactions.TryRemove(context, out var transaction)) return;
        // using で確実に破棄しつつコミットする
        using (transaction)
        {
            // 業務変更 + 監査行をまとめて確定する
            transaction.Commit();
        }
    }

    // 自前トランザクションをロールバックして破棄する(無ければ何もしない)
    private void RollbackOwnedTransaction(DbContext context)
    {
        // このコンテキスト用の自前トランザクションを取り出す(2 重ロールバック防止のため先に除去)
        if (!_ownedTransactions.TryRemove(context, out var transaction)) return;
        // using で確実に破棄しつつロールバックする
        using (transaction)
        {
            try
            {
                // 業務変更 + 監査行をまとめて巻き戻す
                transaction.Rollback();
            }
            catch (Exception)
            {
                // このメソッドは SaveChanges 失敗の例外処理中に呼ばれる。接続断などで
                // Rollback 自体が失敗しても、未コミットのトランザクションは破棄時に
                // DB 側で自動的に巻き戻るため整合性は保たれる。ここで再スローすると
                // 元の失敗例外(呼び出し元が捕捉すべき本来の原因)が握り潰されてしまうため、
                // Rollback 失敗のみ意図的に無視して元の例外を伝播させる。
            }
        }
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

        // 変更追跡中のエントリから監査対象(Added/Modified/Deleted)だけ取り出す。
        // 型名は実行時型(GetType())ではなく EF のメタデータ(Metadata.ClrType)から取る。
        // 実行時型だと、将来 EF の遅延読み込みプロキシ等を有効化した場合に
        // 「IncidentProxy」のような派生型名になり、監査が黙って全部スキップされてしまう
        // (監査証跡の fail-open)ため、プロキシの影響を受けないメタデータ側を使う。
        var entries = context.ChangeTracker.Entries()
            .Where(e => AuditedEntities.Contains(e.Metadata.ClrType.Name)
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
                // 型名はプロキシの影響を受けない EF メタデータから取る(上のフィルタと同じ理由)
                EntityName: entry.Metadata.ClrType.Name,
                // Modified/Deleted の ID は確定済み、Added は 0 (SavedChanges で再読込)
                PrekeyIfKnown: entry.State == EntityState.Added ? null : GetPrimaryKey(entry),
                ChangedAt: now,
                ChangedBy: user,
                ChangesJson: SerializeChanges(entry)));
        }

        // この DbContext の保留エントリとして保存
        _pending[context] = captured;
    }

    // 同期版: 保留中の監査エントリを実際に DB へ書き込み、自前トランザクションを確定する
    private void FlushAuditLogs(DbContext context)
    {
        try
        {
            // 書き込む監査エントリがある場合のみ 2 度目の SaveChanges を行う。
            // AuditLog 自身は監査対象外なので、2 度目の SaveChanges で再帰的に
            // 監査レコードが増えることはない(_pending は既にクリア済み)。
            // なお 2 度目の SaveChanges から再入するフック(監査エントリなし)は
            // この if に入らないため、コミットは業務変更側の呼び出しだけが行う。
            if (BuildAuditLogs(context))
            {
                // 2 度目の SaveChanges で監査ログを DB へ保存
                context.SaveChanges();
                // 業務変更 + 監査行が両方書けたのでまとめてコミット(自前開始時のみ)
                CommitOwnedTransaction(context);
            }
        }
        catch
        {
            // 監査行の書き込みに失敗した場合は業務変更ごと巻き戻す
            // (監査証跡の無い業務変更を残さない = fail-closed)
            RollbackOwnedTransaction(context);
            // 失敗自体は握り潰さず呼び出し元へ伝える
            throw;
        }
    }

    // 非同期版: 保留中の監査エントリを DB へ書き込み、自前トランザクションを確定する
    private async Task FlushAuditLogsAsync(DbContext context, CancellationToken cancellationToken)
    {
        try
        {
            // 書き込む監査エントリがある場合のみ 2 度目の SaveChanges を行う(同期版と同じ理由)
            if (BuildAuditLogs(context))
            {
                // 非同期で監査ログを DB に保存
                await context.SaveChangesAsync(cancellationToken);
                // 業務変更 + 監査行が両方書けたのでまとめてコミット(自前開始時のみ)
                CommitOwnedTransaction(context);
            }
        }
        catch
        {
            // 監査行の書き込みに失敗した場合は業務変更ごと巻き戻す(fail-closed)
            RollbackOwnedTransaction(context);
            // 失敗自体は握り潰さず呼び出し元へ伝える
            throw;
        }
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
            // エントリが空でも念のためキーを削除してメモリを解放する
            _pending.TryRemove(context, out _);
            return false;
        }

        // 同じ DbContext に対する再入を防ぐため先にクリアしてから組み立て
        _pending.TryRemove(context, out _);

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

            // このプロパティに [Sensitive] が付いていれば Mask 種別を取得(無ければ null)。
            // 型はプロキシの影響を受けない EF メタデータから取る(キャッシュキーの安定化)
            var mask = LookupSensitiveMask(entry.Metadata.ClrType, prop.Metadata.Name);

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
            // 秘密鍵(salt)付き HMAC-SHA256 による擬似匿名化(先頭 128bit)
            case Mask.Hash:
                return ComputePseudonym(value.ToString() ?? "");
            // 想定外の Mask 値が来たら安全側に倒して REDACTED に
            default:
                return RedactedPlaceholder;
        }
    }

    // 入力文字列を HMAC-SHA256(鍵 = HashSalt)で擬似匿名化し、先頭 128bit(hex 32 桁)を返す。
    //
    // なぜ素の SHA-256 ではなく HMAC か(issue #61): 日本人の氏名は取りうる値が少なく
    // エントロピーが低いため、salt を連結しただけの決定的 SHA-256 は、AuditLogs を読める者
    // (Admin / DB バックアップ漏洩)が事前計算した辞書で簡単に逆算できてしまう。秘密鍵付きの
    // HMAC にすれば、鍵(HashSalt)を知らない限り逆算できない。本番では HashSalt が空でないことを
    // 起動時(Program.cs)に保証している。
    //
    // なぜ 8 桁(32bit)ではなく 128bit か(issue #62): 32bit は衝突しやすく、規制対応の監査証跡で
    // 「同一人物が X と Y を編集した」という相関に誤検出(別人が同じ値)を生む。128bit に拡張して
    // 衝突をほぼ起こさないようにしつつ、ログを過度に冗長にしない。
    //
    // 注意: ハッシュ方式(SHA-256 連結 → HMAC・128bit)を変えたため、本変更より前に書かれた
    // 既存 AuditLogs のハッシュ値とは突合できない(salt 回転と同じ扱い)。過去ログは書き換えない。
    private string ComputePseudonym(string input)
    {
        // コンストラクタでキャッシュ済みの鍵バイト列を使う(毎回 GetBytes しない)
        // 擬似匿名化したい入力(氏名など)を UTF-8 バイト列に変換する
        var message = Encoding.UTF8.GetBytes(input);
        // 鍵付きハッシュ HMAC-SHA256 を計算する(鍵が無いと値を逆算できない)
        using var hmac = new HMACSHA256(_hmacKeyBytes);
        // 入力バイト列から固定長(32 byte)の HMAC を求める
        var hash = hmac.ComputeHash(message);
        // hex 化して先頭 32 桁(128bit 分)だけ採用する(衝突耐性を確保しつつ冗長さを抑える)
        return $"#{Convert.ToHexString(hash)[..32].ToLowerInvariant()}";
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
