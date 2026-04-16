using System.Text.Json;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;

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
    private static readonly HashSet<string> AuditedEntities = new()
    {
        nameof(Incident),
        nameof(CauseAnalysis),
        nameof(PreventiveMeasure)
    };

    private readonly IHttpContextAccessor? _httpContextAccessor;

    // DbContext インスタンスごとの保留監査エントリ。Scoped に一致するため競合しない。
    private readonly Dictionary<DbContext, List<PendingAudit>> _pending = new();

    public AuditSaveChangesInterceptor(IHttpContextAccessor? httpContextAccessor = null)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result)
    {
        if (eventData.Context is not null) CaptureAndBumpTokens(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is not null) CaptureAndBumpTokens(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        if (eventData.Context is not null) FlushAuditLogs(eventData.Context);
        return base.SavedChanges(eventData, result);
    }

    public override async ValueTask<int> SavedChangesAsync(
        SaveChangesCompletedEventData eventData,
        int result,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is not null) await FlushAuditLogsAsync(eventData.Context, cancellationToken);
        return await base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        if (eventData.Context is not null) _pending.Remove(eventData.Context);
        base.SaveChangesFailed(eventData);
    }

    public override Task SaveChangesFailedAsync(
        DbContextErrorEventData eventData,
        CancellationToken cancellationToken = default)
    {
        if (eventData.Context is not null) _pending.Remove(eventData.Context);
        return base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    private void CaptureAndBumpTokens(DbContext context)
    {
        var user = _httpContextAccessor?.HttpContext?.User?.Identity?.Name ?? "system";
        var now = DateTime.UtcNow;

        var captured = new List<PendingAudit>();

        var entries = context.ChangeTracker.Entries()
            .Where(e => AuditedEntities.Contains(e.Entity.GetType().Name)
                        && (e.State == EntityState.Added
                            || e.State == EntityState.Modified
                            || e.State == EntityState.Deleted))
            .ToList();

        foreach (var entry in entries)
        {
            // Modified の場合のみ ConcurrencyToken を更新
            if (entry.State == EntityState.Modified)
            {
                var tokenProp = entry.Properties.FirstOrDefault(p => p.Metadata.Name == "ConcurrencyToken");
                if (tokenProp is not null)
                {
                    tokenProp.CurrentValue = Guid.NewGuid();
                }
            }

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

        _pending[context] = captured;
    }

    private void FlushAuditLogs(DbContext context)
    {
        if (!BuildAuditLogs(context)) return;
        // AuditLog 自身は監査対象外なので、2 度目の SaveChanges で再帰的に
        // 監査レコードが増えることはない(_pending は既にクリア済み)。
        context.SaveChanges();
    }

    private async Task FlushAuditLogsAsync(DbContext context, CancellationToken cancellationToken)
    {
        if (!BuildAuditLogs(context)) return;
        await context.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// 保留中の監査エントリを AuditLog として ChangeTracker に追加する。
    /// 書き込むべき行があった場合のみ true を返す(呼び出し側が SaveChanges するかどうかの判定用)。
    /// </summary>
    private bool BuildAuditLogs(DbContext context)
    {
        if (!_pending.TryGetValue(context, out var captured) || captured.Count == 0)
        {
            _pending.Remove(context);
            return false;
        }

        _pending.Remove(context);

        foreach (var item in captured)
        {
            // Added 行はここで採番済みの ID を読む。Modified/Deleted は事前取得済み。
            var entityKey = item.PrekeyIfKnown ?? GetPrimaryKey(item.Entry);

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

        return true;
    }

    private static string GetPrimaryKey(EntityEntry entry)
    {
        var key = entry.Metadata.FindPrimaryKey();
        if (key is null) return "";
        var values = key.Properties.Select(p => entry.Property(p.Name).CurrentValue?.ToString() ?? "");
        return string.Join(",", values);
    }

    private static string? SerializeChanges(EntityEntry entry)
    {
        var dict = new Dictionary<string, object?>();

        foreach (var prop in entry.Properties)
        {
            if (prop.Metadata.IsPrimaryKey()) continue;

            switch (entry.State)
            {
                case EntityState.Added:
                    dict[prop.Metadata.Name] = new { @new = prop.CurrentValue };
                    break;
                case EntityState.Deleted:
                    dict[prop.Metadata.Name] = new { old = prop.OriginalValue };
                    break;
                case EntityState.Modified:
                    if (prop.IsModified && !Equals(prop.OriginalValue, prop.CurrentValue))
                    {
                        dict[prop.Metadata.Name] = new { old = prop.OriginalValue, @new = prop.CurrentValue };
                    }
                    break;
            }
        }

        return dict.Count == 0 ? null : JsonSerializer.Serialize(dict);
    }

    private record PendingAudit(
        EntityEntry Entry,
        EntityState State,
        string EntityName,
        string? PrekeyIfKnown,
        DateTime ChangedAt,
        string ChangedBy,
        string? ChangesJson);
}
