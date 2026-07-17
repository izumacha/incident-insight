// DbContext / インターセプタ(テスト対象)を使うために取り込む
using IncidentInsight.Web.Data;
// モデル(Incident)を使うために取り込む
using IncidentInsight.Web.Models;
// 監査設定(AuditOptions)を使うために取り込む
using IncidentInsight.Web.Models.Auditing;
// enum(重症度・種別)を使うために取り込む
using IncidentInsight.Web.Models.Enums;
// 時刻源サービスを使うために取り込む
using IncidentInsight.Web.Services;
// EF Core 本体を使うために取り込む
using Microsoft.EntityFrameworkCore;
// IOptions ラッパーを使うために取り込む
using Microsoft.Extensions.Options;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Data;

// 業務変更と監査ログが 1 トランザクションで原子的にコミットされることの検証。
// InMemory プロバイダはトランザクション未対応のためこの動作を検証できず、
// 本物のリレーショナル DB(SQLite ファイル DB)を使う。
// 以前は業務変更(1 度目の SaveChanges)がコミットされた後に監査行(2 度目の
// SaveChanges)を書いていたため、監査行の INSERT が失敗すると「監査証跡の無い
// 業務変更」が残ってしまっていた(規制対応の監査証跡としては許容できない)。
public class AuditTransactionAtomicityTests
{
    // テスト用の固定 salt(本番では必須の HashSalt を満たすためのダミー)
    private const string TestSalt = "unit-test-salt";

    // SQLite ファイル DB に監査インターセプタ付きの DbContext オプションを作るヘルパー
    private static DbContextOptions<ApplicationDbContext> BuildSqliteOptions(string connectionString) =>
        new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite(connectionString)
            .AddInterceptors(new AuditSaveChangesInterceptor(
                new SystemClock(), null, Options.Create(new AuditOptions { HashSalt = TestSalt })))
            .Options;

    // テスト用のインシデントを 1 件作るヘルパー
    private static Incident NewIncident() => new()
    {
        OccurredAt = new DateTime(2026, 6, 1, 9, 0, 0),
        Department = "内科病棟",
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "初回の状況説明",
        ReporterName = "テスト太郎"
    };

    // 一時 DB ファイルと補助ファイル(WAL/SHM/journal)を削除するヘルパー
    private static void CleanupDbFiles(string dbPath)
    {
        // SQLite が作りうる関連ファイルをまとめて削除する
        foreach (var path in new[] { dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal" })
        {
            // 存在するファイルだけ削除する
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task Update_OnRelationalProvider_PersistsBusinessChangeAndAuditRowTogether()
    {
        // 正常系: インターセプタが自前トランザクションを開始しても、
        // 業務変更と監査行の両方が問題なく永続化されることを確認する(回帰スモーク)
        var dbPath = Path.Combine(Path.GetTempPath(), $"incident-insight-audit-atomic-{Guid.NewGuid():N}.db");
        var options = BuildSqliteOptions($"Data Source={dbPath}");
        try
        {
            int incidentId;
            // スキーマ作成 + シード + 更新を実行する
            await using (var db = new ApplicationDbContext(options))
            {
                // マイグレーションではなく EnsureCreated で素早くスキーマだけ作る
                await db.Database.EnsureCreatedAsync();
                // インシデントを 1 件シードする(この時点で Added の監査行も書かれる)
                var incident = NewIncident();
                db.Incidents.Add(incident);
                await db.SaveChangesAsync();
                incidentId = incident.Id;

                // 業務変更(説明の更新)を保存する
                incident.Description = "更新後の状況説明";
                await db.SaveChangesAsync();
            }

            // 別のコンテキストで読み直し、業務変更と監査行の両方を確認する
            await using (var verifyDb = new ApplicationDbContext(options))
            {
                // 業務変更が永続化されていること
                var saved = await verifyDb.Incidents.SingleAsync(i => i.Id == incidentId);
                Assert.Equal("更新後の状況説明", saved.Description);
                // Added + Modified の監査行が揃っていること
                var operations = await verifyDb.AuditLogs
                    .Where(a => a.EntityName == nameof(Incident))
                    .Select(a => a.Operation)
                    .ToListAsync();
                Assert.Contains("Added", operations);
                Assert.Contains("Modified", operations);
            }
        }
        finally
        {
            // 一時 DB ファイルの後始末
            CleanupDbFiles(dbPath);
        }
    }

    [Fact]
    public async Task Update_WhenAuditInsertFails_RollsBackBusinessChange()
    {
        // 異常系(本題): 監査行の INSERT が失敗した場合、業務変更ごとロールバックされ
        // 「監査証跡の無い業務変更」が DB に残らないこと(fail-closed)を確認する。
        // AuditLogs テーブルを削除することで監査行の INSERT 失敗を再現する。
        var dbPath = Path.Combine(Path.GetTempPath(), $"incident-insight-audit-rollback-{Guid.NewGuid():N}.db");
        var options = BuildSqliteOptions($"Data Source={dbPath}");
        try
        {
            int incidentId;
            // スキーマ作成 + シードを実行する
            await using (var setupDb = new ApplicationDbContext(options))
            {
                // スキーマだけ素早く作る
                await setupDb.Database.EnsureCreatedAsync();
                // インシデントを 1 件シードする
                var incident = NewIncident();
                setupDb.Incidents.Add(incident);
                await setupDb.SaveChangesAsync();
                incidentId = incident.Id;
                // 監査行の INSERT を必ず失敗させるため AuditLogs テーブルを落とす
                // (ExecuteSqlRaw は監査対象エンティティへの操作ではないので使用可)
                await setupDb.Database.ExecuteSqlRawAsync("DROP TABLE AuditLogs;");
            }

            // 業務変更を試みる: 監査行が書けないため SaveChanges は失敗するはず
            await using (var db = new ApplicationDbContext(options))
            {
                // 対象を読み込んで説明を書き換える
                var incident = await db.Incidents.SingleAsync(i => i.Id == incidentId);
                incident.Description = "監査に失敗する更新";
                // 監査行の INSERT 失敗が DbUpdateException として伝播すること
                await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
            }

            // 別のコンテキストで読み直し、業務変更がロールバックされていることを確認する
            await using (var verifyDb = new ApplicationDbContext(options))
            {
                // 説明が元のままであること(監査証跡なしの変更が残っていない)
                var saved = await verifyDb.Incidents.SingleAsync(i => i.Id == incidentId);
                Assert.Equal("初回の状況説明", saved.Description);
            }
        }
        finally
        {
            // 一時 DB ファイルの後始末
            CleanupDbFiles(dbPath);
        }
    }
}
