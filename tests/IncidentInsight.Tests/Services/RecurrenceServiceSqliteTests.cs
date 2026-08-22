// ApplicationDbContext を使えるようにする（SQLite ファイル DB のセットアップに必要）
using IncidentInsight.Web.Data;
// Incident / CauseAnalysis / CauseCategory などのモデルを使えるようにする
using IncidentInsight.Web.Models;
// IncidentTypeKind / IncidentSeverity などの列挙型を使えるようにする
using IncidentInsight.Web.Models.Enums;
// テスト対象の RecurrenceService を使えるようにする
using IncidentInsight.Web.Services;
// SQLite ファイル DB の後始末ヘルパーを使えるようにする
using IncidentInsight.Tests.Helpers;
// EF Core の DbContextOptionsBuilder / UseSqlite を使えるようにする
using Microsoft.EntityFrameworkCore;
// テストでは何も出力しないロガー(NullLogger)を使うため
using Microsoft.Extensions.Logging.Abstractions;

// テストクラスが所属する名前空間（テストプロジェクトの Services フォルダ配下）
namespace IncidentInsight.Tests.Services;

/// <summary>
/// RecurrenceService を「実際のリレーショナルプロバイダ（SQLite）」で動かす回帰テスト。
/// </summary>
/// <remarks>
/// 他の RecurrenceService テストは EF Core の InMemory プロバイダを使っている。InMemory は
/// 投影（Select）をクライアント側で評価するため、<b>SQL へ翻訳できないクエリを書いても素通りする</b>。
/// 一方 <c>LoadCauseCategoryDisplayNamesAsync</c> は、取得に失敗しても見出しを
/// 「部署 / 種別」へ縮退させて続行する fail-safe（§9）になっている。この 2 つが重なると、
/// 将来だれかが投影に翻訳不能な式を足したとき、
/// <b>テストは緑のまま・画面は 500 にもならず、本番の見出しだけが恒久的に分類名を失う</b>。
/// そこで実プロバイダでの翻訳可否をここで固定する（`Microsoft.EntityFrameworkCore.Sqlite` は
/// ConcurrencyTests などが既にこの用途で使っている）。
/// </remarks>
public class RecurrenceServiceSqliteTests
{
    /// <summary>
    /// SQLite（実プロバイダ）でも再発アラートの見出しに「親 &gt; 子」形式の原因分類名が入ることを検証する。
    /// 分類名の引き当てクエリが SQL へ翻訳できなくなったら、このテストが落ちる。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_OnSqlite_TranslatesCauseCategoryNameQuery()
    {
        // テスト専用の SQLite ファイル DB のパスを作る（テストごとに一意）
        var dbPath = Path.Combine(Path.GetTempPath(), $"incident-insight-recurrence-sqlite-{Guid.NewGuid():N}.db");
        // EF Core へ渡す接続文字列を組み立てる
        var connectionString = $"Data Source={dbPath}";
        try
        {
            // マイグレーション経由ではなく EnsureCreated でスキーマだけ素早く作る
            // (このテストが見ているのはクエリの翻訳可否で、マイグレーション履歴とは無関係)
            await using var db = new ApplicationDbContext(
                new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connectionString).Options);
            // スキーマを作成する
            await db.Database.EnsureCreatedAsync();

            // 親カテゴリ（大分類）を作成する
            var parent = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
            // 親を DB に追加する
            db.CauseCategories.Add(parent);
            // 親の Id を確定させる（子の ParentId に使うため）
            await db.SaveChangesAsync();

            // 親にぶら下がる子カテゴリ（小分類）を作成する
            var child = new CauseCategory { Name = "確認不足", ParentId = parent.Id, DisplayOrder = 1 };
            // 子を DB に追加する
            db.CauseCategories.Add(child);
            // 子を保存する
            await db.SaveChangesAsync();

            // 再発する 2 件のインシデントを作る（新しい方）
            var newer = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-5));
            // 再発する 2 件のインシデントを作る（古い方）
            var older = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
            // 2 件を DB に追加する
            db.Incidents.AddRange(newer, older);
            // DB に保存して Id を確定させる
            await db.SaveChangesAsync();

            // 2 件に同じ子カテゴリでなぜなぜ分析を紐づける（これで再発と判定される）
            db.CauseAnalyses.AddRange(
                new CauseAnalysis { IncidentId = newer.Id, CauseCategoryId = child.Id, Why1 = "w" },
                new CauseAnalysis { IncidentId = older.Id, CauseCategoryId = child.Id, Why1 = "w" });
            // 原因分析を DB に保存する
            await db.SaveChangesAsync();

            // テスト対象のサービスを生成する（ロガーは出力しない NullLogger）
            var svc = new RecurrenceService(new SystemClock(), NullLogger<RecurrenceService>.Instance);
            // 直近 90 日を時間窓として再発アラートを取得する（ここで実 SQL が発行される）
            var alerts = await svc.FindRecurrenceAlertsAsync(db.Incidents, db.CauseCategories, TimeSpan.FromDays(90));

            // アラートが 1 件だけ生成されることを確認する
            var alert = Assert.Single(alerts);
            // 見出しに「親 > 子」形式の分類名が入っていることを確認する。
            // 分類名の引き当てが翻訳できずに例外→fail-safe で縮退した場合、ここが落ちる
            Assert.Contains("ヒューマンエラー > 確認不足", alert.PatternDescription);
            // 従来からの「部署 / 種別」表記も保たれていることを確認する
            Assert.Contains("外科病棟 / 投薬ミス", alert.PatternDescription);
        }
        finally
        {
            // SQLite の本体ファイルと補助ファイルをまとめて後始末する
            SqliteTestFiles.Cleanup(dbPath);
        }
    }

    /// <summary>
    /// テスト用インシデントを生成するヘルパーメソッド。
    /// </summary>
    /// <param name="dept">部署名（例: "外科病棟"）</param>
    /// <param name="type">インシデント種別（例: Medication）</param>
    /// <param name="occurredAt">発生日時</param>
    /// <returns>テスト用の Incident インスタンス</returns>
    private static Incident MakeIncident(string dept, IncidentTypeKind type, DateTime occurredAt)
        => new()
        {
            Department = dept,                  // 部署名をセットする
            IncidentType = type,                // インシデント種別をセットする
            Severity = IncidentSeverity.Level1, // 重症度は固定値（このテストでは任意の値）
            Description = "テスト",             // 状況説明（PHI テスト対象外なので簡略化）
            ReporterName = "テスト太郎",         // 報告者名（PHI テスト対象外なので簡略化）
            OccurredAt = occurredAt,            // 発生日時をセットする
            ReportedAt = occurredAt             // 報告日時（テストでは発生日時と同じにする）
        };
}
