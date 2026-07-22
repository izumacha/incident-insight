// アプリ本体の DbContext / シーダーを使う
using IncidentInsight.Web.Data;
// テスト用の固定時刻 IClock 実装を使う
using IncidentInsight.Tests.Helpers;
// InMemory プロバイダで DbContext を構成するために使う
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Data;

/// <summary>
/// DbSeeder のテスト。マスタデータ(原因分類)投入の Seed と、
/// Development 限定で呼ばれるデモインシデント投入の SeedDemoData が
/// それぞれ期待どおり投入・スキップ(冪等)されることを検証する。
/// </summary>
public class DbSeederTests : IDisposable
{
    // テスト対象の InMemory DbContext(テストごとに独立した DB 名)
    private readonly ApplicationDbContext _db;
    // デモデータの相対日付計算に使う固定時刻(決定論的なテストのため)
    private static readonly FixedClock Clock = new(new DateTime(2026, 7, 1, 9, 0, 0));

    public DbSeederTests()
    {
        // テストごとに一意な名前の InMemory DB を作る(他テストとの干渉防止)
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        // DbContext を生成して保持
        _db = new ApplicationDbContext(options);
    }

    // テスト終了時に DbContext を破棄する
    public void Dispose() => _db.Dispose();

    [Fact]
    public void Seed_SeedsMasterCategories_ButNoDemoIncidents()
    {
        // マスタデータのみの Seed を実行
        DbSeeder.Seed(_db);

        // 原因分類マスタ(親5件 + 子23件)が投入されていること
        Assert.Equal(28, _db.CauseCategories.Count());
        // デモインシデント・分析・対策は一切投入されないこと(本番想定の呼び出し)
        Assert.False(_db.Incidents.Any());
        Assert.False(_db.CauseAnalyses.Any());
        Assert.False(_db.PreventiveMeasures.Any());
    }

    [Fact]
    public void Seed_IsIdempotent_WhenCalledTwice()
    {
        // 1 回目の Seed でマスタを投入
        DbSeeder.Seed(_db);
        // 投入直後のカテゴリ件数を控える
        var countAfterFirst = _db.CauseCategories.Count();

        // 2 回目の Seed(再起動を想定)
        DbSeeder.Seed(_db);

        // 件数が変わらないこと(重複投入されない冪等性)
        Assert.Equal(countAfterFirst, _db.CauseCategories.Count());
    }

    [Fact]
    public void SeedDemoData_SeedsDemoIncidents_WhenRequested()
    {
        // 先にマスタ(原因分類)を投入(デモデータがカテゴリ名を参照するため)
        DbSeeder.Seed(_db);
        // Development を想定してデモデータ投入を実行
        DbSeeder.SeedDemoData(_db, Clock);

        // サンプルインシデント 5 件が投入されること
        Assert.Equal(5, _db.Incidents.Count());
        // 各インシデントに対応するなぜなぜ分析が投入されること
        Assert.Equal(5, _db.CauseAnalyses.Count());
        // 再発防止策のデモデータも投入されること
        Assert.True(_db.PreventiveMeasures.Any());
    }

    [Fact]
    public void SeedDemoData_IsIdempotent_WhenCalledTwice()
    {
        // マスタ + デモデータを 1 回投入
        DbSeeder.Seed(_db);
        DbSeeder.SeedDemoData(_db, Clock);
        // 投入直後のインシデント件数を控える
        var countAfterFirst = _db.Incidents.Count();

        // 2 回目の SeedDemoData(再起動を想定)
        DbSeeder.SeedDemoData(_db, Clock);

        // 件数が変わらないこと(重複投入されない冪等性)
        Assert.Equal(countAfterFirst, _db.Incidents.Count());
    }

    [Fact]
    public void SeedDemoData_SkipsSafely_WhenRequiredCategoriesMissing()
    {
        // マスタ未投入のまま(参照カテゴリが存在しない状態で)デモデータ投入を実行
        DbSeeder.SeedDemoData(_db, Clock);

        // 例外を投げず、インシデントも投入されないこと(fail-safe のスキップ)
        Assert.False(_db.Incidents.Any());
    }
}
