using System.Text.Json;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Auditing;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentInsight.Tests.Data;

public class AuditSaveChangesInterceptorTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    // テスト用の固定 salt(Hash マスクの決定的な検証に使う)
    private const string TestSalt = "unit-test-salt";

    public AuditSaveChangesInterceptorTests()
    {
        // 固定 salt を持つ AuditOptions を IOptions でラップ
        var auditOptions = Options.Create(new AuditOptions { HashSalt = TestSalt });
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .AddInterceptors(new AuditSaveChangesInterceptor(new SystemClock(), null, auditOptions))
            .Options;
        _db = new ApplicationDbContext(options);
    }

    public void Dispose() => _db.Dispose();

    private static Incident NewIncident() => new()
    {
        OccurredAt = DateTime.Now,
        Department = "内科病棟",
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト状況",
        ReporterName = "テスト太郎"
    };

    [Fact]
    public async Task Added_Incident_WritesAuditLog()
    {
        var incident = NewIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var logs = await _db.AuditLogs.ToListAsync();
        var log = Assert.Single(logs);
        Assert.Equal(nameof(Incident), log.EntityName);
        Assert.Equal("Added", log.Operation);
        Assert.Equal(incident.Id.ToString(), log.EntityKey);
        Assert.False(string.IsNullOrEmpty(log.ChangesJson));
    }

    [Fact]
    public async Task Modified_PreventiveMeasure_WritesAuditLogAndBumpsConcurrencyToken()
    {
        var incident = NewIncident();
        var measure = new PreventiveMeasure
        {
            Description = "テスト対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        };
        incident.PreventiveMeasures.Add(measure);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var originalToken = measure.ConcurrencyToken;

        // Modify status
        measure.Status = MeasureStatus.Completed;
        measure.CompletedAt = DateTime.Now;
        await _db.SaveChangesAsync();

        var modifiedLog = await _db.AuditLogs
            .Where(a => a.EntityName == nameof(PreventiveMeasure) && a.Operation == "Modified")
            .SingleAsync();

        Assert.Contains("Status", modifiedLog.ChangesJson);
        Assert.NotEqual(originalToken, measure.ConcurrencyToken);
    }

    [Fact]
    public async Task Deleted_CauseAnalysis_WritesAuditLog()
    {
        var incident = NewIncident();
        var category = new CauseCategory { Name = "テスト分類", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var analysis = new CauseAnalysis
        {
            Incident = incident,
            CauseCategory = category,
            Why1 = "なぜ1"
        };
        incident.CauseAnalyses.Add(analysis);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.Remove(analysis);
        await _db.SaveChangesAsync();

        var deletedLog = await _db.AuditLogs
            .Where(a => a.EntityName == nameof(CauseAnalysis) && a.Operation == "Deleted")
            .SingleAsync();

        Assert.Equal(analysis.Id.ToString(), deletedLog.EntityKey);
    }

    [Fact]
    public async Task Deleted_Incident_WithChildrenLoaded_AuditsAllChildren()
    {
        // Incident 削除時に子(CauseAnalysis / PreventiveMeasure)を Include してから
        // Remove するコントローラのパターンを再現し、ChangeTracker 経由で子も
        // 監査ログに記録されることを検証する。
        var category = new CauseCategory { Name = "テスト分類", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var incident = NewIncident();
        incident.CauseAnalyses.Add(new CauseAnalysis { CauseCategory = category, Why1 = "なぜ1" });
        incident.PreventiveMeasures.Add(new PreventiveMeasure
        {
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        });
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var toDelete = await _db.Incidents
            .Include(i => i.CauseAnalyses)
            .Include(i => i.PreventiveMeasures)
            .FirstAsync(i => i.Id == incident.Id);
        _db.Incidents.Remove(toDelete);
        await _db.SaveChangesAsync();

        var deletedLogs = await _db.AuditLogs
            .Where(a => a.Operation == "Deleted")
            .ToListAsync();

        Assert.Contains(deletedLogs, l => l.EntityName == nameof(Incident));
        Assert.Contains(deletedLogs, l => l.EntityName == nameof(CauseAnalysis));
        Assert.Contains(deletedLogs, l => l.EntityName == nameof(PreventiveMeasure));
    }

    [Fact]
    public async Task NonAuditedEntity_DoesNotProduceAuditLog()
    {
        var category = new CauseCategory { Name = "カテゴリA", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var logCount = await _db.AuditLogs.CountAsync();
        Assert.Equal(0, logCount);
    }

    // --- PHI マスキング ---

    [Fact]
    public async Task Sensitive_Redact_HidesDescriptionInChangesJson()
    {
        // Description は [Sensitive(Mask.Redact)] のため監査ログに平文で残ってはいけない
        var incident = NewIncident();
        incident.Description = "患者A様 田中太郎 が転倒した";
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var log = await _db.AuditLogs.SingleAsync(a => a.EntityName == nameof(Incident));
        // 平文の患者情報が含まれていないこと
        Assert.DoesNotContain("田中太郎", log.ChangesJson);
        Assert.DoesNotContain("患者A", log.ChangesJson);
        // REDACTED プレースホルダで置換されていること
        Assert.Contains("[REDACTED]", log.ChangesJson);
    }

    [Fact]
    public async Task Sensitive_Hash_ReporterName_ProducesShortHashPrefix()
    {
        // ReporterName は [Sensitive(Mask.Hash)] のためハッシュ表記(#xxxxxxxx)で記録される
        var incident = NewIncident();
        incident.ReporterName = "山田花子";
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var log = await _db.AuditLogs.SingleAsync(a => a.EntityName == nameof(Incident));
        // 平文の氏名は出ない
        Assert.DoesNotContain("山田花子", log.ChangesJson);
        // # で始まる 8 桁 hex のプレフィックスがある
        Assert.Matches("#[0-9a-f]{8}", log.ChangesJson!);
    }

    [Fact]
    public async Task Sensitive_Hash_SameInputAndSalt_ProducesSameHash()
    {
        // 同じ salt + 同じ入力なら毎回同じ短縮ハッシュを返すこと(担当者の同一性追跡が成立する根拠)
        var first = NewIncident();
        first.ReporterName = "鈴木一郎";
        _db.Incidents.Add(first);
        await _db.SaveChangesAsync();

        var second = NewIncident();
        second.ReporterName = "鈴木一郎";
        _db.Incidents.Add(second);
        await _db.SaveChangesAsync();

        var logs = await _db.AuditLogs
            .Where(a => a.EntityName == nameof(Incident) && a.Operation == "Added")
            .OrderBy(a => a.Id)
            .ToListAsync();
        Assert.Equal(2, logs.Count);

        // 各ログから ReporterName のハッシュを取り出して一致を確認
        var hash1 = ExtractFieldNew(logs[0].ChangesJson!, nameof(Incident.ReporterName));
        var hash2 = ExtractFieldNew(logs[1].ChangesJson!, nameof(Incident.ReporterName));
        Assert.Equal(hash1, hash2);
        Assert.StartsWith("#", hash1);
    }

    [Fact]
    public async Task NonSensitive_Field_StoredPlain()
    {
        // Department は [Sensitive] が付いていないので平文のまま記録される
        var incident = NewIncident();
        incident.Department = "ICU";
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var log = await _db.AuditLogs.SingleAsync(a => a.EntityName == nameof(Incident));
        Assert.Contains("ICU", log.ChangesJson);
    }

    [Fact]
    public async Task Sensitive_Modified_BothOldAndNewMasked()
    {
        // Modified の old/new 双方が [Sensitive] に従ってマスクされること
        var incident = NewIncident();
        incident.Description = "旧記述: 田中様";
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // ChangeTracker から切り離して再取得し、Description だけ更新
        incident.Description = "新記述: 山田様";
        await _db.SaveChangesAsync();

        var modifiedLog = await _db.AuditLogs.SingleAsync(
            a => a.EntityName == nameof(Incident) && a.Operation == "Modified");
        // 旧値・新値ともに平文が漏れていない
        Assert.DoesNotContain("田中", modifiedLog.ChangesJson);
        Assert.DoesNotContain("山田", modifiedLog.ChangesJson);
        // REDACTED が old / new 両方に出ている(2 回以上出現)
        var occurrences = System.Text.RegularExpressions.Regex.Matches(
            modifiedLog.ChangesJson!, "\\[REDACTED\\]").Count;
        Assert.True(occurrences >= 2);
    }

    [Fact]
    public async Task Sensitive_Deleted_OldValueMasked()
    {
        // 削除時の old 値もマスクされること(削除前の患者情報が残らないこと)
        var incident = NewIncident();
        incident.ReporterName = "佐藤健";
        incident.Description = "状況: 患者B様";
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // 削除時は子ナビゲーションの Include は不要(Incident 単体の検証)
        _db.Incidents.Remove(incident);
        await _db.SaveChangesAsync();

        var deletedLog = await _db.AuditLogs.SingleAsync(
            a => a.EntityName == nameof(Incident) && a.Operation == "Deleted");
        // 平文の氏名 / 患者情報が残っていないこと
        Assert.DoesNotContain("佐藤健", deletedLog.ChangesJson);
        Assert.DoesNotContain("患者B", deletedLog.ChangesJson);
    }

    // ChangesJson から特定列の "new" 値を抽出する小さなユーティリティ
    private static string ExtractFieldNew(string changesJson, string fieldName)
    {
        // JSON を JsonDocument で読み込む
        using var doc = JsonDocument.Parse(changesJson);
        // ルート直下に列名のオブジェクトがある
        var field = doc.RootElement.GetProperty(fieldName);
        // "new" プロパティを文字列で取得
        return field.GetProperty("new").GetString() ?? "";
    }
}
