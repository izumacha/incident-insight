using System.Text.Json;
using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Controllers;

// Chart.js on the frontend consumes { labels, data } JSON verbatim. These tests
// pin the shape so that a future controller refactor can't silently break the
// dashboard without the CI catching it.
public class AnalyticsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly AnalyticsController _controller;

    public AnalyticsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new AnalyticsController(_db, new SystemClock());
        // ログイン中の利用者を必ず付ける。この画面は [Authorize(Policy = CanViewAnalytics)] なので
        // 本番で User が空のまま動くことはなく、付けないと実在確認の部署スコープ
        // (ScopedByUser)が NullReferenceException になる。ロールは Admin
        // ——この画面を開けるのは Admin / RiskManager だけで、どちらも全部署を見られる
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    // JSON の読み取りは共有ヘルパーへ寄せてある(絞り込み方式を固定する
    // UnlistedFilterValuePolicyTests も同じ読み方をするため。写しを持つと、
    // 片方だけ直列化の規約を直したときにもう片方が本番と違うキー名を読む)
    private static JsonDocument ToJsonDocument(IActionResult result) =>
        JsonResultReader.ToJsonDocument(result);

    private static Incident MakeIncident(string dept = "内科病棟",
        IncidentTypeKind type = IncidentTypeKind.Medication,
        IncidentSeverity severity = IncidentSeverity.Level2,
        DateTime? occurredAt = null) => new()
    {
        Department = dept,
        IncidentType = type,
        Severity = severity,
        Description = "テスト",
        ReporterName = "テスト太郎",
        OccurredAt = occurredAt ?? DateTime.Now,
        ReportedAt = DateTime.Now
    };

    // 部署フィルタの「空入力」判定が一覧画面と揃っていることを固定する(issue #187)。
    // グラフ系エンドポイントは一覧と同じ department をクエリ文字列で受けるため、ここだけ
    // string.IsNullOrEmpty のままだと、空白のみの値で /Incidents は全件を返すのに
    // グラフだけが Department == " " に一致せず全系列 0 になる(同じ値で画面ごとに結果が変わる)。
    // 3 エンドポイントが各自で判定を持つので、経路ごとに押さえる。
    [Theory]
    [InlineData(" ")]           // 半角スペース
    [InlineData("　")]          // 全角スペース
    public async Task Endpoints_WhitespaceOnlyDepartment_IsTreatedAsNoFilter(string blankInput)
    {
        // 日本語の部署名を持つインシデントを 1 件用意する(空白とは完全一致しない)
        var incident = MakeIncident(dept: "内科病棟");
        _db.Incidents.Add(incident);
        // 原因分析も 1 件ぶら下げる(ByCause の集計対象にするため)
        _db.CauseAnalyses.Add(new CauseAnalysis
        {
            Incident = incident,
            CauseCategory = new CauseCategory { Name = "確認不足", DisplayOrder = 1 },
            Why1 = "確認していなかった"
        });
        await _db.SaveChangesAsync();

        // 月次推移: 絞り込みが走らず、今月のカウントに 1 件が残ること
        using (var doc = ToJsonDocument(await _controller.MonthlyTrend(null, null, blankInput)))
        {
            var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
            Assert.Equal(1, data[^1].GetInt32());
        }

        // 重症度別: 絞り込みが走らず、合計が 1 件になること
        using (var doc = ToJsonDocument(await _controller.BySeverity(null, null, blankInput)))
        {
            var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
            Assert.Equal(1, data.Sum(d => d.GetInt32()));
        }

        // 原因別: 絞り込みが走らず、合計が 1 件になること
        using (var doc = ToJsonDocument(await _controller.ByCause(null, null, blankInput)))
        {
            var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
            Assert.Equal(1, data.Sum(d => d.GetInt32()));
        }
    }

    [Fact]
    public async Task MonthlyTrend_EmptyDb_Returns12MonthLabelsAndZeroCounts()
    {
        var result = await _controller.MonthlyTrend(null, null, null);
        using var doc = ToJsonDocument(result);

        var labels = doc.RootElement.GetProperty("labels").EnumerateArray().ToList();
        var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();

        Assert.Equal(12, labels.Count);
        Assert.Equal(12, data.Count);
        Assert.All(data, d => Assert.Equal(0, d.GetInt32()));
    }

    [Fact]
    public async Task MonthlyTrend_WithIncidents_CountsByCurrentMonth()
    {
        _db.Incidents.Add(MakeIncident(occurredAt: DateTime.Today));
        _db.Incidents.Add(MakeIncident(occurredAt: DateTime.Today));
        await _db.SaveChangesAsync();

        var result = await _controller.MonthlyTrend(null, null, null);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
        Assert.Equal(2, data[^1].GetInt32());
    }

    [Fact]
    public async Task MonthlyTrend_DateFrom_ExcludesIncidentBeforeCutoff()
    {
        // 同じ日の午前(古い方)と午後(新しい方)に発生したインシデントを用意する(月境界のフレーク回避)
        _db.Incidents.Add(MakeIncident(occurredAt: DateTime.Today.AddHours(3)));
        _db.Incidents.Add(MakeIncident(occurredAt: DateTime.Today.AddHours(15)));
        await _db.SaveChangesAsync();

        // dateFrom を当日正午にして、午前発生分だけを除外する
        var result = await _controller.MonthlyTrend(DateTime.Today.AddHours(12), null, null);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();
        // dateFrom 以降の午後発生分 1 件だけが今月のカウントに含まれることを確認する
        Assert.Equal(1, data[^1].GetInt32());
    }

    [Fact]
    public async Task ByDepartment_ReturnsGroupedCounts()
    {
        _db.Incidents.AddRange(
            MakeIncident(dept: "ICU"),
            MakeIncident(dept: "ICU"),
            MakeIncident(dept: "外来"));
        await _db.SaveChangesAsync();

        var result = await _controller.ByDepartment(null, null);
        using var doc = ToJsonDocument(result);

        var labels = doc.RootElement.GetProperty("labels").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();

        Assert.Equal(2, labels.Count);
        Assert.Equal("ICU", labels[0]);
        Assert.Equal(2, data[0]);
        Assert.Equal("外来", labels[1]);
        Assert.Equal(1, data[1]);
    }

    [Fact]
    public async Task BySeverity_AlwaysReturnsAllSevenLevelsInOrder()
    {
        _db.Incidents.Add(MakeIncident(severity: IncidentSeverity.Level2));
        _db.Incidents.Add(MakeIncident(severity: IncidentSeverity.Level4));
        await _db.SaveChangesAsync();

        var result = await _controller.BySeverity(null, null, null);
        using var doc = ToJsonDocument(result);

        var labels = doc.RootElement.GetProperty("labels").EnumerateArray().ToList();
        var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();

        Assert.Equal(7, labels.Count);
        Assert.Equal(7, data.Count);
        Assert.Equal(2, data.Sum(d => d.GetInt32()));
    }

    [Fact]
    public async Task MeasureStatus_ReturnsFourBucketsWithColors()
    {
        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        _db.PreventiveMeasures.AddRange(
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "A", MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = MeasureStatus.Planned, DueDate = DateTime.Today.AddDays(10)
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "B", MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = MeasureStatus.Completed, DueDate = DateTime.Today.AddDays(-5)
            });
        await _db.SaveChangesAsync();

        var result = await _controller.MeasureStatus();
        using var doc = ToJsonDocument(result);

        Assert.Equal(4, doc.RootElement.GetProperty("labels").GetArrayLength());
        Assert.Equal(4, doc.RootElement.GetProperty("data").GetArrayLength());
        Assert.Equal(4, doc.RootElement.GetProperty("colors").GetArrayLength());
    }

    // 分析画面のサマリー欄(Scripts/analytics.ts)は、位置ではなくラベル一致で
    // 「期限超過」「完了」バケットを引き当てる。ラベルの唯一の源は EnumLabels であり、
    // ここで日本語文字列を直書きし直すと EnumLabels 側の表記変更に追従できず、
    // サマリー欄が黙って「取得できません」に落ちる。EnumLabels 由来であることを固定する(§6)
    [Fact]
    public async Task MeasureStatus_LabelsComeFromEnumLabels_NotHardcodedStrings()
    {
        // 対策が 0 件でもラベル配列は常に 4 バケット分返る(件数だけが 0 になる)
        var result = await _controller.MeasureStatus();
        using var doc = ToJsonDocument(result);

        // 返却されたラベル配列を文字列として取り出す
        var labels = doc.RootElement.GetProperty("labels").EnumerateArray()
            .Select(e => e.GetString())
            .ToList();

        // 3 つの enum ラベルは EnumLabels.Japanese(MeasureStatus) と一致すること
        Assert.Equal(EnumLabels.Japanese(MeasureStatus.Planned), labels[0]);
        Assert.Equal(EnumLabels.Japanese(MeasureStatus.InProgress), labels[1]);
        // enum に無い派生バケットは EnumLabels.MeasureOverdueLabel を唯一の源とすること
        Assert.Equal(EnumLabels.MeasureOverdueLabel, labels[2]);
        Assert.Equal(EnumLabels.Japanese(MeasureStatus.Completed), labels[3]);
    }

    [Fact]
    public async Task EffectivenessRating_ReturnsFiveBucketsAndRecurrenceStats()
    {
        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _db.PreventiveMeasures.AddRange(
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "A", MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = MeasureStatus.Completed, DueDate = DateTime.Today,
                EffectivenessRating = 5, RecurrenceObserved = false
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "B", MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = MeasureStatus.Completed, DueDate = DateTime.Today,
                EffectivenessRating = 2, RecurrenceObserved = true
            });
        await _db.SaveChangesAsync();

        var result = await _controller.EffectivenessRating();
        using var doc = ToJsonDocument(result);

        // バケット数は EffectivenessScale(段階数の唯一の源)と一致すること。
        // 数値を直書きすると、段階を増やしたときにテストだけが古い本数を要求してしまう
        var expectedBucketCount = EffectivenessScale.All.Count();
        Assert.Equal(expectedBucketCount, doc.RootElement.GetProperty("labels").GetArrayLength());
        Assert.Equal(expectedBucketCount, doc.RootElement.GetProperty("data").GetArrayLength());
        Assert.Equal(1, doc.RootElement.GetProperty("recurrenceStats").GetProperty("recurred").GetInt32());
        Assert.Equal(1, doc.RootElement.GetProperty("recurrenceStats").GetProperty("prevented").GetInt32());
    }

    // 有効性評価グラフのラベル・配色が EffectivenessScale / EnumLabels 由来であることを固定する。
    // 以前はコントローラが「★1 (効果なし)」等を直書きし、配色は analytics.ts が 16 進値で
    // 持っていたため、語彙や配色を変えると画面ごとに食い違った(CLAUDE.md §6)
    [Fact]
    public async Task EffectivenessRating_LabelsAndColors_ComeFromCentralSource()
    {
        var result = await _controller.EffectivenessRating();
        using var doc = ToJsonDocument(result);

        // 期待するラベル列を尺度から組み立てる(取り出し側が string? なので合わせる)
        var expectedLabels = EffectivenessScale.All.Select(r => (string?)EffectivenessScale.ChartLabel(r)).ToList();
        // 実際に返ってきたラベル列を取り出す
        var actualLabels = doc.RootElement.GetProperty("labels").EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Equal(expectedLabels, actualLabels);

        // 期待する配色列を尺度 → EnumLabels.Hex の順で解決する(取り出し側が string? なので合わせる)
        var expectedColors = EffectivenessScale.All
            .Select(r => (string?)EnumLabels.Hex(EffectivenessScale.ColorName(r)))
            .ToList();
        // 実際に返ってきた配色列を取り出す
        var actualColors = doc.RootElement.GetProperty("colors").EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Equal(expectedColors, actualColors);
    }

    [Fact]
    public async Task ByIncidentType_ReturnsOrderedCounts()
    {
        _db.Incidents.AddRange(
            MakeIncident(type: IncidentTypeKind.Medication),
            MakeIncident(type: IncidentTypeKind.Medication),
            MakeIncident(type: IncidentTypeKind.Fall));
        await _db.SaveChangesAsync();

        var result = await _controller.ByIncidentType(null, null);
        using var doc = ToJsonDocument(result);

        var labels = doc.RootElement.GetProperty("labels").EnumerateArray()
            .Select(e => e.GetString()).ToList();
        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();

        Assert.Equal("投薬ミス", labels[0]);
        Assert.Equal(2, data[0]);
    }

    // Regression tests for #27: `dateTo` must include incidents that occurred
    // later in the same calendar day, not just those at 00:00.
    [Fact]
    public async Task ByDepartment_DateTo_IncludesSameDayAfternoonIncident()
    {
        var dateTo = new DateTime(2026, 4, 17);
        _db.Incidents.Add(MakeIncident(dept: "ICU",
            occurredAt: dateTo.AddHours(14)));
        _db.Incidents.Add(MakeIncident(dept: "ICU",
            occurredAt: dateTo.AddDays(1)));
        await _db.SaveChangesAsync();

        var result = await _controller.ByDepartment(null, dateTo);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();
        Assert.Single(data);
        Assert.Equal(1, data[0]);
    }

    [Fact]
    public async Task ByDepartment_DateToMaxValueDate_DoesNotThrow_AndIncludesLastDay()
    {
        // 発生日が表現可能な最終日(9999-12-31)のインシデントを投入する
        _db.Incidents.Add(MakeIncident(dept: "ICU", occurredAt: DateTime.MaxValue.Date));
        await _db.SaveChangesAsync();

        // 以前は dateTo=9999-12-31 で Date.AddDays(1) が ArgumentOutOfRangeException(HTTP 500)
        // を投げていた。修正後は例外なく処理され、最終日の発生分も含めて集計されることを確認する
        var result = await _controller.ByDepartment(null, DateTime.MaxValue.Date);
        using var doc = ToJsonDocument(result);

        // 件数配列を取り出す
        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();
        // 最終日の 1 件が上限フィルタに含まれること
        Assert.Single(data);
        Assert.Equal(1, data[0]);
    }

    [Fact]
    public async Task BySeverity_DateTo_IncludesSameDayAfternoonIncident()
    {
        var dateTo = new DateTime(2026, 4, 17);
        _db.Incidents.Add(MakeIncident(occurredAt: dateTo.AddHours(23).AddMinutes(59)));
        await _db.SaveChangesAsync();

        var result = await _controller.BySeverity(null, dateTo, null);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();
        Assert.Equal(1, data.Sum());
    }

    [Fact]
    public async Task ByIncidentType_DateTo_IncludesSameDayAfternoonIncident()
    {
        var dateTo = new DateTime(2026, 4, 17);
        _db.Incidents.Add(MakeIncident(occurredAt: dateTo.AddHours(10)));
        await _db.SaveChangesAsync();

        var result = await _controller.ByIncidentType(null, dateTo);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();
        Assert.Single(data);
        Assert.Equal(1, data[0]);
    }

    [Fact]
    public async Task ByCause_DateTo_IncludesSameDayAfternoonIncident()
    {
        var dateTo = new DateTime(2026, 4, 17);
        var category = new CauseCategory { Name = "ヒューマン", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var sameDay = MakeIncident(occurredAt: dateTo.AddHours(15));
        var nextDay = MakeIncident(occurredAt: dateTo.AddDays(1));
        _db.Incidents.AddRange(sameDay, nextDay);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = sameDay.Id, CauseCategoryId = category.Id, Why1 = "x" },
            new CauseAnalysis { IncidentId = nextDay.Id, CauseCategoryId = category.Id, Why1 = "y" });
        await _db.SaveChangesAsync();

        var result = await _controller.ByCause(null, dateTo, null);
        using var doc = ToJsonDocument(result);

        var data = doc.RootElement.GetProperty("data").EnumerateArray()
            .Select(e => e.GetInt32()).ToList();
        Assert.Single(data);
        Assert.Equal(1, data[0]);
    }
}
