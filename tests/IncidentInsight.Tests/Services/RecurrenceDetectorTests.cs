using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Services;

namespace IncidentInsight.Tests.Services;

public class RecurrenceDetectorTests
{
    private static Incident MakeIncident(int id, string dept, IncidentTypeKind type, params int[] categoryIds)
    {
        var incident = new Incident
        {
            Id = id,
            Department = dept,
            IncidentType = type,
            Severity = IncidentSeverity.Level1,
            Description = "テスト",
            ReporterName = "テスト太郎",
            OccurredAt = DateTime.Now,
            ReportedAt = DateTime.Now
        };
        foreach (var c in categoryIds)
        {
            incident.CauseAnalyses.Add(new CauseAnalysis { CauseCategoryId = c, Why1 = "why1" });
        }
        return incident;
    }

    [Fact]
    public void FindSimilar_ReturnsEmpty_WhenTargetHasNoCauseAnalyses()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication);
        var candidates = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 10) };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Empty(result);
    }

    [Fact]
    public void FindSimilar_ReturnsEmpty_WhenNoCauseCategoryOverlaps()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);
        var candidates = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 20) };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Empty(result);
    }

    [Fact]
    public void FindSimilar_ReturnsMatch_WhenDeptTypeAndCauseOverlap()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10, 11);
        var candidates = new[]
        {
            MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 11),   // match
            MakeIncident(3, "外科病棟", IncidentTypeKind.Medication, 10),   // diff dept
            MakeIncident(4, "内科病棟", IncidentTypeKind.Fall, 10),         // diff type
            MakeIncident(5, "内科病棟", IncidentTypeKind.Medication, 99)    // no overlap
        };

        var result = RecurrenceDetector.FindSimilar(target, candidates);

        Assert.Single(result);
        Assert.Equal(2, result[0].Id);
    }

    [Fact]
    public void FindSimilar_ExcludesTargetItself()
    {
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);
        var self = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10);

        var result = RecurrenceDetector.FindSimilar(target, new[] { self });

        Assert.Empty(result);
    }

    /// <summary>
    /// 基点に原因分類が 1 件も無ければ、重なった分類も 0 件になることを検証する。
    /// </summary>
    [Fact]
    public void FindSharedCauseCategoryIds_ReturnsEmpty_WhenTargetHasNoCauseAnalyses()
    {
        // 原因分類を持たない基点インシデントを作る
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication);
        // 分類を持つ類似インシデントを 1 件用意する
        var similar = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 10) };

        // 重なった分類 ID を取り出す
        var result = RecurrenceDetector.FindSharedCauseCategoryIds(RecurrenceDetector.CauseCategoryIdsOf(target), similar);

        // 基点に分類が無いので重なりようが無く、空になる
        Assert.Empty(result);
    }

    /// <summary>
    /// 基点にしか無い分類は返さず、実際に重なった分類だけを返すことを検証する。
    /// </summary>
    [Fact]
    public void FindSharedCauseCategoryIds_ReturnsOnlyOverlappingCategories()
    {
        // 基点は分類 10 と 11 を持つ
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10, 11);
        // 類似側は分類 11 だけを持つ（10 は重ならない）
        var similar = new[] { MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 11) };

        // 重なった分類 ID を取り出す
        var result = RecurrenceDetector.FindSharedCauseCategoryIds(RecurrenceDetector.CauseCategoryIdsOf(target), similar);

        // 重なった 11 だけが返ることを確認する
        Assert.Equal(new[] { 11 }, result);
    }

    /// <summary>
    /// 重なりの強い（共有する類似インシデントが多い）分類が先に並び、
    /// 同数のときは分類 ID の昇順になることを検証する。
    /// </summary>
    [Fact]
    public void FindSharedCauseCategoryIds_OrdersByShareCount_ThenById()
    {
        // 基点は分類 10・20・30 を持つ
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10, 20, 30);
        var similar = new[]
        {
            // 30 を 2 件が共有し、10 と 20 は 1 件ずつが共有する形にする
            MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 30, 10),
            MakeIncident(3, "内科病棟", IncidentTypeKind.Medication, 30, 20)
        };

        // 重なった分類 ID を取り出す
        var result = RecurrenceDetector.FindSharedCauseCategoryIds(RecurrenceDetector.CauseCategoryIdsOf(target), similar);

        // 共有数 2 の 30 が先頭、残りは共有数 1 で同数なので ID 昇順（10 → 20）
        Assert.Equal(new[] { 30, 10, 20 }, result);
    }

    /// <summary>
    /// 1 件のインシデントが同じ分類のなぜなぜ分析を複数持っていても、
    /// 共有数が二重に数えられないことを検証する（並び順が実態とずれないようにするため）。
    /// </summary>
    [Fact]
    public void FindSharedCauseCategoryIds_DoesNotDoubleCount_DuplicateAnalysesInOneIncident()
    {
        // 基点は分類 10 と 20 を持つ
        var target = MakeIncident(1, "内科病棟", IncidentTypeKind.Medication, 10, 20);
        var similar = new[]
        {
            // 1 件目は分類 10 のなぜなぜ分析を 2 件持つ（二重計上されれば共有数 2 に見えてしまう）
            MakeIncident(2, "内科病棟", IncidentTypeKind.Medication, 10, 10),
            // 2 件目は分類 20 を 1 件だけ持つ
            MakeIncident(3, "内科病棟", IncidentTypeKind.Medication, 20)
        };

        // 重なった分類 ID を取り出す
        var result = RecurrenceDetector.FindSharedCauseCategoryIds(RecurrenceDetector.CauseCategoryIdsOf(target), similar);

        // どちらも共有インシデント数は 1 なので、ID 昇順（10 → 20）に並ぶ
        Assert.Equal(new[] { 10, 20 }, result);
    }
}
