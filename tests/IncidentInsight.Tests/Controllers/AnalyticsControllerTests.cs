using System.Text.Json;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
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
        _controller = new AnalyticsController(_db);
    }

    public void Dispose() => _db.Dispose();

    private static JsonDocument ToJsonDocument(IActionResult result)
    {
        var json = Assert.IsType<JsonResult>(result);
        var serialized = JsonSerializer.Serialize(json.Value);
        return JsonDocument.Parse(serialized);
    }

    private static Incident MakeIncident(string dept = "内科病棟", string type = "投薬ミス",
        string severity = "Level2", DateTime? occurredAt = null) => new()
    {
        Department = dept,
        IncidentType = type,
        Severity = severity,
        Description = "テスト",
        ReporterName = "テスト太郎",
        OccurredAt = occurredAt ?? DateTime.Now,
        ReportedAt = DateTime.Now
    };

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
        // Last entry corresponds to the current month.
        Assert.Equal(2, data[^1].GetInt32());
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
        // Ordered descending by count — "ICU" should be first.
        Assert.Equal("ICU", labels[0]);
        Assert.Equal(2, data[0]);
        Assert.Equal("外来", labels[1]);
        Assert.Equal(1, data[1]);
    }

    [Fact]
    public async Task BySeverity_AlwaysReturnsAllSevenLevelsInOrder()
    {
        _db.Incidents.Add(MakeIncident(severity: "Level2"));
        _db.Incidents.Add(MakeIncident(severity: "Level4"));
        await _db.SaveChangesAsync();

        var result = await _controller.BySeverity(null, null, null);
        using var doc = ToJsonDocument(result);

        var labels = doc.RootElement.GetProperty("labels").EnumerateArray().ToList();
        var data = doc.RootElement.GetProperty("data").EnumerateArray().ToList();

        // Severity chart should have 7 fixed slots regardless of data presence.
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
                IncidentId = incident.Id, Description = "A", MeasureType = "ShortTerm",
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = "Planned", DueDate = DateTime.Today.AddDays(10)
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "B", MeasureType = "ShortTerm",
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = "Completed", DueDate = DateTime.Today.AddDays(-5)
            });
        await _db.SaveChangesAsync();

        var result = await _controller.MeasureStatus();
        using var doc = ToJsonDocument(result);

        Assert.Equal(4, doc.RootElement.GetProperty("labels").GetArrayLength());
        Assert.Equal(4, doc.RootElement.GetProperty("data").GetArrayLength());
        Assert.Equal(4, doc.RootElement.GetProperty("colors").GetArrayLength());
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
                IncidentId = incident.Id, Description = "A", MeasureType = "ShortTerm",
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = "Completed", DueDate = DateTime.Today,
                EffectivenessRating = 5, RecurrenceObserved = false
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id, Description = "B", MeasureType = "ShortTerm",
                ResponsiblePerson = "x", ResponsibleDepartment = "y",
                Status = "Completed", DueDate = DateTime.Today,
                EffectivenessRating = 2, RecurrenceObserved = true
            });
        await _db.SaveChangesAsync();

        var result = await _controller.EffectivenessRating();
        using var doc = ToJsonDocument(result);

        Assert.Equal(5, doc.RootElement.GetProperty("labels").GetArrayLength());
        Assert.Equal(5, doc.RootElement.GetProperty("data").GetArrayLength());
        Assert.Equal(1, doc.RootElement.GetProperty("recurrenceStats").GetProperty("recurred").GetInt32());
        Assert.Equal(1, doc.RootElement.GetProperty("recurrenceStats").GetProperty("prevented").GetInt32());
    }

    [Fact]
    public async Task ByIncidentType_ReturnsOrderedCounts()
    {
        _db.Incidents.AddRange(
            MakeIncident(type: "投薬ミス"),
            MakeIncident(type: "投薬ミス"),
            MakeIncident(type: "転倒・転落"));
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

    [Fact]
    public async Task GetSubcategories_ReturnsChildrenOfParent()
    {
        var parent = new CauseCategory { Name = "ヒューマン", DisplayOrder = 1 };
        _db.CauseCategories.Add(parent);
        await _db.SaveChangesAsync();

        _db.CauseCategories.AddRange(
            new CauseCategory { Name = "注意不足", ParentId = parent.Id, DisplayOrder = 1 },
            new CauseCategory { Name = "確認不足", ParentId = parent.Id, DisplayOrder = 2 });
        await _db.SaveChangesAsync();

        var result = await _controller.GetSubcategories(parent.Id);
        using var doc = ToJsonDocument(result);

        var items = doc.RootElement.EnumerateArray().ToList();
        Assert.Equal(2, items.Count);
        // The controller projects `new { c.Id, c.Name }` so serialization preserves
        // the property names as-is (PascalCase). ASP.NET's Json() pipeline would
        // lowercase them, but here we serialize the raw anonymous type.
        Assert.Equal("注意不足", items[0].GetProperty("Name").GetString());
    }
}
