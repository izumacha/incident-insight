using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Controllers;

public class AuditLogsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly AuditLogsController _controller;

    public AuditLogsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new AuditLogsController(_db);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    private static AuditLog MakeLog(string entity = "Incident", string op = "Modified",
        string user = "admin", string key = "1", DateTime? at = null, string? json = null) => new()
    {
        EntityName = entity,
        Operation = op,
        ChangedBy = user,
        EntityKey = key,
        ChangedAt = at ?? DateTime.UtcNow,
        ChangesJson = json
    };

    // --- Index ---

    [Fact]
    public async Task Index_NoFilters_ReturnsAllLogsNewestFirst()
    {
        var older = MakeLog(at: DateTime.UtcNow.AddHours(-2), key: "1");
        var newer = MakeLog(at: DateTime.UtcNow, key: "2");
        _db.AuditLogs.AddRange(older, newer);
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null, null);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<AuditLogListViewModel>(view.Model);
        Assert.Equal(2, vm.TotalCount);
        Assert.Equal(2, vm.Logs.Count);
        Assert.Equal("2", vm.Logs[0].EntityKey);
        Assert.Equal("1", vm.Logs[1].EntityKey);
    }

    [Fact]
    public async Task Index_FilterByEntityName_LimitsResults()
    {
        _db.AuditLogs.AddRange(
            MakeLog(entity: "Incident"),
            MakeLog(entity: "PreventiveMeasure"),
            MakeLog(entity: "PreventiveMeasure"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index("PreventiveMeasure", null, null, null, null, null);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Equal(2, vm.TotalCount);
        Assert.All(vm.Logs, l => Assert.Equal("PreventiveMeasure", l.EntityName));
    }

    [Fact]
    public async Task Index_FilterByOperation_LimitsResults()
    {
        _db.AuditLogs.AddRange(
            MakeLog(op: "Added"),
            MakeLog(op: "Modified"),
            MakeLog(op: "Deleted"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, "Deleted", null, null, null, null);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Single(vm.Logs);
        Assert.Equal("Deleted", vm.Logs[0].Operation);
    }

    [Fact]
    public async Task Index_FilterByChangedBy_PartialMatch()
    {
        _db.AuditLogs.AddRange(
            MakeLog(user: "alice@example.com"),
            MakeLog(user: "bob@example.com"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, "alice", null, null, null);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Single(vm.Logs);
        Assert.Contains("alice", vm.Logs[0].ChangedBy);
    }

    [Fact]
    public async Task Index_FilterByEntityKey_ExactMatch()
    {
        _db.AuditLogs.AddRange(
            MakeLog(key: "10"),
            MakeLog(key: "100"),
            MakeLog(key: "10"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, "10", null, null);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Equal(2, vm.Logs.Count);
        Assert.All(vm.Logs, l => Assert.Equal("10", l.EntityKey));
    }

    [Fact]
    public async Task Index_FilterByDateRange_IncludesLastDay()
    {
        var t = new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);
        _db.AuditLogs.AddRange(
            MakeLog(at: t.AddDays(-2), key: "before"),
            MakeLog(at: t, key: "inside"),
            MakeLog(at: t.AddDays(2), key: "after"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null,
            dateFrom: t.AddDays(-1).Date, dateTo: t.AddDays(1).Date);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Single(vm.Logs);
        Assert.Equal("inside", vm.Logs[0].EntityKey);
    }

    [Fact]
    public async Task Index_RejectsUnknownEntityName_TreatsAsNoFilter()
    {
        // Entity-name filter is allowlisted server-side so URL tampering can't probe arbitrary tables.
        _db.AuditLogs.AddRange(MakeLog(entity: "Incident"), MakeLog(entity: "PreventiveMeasure"));
        await _db.SaveChangesAsync();

        var result = await _controller.Index("DROP TABLE users", null, null, null, null, null);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Equal(2, vm.TotalCount);
    }

    [Fact]
    public async Task Index_NegativePage_NormalizesToOne()
    {
        _db.AuditLogs.Add(MakeLog());
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null, null, page: -5);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        Assert.Equal(1, vm.Page);
    }

    [Theory]
    [InlineData(0)]              // ?page=0     : 補正しないと (0-1)*PageSize = 負の OFFSET
    [InlineData(-5)]            // ?page=-5    : 負数
    [InlineData(int.MaxValue)] // ?page=巨大 : (page-1)*PageSize が int 桁あふれで負値に化ける
    public async Task Index_OutOfRangePage_ClampsToFirstPageWithoutThrowing(int page)
    {
        // ページング境界(0・負数・巨大値)を投入する。
        // 補正しないと Skip((page-1)*PageSize) が負の OFFSET になり、
        // PostgreSQL / SQL Server では例外→500 になる(SQLite は 0 とみなすため見逃されやすい)。
        // ここではコントローラ側の Math.Clamp 補正で 1 ページ目にフォールバックすることを検証する。
        // (IncidentsController の同名テストと同じ不変条件を AuditLogs 側でも担保する)
        _db.AuditLogs.AddRange(MakeLog(key: "1"), MakeLog(key: "2"), MakeLog(key: "3"));
        await _db.SaveChangesAsync();

        // 範囲外のページ番号で一覧を要求する(例外を投げないこと自体が検証対象)
        var result = await _controller.Index(null, null, null, null, null, null, page: page);

        var vm = Assert.IsType<AuditLogListViewModel>(((ViewResult)result).Model);
        // 補正後のページ番号が 1(先頭ページ)であること
        Assert.Equal(1, vm.Page);
        // 先頭ページに全 3 件が漏れなく載ること(負の OFFSET で欠落していない)
        Assert.Equal(3, vm.TotalCount);
        Assert.Equal(3, vm.Logs.Count);
    }

    // --- Details ---

    [Fact]
    public async Task Details_UnknownId_Returns404()
    {
        var result = await _controller.Details(999);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Details_ParsesChangesJson_IntoRows()
    {
        var json = """{"Description":{"old":"A","new":"B"},"Severity":{"old":"Level1","new":"Level3"}}""";
        var log = MakeLog(json: json);
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(log.Id);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<AuditLogDetailViewModel>(view.Model);
        Assert.NotNull(vm.Changes);
        Assert.Equal(2, vm.Changes!.Count);
        // Sorted by property name (ordinal) so Description comes before Severity.
        Assert.Equal("Description", vm.Changes[0].PropertyName);
        Assert.Equal("A", vm.Changes[0].OldValue);
        Assert.Equal("B", vm.Changes[0].NewValue);
        Assert.Equal("Severity", vm.Changes[1].PropertyName);
    }

    [Fact]
    public async Task Details_NullValuesInJson_PreservedAsNull()
    {
        var json = """{"ImmediateActions":{"old":null,"new":"応急処置済み"}}""";
        var log = MakeLog(json: json);
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(log.Id);

        var vm = Assert.IsType<AuditLogDetailViewModel>(((ViewResult)result).Model);
        Assert.NotNull(vm.Changes);
        var row = Assert.Single(vm.Changes!);
        Assert.Null(row.OldValue);
        Assert.Equal("応急処置済み", row.NewValue);
    }

    [Fact]
    public async Task Details_MalformedJson_ReturnsNullChangesForFallback()
    {
        var log = MakeLog(json: "{not valid json");
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(log.Id);

        var vm = Assert.IsType<AuditLogDetailViewModel>(((ViewResult)result).Model);
        // Controller hands the raw JSON back so the view can render <pre>.
        Assert.Null(vm.Changes);
    }

    [Fact]
    public async Task Details_EmptyChangesJson_ReturnsNullChanges()
    {
        var log = MakeLog(json: null);
        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(log.Id);

        var vm = Assert.IsType<AuditLogDetailViewModel>(((ViewResult)result).Model);
        Assert.Null(vm.Changes);
    }
}
