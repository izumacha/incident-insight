using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Authorization;

public class DepartmentScopeTests : IDisposable
{
    private readonly ApplicationDbContext _db;

    public DepartmentScopeTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
    }

    public void Dispose() => _db.Dispose();

    private async Task SeedAsync()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "内科病棟", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "内科病棟", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "C", ReporterName = "C", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();
    }

    [Fact]
    public async Task Admin_SeesAllIncidents()
    {
        await SeedAsync();
        var list = await _db.Incidents.ScopedByUser(UserContextHelper.Admin()).ToListAsync();
        Assert.Equal(3, list.Count);
    }

    [Fact]
    public async Task RiskManager_SeesAllIncidents()
    {
        await SeedAsync();
        var list = await _db.Incidents.ScopedByUser(UserContextHelper.RiskManager()).ToListAsync();
        Assert.Equal(3, list.Count);
    }

    [Fact]
    public async Task Staff_SeesOnlyOwnDepartment()
    {
        await SeedAsync();
        var list = await _db.Incidents.ScopedByUser(UserContextHelper.Staff("内科病棟")).ToListAsync();
        Assert.Equal(2, list.Count);
        Assert.All(list, i => Assert.Equal("内科病棟", i.Department));
    }

    [Fact]
    public async Task Staff_WithoutDepartmentClaim_SeesNothing()
    {
        await SeedAsync();
        var user = UserContextHelper.Build(AppRoles.Staff, department: null);
        var list = await _db.Incidents.ScopedByUser(user).ToListAsync();
        Assert.Empty(list);
    }

    [Fact]
    public async Task PreventiveMeasure_ScopedByIncidentDepartment()
    {
        var inc1 = new Incident { Department = "内科病棟", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = DateTime.Now };
        var inc2 = new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = DateTime.Now };
        _db.Incidents.AddRange(inc1, inc2);
        await _db.SaveChangesAsync();

        _db.PreventiveMeasures.AddRange(
            new PreventiveMeasure { IncidentId = inc1.Id, Description = "m1", MeasureType = MeasureTypeKind.ShortTerm, ResponsiblePerson = "x", ResponsibleDepartment = "内科病棟", DueDate = DateTime.Today },
            new PreventiveMeasure { IncidentId = inc2.Id, Description = "m2", MeasureType = MeasureTypeKind.ShortTerm, ResponsiblePerson = "y", ResponsibleDepartment = "外来",     DueDate = DateTime.Today }
        );
        await _db.SaveChangesAsync();

        var list = await _db.PreventiveMeasures.ScopedByUser(UserContextHelper.Staff("内科病棟")).ToListAsync();
        Assert.Single(list);
        Assert.Equal("m1", list[0].Description);
    }
}
