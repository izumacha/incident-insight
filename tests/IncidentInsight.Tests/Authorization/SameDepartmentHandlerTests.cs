using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.AspNetCore.Authorization;

namespace IncidentInsight.Tests.Authorization;

public class SameDepartmentHandlerTests
{
    private static Incident IncidentIn(string dept) => new()
    {
        Department = dept,
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト",
        ReporterName = "テスト太郎",
        OccurredAt = DateTime.Now
    };

    private static async Task<bool> RunAsync(SameDepartmentHandler handler,
        System.Security.Claims.ClaimsPrincipal user, object? resource)
    {
        var requirement = new SameDepartmentRequirement();
        var context = new AuthorizationHandlerContext(
            new[] { requirement }, user, resource);
        await handler.HandleAsync(context);
        return context.HasSucceeded;
    }

    [Fact]
    public async Task Admin_Succeeds_RegardlessOfDepartment()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.Admin();

        Assert.True(await RunAsync(handler, user, IncidentIn("外来")));
    }

    [Fact]
    public async Task RiskManager_Succeeds_RegardlessOfDepartment()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.RiskManager();

        Assert.True(await RunAsync(handler, user, IncidentIn("ICU")));
    }

    [Fact]
    public async Task Staff_SameDepartment_Succeeds()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.Staff("内科病棟");

        Assert.True(await RunAsync(handler, user, IncidentIn("内科病棟")));
    }

    [Fact]
    public async Task Staff_DifferentDepartment_Fails()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.Staff("内科病棟");

        Assert.False(await RunAsync(handler, user, IncidentIn("外来")));
    }

    [Fact]
    public async Task Staff_NoDepartmentClaim_Fails()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.Build(AppRoles.Staff, department: null);

        Assert.False(await RunAsync(handler, user, IncidentIn("内科病棟")));
    }

    [Fact]
    public async Task Staff_PreventiveMeasureResource_UsesIncidentDepartment()
    {
        var handler = new SameDepartmentHandler();
        var user = UserContextHelper.Staff("内科病棟");

        var measure = new PreventiveMeasure
        {
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = "内科病棟",
            DueDate = DateTime.Today,
            Incident = IncidentIn("外来") // Incident の部署が違うので不許可
        };

        Assert.False(await RunAsync(handler, user, measure));
    }
}
