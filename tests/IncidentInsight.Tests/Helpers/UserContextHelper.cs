using System.Security.Claims;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// Utility builders for wiring <see cref="ClaimsPrincipal"/> into controllers
/// under test — simulate Admin / RiskManager / Staff login with an optional
/// department claim.
/// </summary>
public static class UserContextHelper
{
    public static ClaimsPrincipal Build(string role, string? department = null, string userName = "tester")
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userName),
            new(ClaimTypes.NameIdentifier, userName),
            new(ClaimTypes.Role, role)
        };
        if (!string.IsNullOrWhiteSpace(department))
            claims.Add(new Claim(AppClaimTypes.Department, department));

        var identity = new ClaimsIdentity(claims, authenticationType: "TestAuth");
        return new ClaimsPrincipal(identity);
    }

    public static ClaimsPrincipal Admin() => Build(AppRoles.Admin);
    public static ClaimsPrincipal RiskManager() => Build(AppRoles.RiskManager);
    public static ClaimsPrincipal Staff(string department) => Build(AppRoles.Staff, department);

    /// <summary>
    /// Wires a ClaimsPrincipal into <paramref name="controller"/>.ControllerContext + TempData,
    /// and returns a real <see cref="IAuthorizationService"/> with <see cref="SameDepartmentHandler"/>
    /// registered so policy evaluation works during tests.
    /// </summary>
    public static IAuthorizationService BuildAuthService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddAuthorization(options =>
        {
            options.AddPolicy(Policies.CanViewAnalytics,
                p => p.RequireRole(AppRoles.Admin, AppRoles.RiskManager));
            options.AddPolicy(Policies.CanDeleteIncident,
                p => p.RequireRole(AppRoles.Admin, AppRoles.RiskManager));
            options.AddPolicy(Policies.CanEditIncident,
                p => p.AddRequirements(new SameDepartmentRequirement()));
            options.AddPolicy(Policies.CanViewIncident,
                p => p.AddRequirements(new SameDepartmentRequirement()));
        });
        services.AddSingleton<IAuthorizationHandler, SameDepartmentHandler>();
        var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IAuthorizationService>();
    }

    public static void AttachUser(Controller controller, ClaimsPrincipal user)
    {
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = user }
        };
        controller.TempData = new TestTempData();
    }
}
