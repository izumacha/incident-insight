using System.Reflection;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Controllers;
using Microsoft.AspNetCore.Authorization;

namespace IncidentInsight.Tests.Controllers;

// Guard-rail tests: enforce that [Authorize] stays on app controllers and that
// login endpoints remain [AllowAnonymous]. A developer accidentally removing
// [Authorize] on a controller that handles patient-sensitive data would be a
// security regression; these tests make that impossible to land silently.
public class AuthorizationAttributeTests
{
    [Theory]
    [InlineData(typeof(HomeController))]
    [InlineData(typeof(IncidentsController))]
    [InlineData(typeof(PreventiveMeasuresController))]
    [InlineData(typeof(AnalyticsController))]
    public void AppController_HasAuthorizeAttribute(Type controllerType)
    {
        var attr = controllerType.GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.NotNull(attr);
    }

    [Fact]
    public void AccountController_HasNoClassLevelAuthorizeAttribute()
    {
        // AccountController must not require auth at class level — otherwise login
        // would be unreachable. Anonymous endpoints are opted in per-action below.
        var attr = typeof(AccountController).GetCustomAttribute<AuthorizeAttribute>(inherit: false);
        Assert.Null(attr);
    }

    [Fact]
    public void AccountController_LoginGet_IsAllowAnonymous()
    {
        var method = typeof(AccountController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .First(m => m.Name == nameof(AccountController.Login)
                && m.GetParameters().Length == 1
                && m.GetParameters()[0].ParameterType == typeof(string));

        Assert.NotNull(method.GetCustomAttribute<AllowAnonymousAttribute>(inherit: false));
    }

    [Fact]
    public void AccountController_AccessDenied_IsAllowAnonymous()
    {
        var method = typeof(AccountController)
            .GetMethod(nameof(AccountController.AccessDenied));

        Assert.NotNull(method);
        Assert.NotNull(method!.GetCustomAttribute<AllowAnonymousAttribute>(inherit: false));
    }

    [Theory]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.Create))]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.Edit))]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.Delete))]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.AddMeasure))]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.CompleteMeasure))]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.RateMeasure))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.Create))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.Edit))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.Complete))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.Review))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.UpdateStatus))]
    public void MutatingAction_HasValidateAntiForgeryToken(Type controllerType, string actionName)
    {
        var postMethods = controllerType
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .Where(m => m.Name == actionName
                && m.GetCustomAttribute<Microsoft.AspNetCore.Mvc.HttpPostAttribute>() != null)
            .ToList();

        Assert.NotEmpty(postMethods);
        Assert.All(postMethods, m =>
            Assert.NotNull(m.GetCustomAttribute<Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute>()));
    }

    // Policy guard-rails: make sure the restrictive policies stay pinned to the
    // controllers/actions they were designed for, so a refactor can't drop
    // department scoping or role gating silently.
    [Fact]
    public void AnalyticsController_RequiresCanViewAnalyticsPolicy()
    {
        var attr = typeof(AnalyticsController).GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.NotNull(attr);
        Assert.Equal(Policies.CanViewAnalytics, attr!.Policy);
    }

    [Theory]
    [InlineData(typeof(IncidentsController), nameof(IncidentsController.Delete))]
    [InlineData(typeof(PreventiveMeasuresController), nameof(PreventiveMeasuresController.Delete))]
    public void DeleteAction_RequiresCanDeleteIncidentPolicy(Type controllerType, string actionName)
    {
        var method = controllerType
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .First(m => m.Name == actionName
                && m.GetCustomAttribute<Microsoft.AspNetCore.Mvc.HttpPostAttribute>() != null);

        var attr = method.GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.NotNull(attr);
        Assert.Equal(Policies.CanDeleteIncident, attr!.Policy);
    }
}
