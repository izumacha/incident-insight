using System.Reflection;
using IncidentInsight.Web.Authorization;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Models.RateLimiting;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;

namespace IncidentInsight.Tests.Controllers;

// Guard-rail tests: enforce that [Authorize] stays on app controllers and that
// login endpoints remain [AllowAnonymous]. A developer accidentally removing
// [Authorize] on a controller that handles patient-sensitive data would be a
// security regression; these tests make that impossible to land silently.
public class AuthorizationAttributeTests
{
    [Theory]
    [InlineData(typeof(HomeController))]           // ダッシュボード: 認証必須
    [InlineData(typeof(IncidentsController))]       // インシデント CRUD: 認証必須
    [InlineData(typeof(PreventiveMeasuresController))] // 予防策 kanban: 認証必須
    [InlineData(typeof(AnalyticsController))]       // 分析グラフ: 認証必須（CanViewAnalytics ポリシー）
    [InlineData(typeof(CauseAnalysesController))]   // 原因分析 CRUD: 認証必須
    [InlineData(typeof(AuditLogsController))]        // 監査ログ閲覧: 認証必須
    [InlineData(typeof(IncidentMeasuresController))] // インシデント詳細からのインライン操作: 認証必須
    public void AppController_HasAuthorizeAttribute(Type controllerType)
    {
        var attr = controllerType.GetCustomAttribute<AuthorizeAttribute>(inherit: true);
        Assert.NotNull(attr);
    }

    [Fact]
    public void AccountController_HasClassLevelAuthorizeAttribute()
    {
        // AccountController もクラス既定は [Authorize](fail-closed)。ログイン画面が
        // 到達不能になることはない: Login / AccessDenied はアクション単位の
        // [AllowAnonymous](下のテストで担保)がクラス属性より優先されるため。
        // クラス属性を外すと、将来アクションを追加したときに認可の付け忘れで
        // 匿名公開されてしまうリスクがあるので、既定拒否をここで固定する。
        var attr = typeof(AccountController).GetCustomAttribute<AuthorizeAttribute>(inherit: false);
        Assert.NotNull(attr);
    }

    [Fact]
    public void AccountController_LoginPost_IsAllowAnonymous()
    {
        // クラス既定 [Authorize] の下でログイン POST が到達可能であることを担保する
        var method = typeof(AccountController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .First(m => m.Name == nameof(AccountController.Login)
                && m.GetParameters().Length == 2);

        Assert.NotNull(method.GetCustomAttribute<AllowAnonymousAttribute>(inherit: false));
    }

    [Fact]
    public void AccountController_Logout_IsAllowAnonymous()
    {
        // Logout はクラス既定 [Authorize] の例外として [AllowAnonymous] を維持する。
        // 認証必須にすると、クッキー失効後のログアウト操作がログイン画面へ challenge され、
        // ログイン成功直後に POST 専用の /Account/Logout へ GET され 405 になるため。
        var method = typeof(AccountController).GetMethod(nameof(AccountController.Logout));

        Assert.NotNull(method);
        Assert.NotNull(method!.GetCustomAttribute<AllowAnonymousAttribute>(inherit: false));
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
    public void AccountController_LoginPost_HasLoginRateLimitPolicy()
    {
        // 匿名で叩ける資格情報検証エンドポイント(POST /Account/Login)には、
        // パスワードスプレー/ロックアウト DoS 対策の IP 単位レート制限が必須(CLAUDE.md §9)。
        // 属性が外れる回帰をここで検知する。ポリシー名は LoginRateLimitOptions.PolicyName
        // を唯一の定数として Program.cs 側の登録と一致させる(§6 一元管理)。
        var method = typeof(AccountController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .First(m => m.Name == nameof(AccountController.Login)
                && m.GetParameters().Length == 2);

        // レート制限属性が付いていることを確認する
        var attr = method.GetCustomAttribute<EnableRateLimitingAttribute>(inherit: false);
        Assert.NotNull(attr);
        // ポリシー名が Program.cs で登録される名前付きポリシーと一致することを確認する
        Assert.Equal(LoginRateLimitOptions.PolicyName, attr!.PolicyName);
    }

    [Fact]
    public void AccountController_LoginGet_And_Logout_DoNotHaveRateLimiting()
    {
        // レート制限は資格情報を検証する POST /Account/Login のみが対象。
        // GET(画面表示)や Logout に誤って広げると、正規ユーザーの画面表示や
        // サインアウトまで巻き添えで拒否されるため、付いていないことを固定する。
        var loginGet = typeof(AccountController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public)
            .First(m => m.Name == nameof(AccountController.Login)
                && m.GetParameters().Length == 1
                && m.GetParameters()[0].ParameterType == typeof(string));
        var logout = typeof(AccountController).GetMethod(nameof(AccountController.Logout));

        // GET Login にはレート制限属性が無いことを確認する
        Assert.Null(loginGet.GetCustomAttribute<EnableRateLimitingAttribute>(inherit: false));
        // Logout にもレート制限属性が無いことを確認する
        Assert.NotNull(logout);
        Assert.Null(logout!.GetCustomAttribute<EnableRateLimitingAttribute>(inherit: false));
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
    [InlineData(typeof(IncidentMeasuresController), nameof(IncidentMeasuresController.AddMeasure))]
    [InlineData(typeof(IncidentMeasuresController), nameof(IncidentMeasuresController.CompleteMeasure))]
    [InlineData(typeof(IncidentMeasuresController), nameof(IncidentMeasuresController.RateMeasure))]
    [InlineData(typeof(CauseAnalysesController), nameof(CauseAnalysesController.AddCauseAnalysis))]
    [InlineData(typeof(CauseAnalysesController), nameof(CauseAnalysesController.EditCauseAnalysis))]
    [InlineData(typeof(CauseAnalysesController), nameof(CauseAnalysesController.DeleteCauseAnalysis))]
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

    // Details.cshtml のインラインフォームは IncidentDetailViewModel のネストプロパティ
    // (NewMeasure / NewCauseAnalysis)経由で描画されるため、フィールド名は
    // 「NewMeasure.Description」のように prefix 付きで POST される。受け側アクションの
    // Bind(Prefix) がビューモデルのプロパティ名と一致していないと、バインダが空 prefix に
    // フォールバックして IncidentId が 0 のまま常に 404 になる。その契約をここで固定化する。
    [Theory]
    [InlineData(typeof(IncidentMeasuresController), nameof(IncidentMeasuresController.AddMeasure),
        nameof(IncidentDetailViewModel.NewMeasure))]
    [InlineData(typeof(CauseAnalysesController), nameof(CauseAnalysesController.AddCauseAnalysis),
        nameof(IncidentDetailViewModel.NewCauseAnalysis))]
    public void InlineDetailFormAction_BindsWithViewModelPropertyPrefix(
        Type controllerType, string actionName, string expectedPrefix)
    {
        var parameter = controllerType
            .GetMethod(actionName)!
            .GetParameters().Single();

        var bind = parameter.GetCustomAttribute<Microsoft.AspNetCore.Mvc.BindAttribute>(inherit: false);
        Assert.NotNull(bind);
        Assert.Equal(expectedPrefix, bind!.Prefix);
    }
}
