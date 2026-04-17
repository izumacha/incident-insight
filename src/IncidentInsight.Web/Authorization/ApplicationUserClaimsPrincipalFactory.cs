using System.Security.Claims;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IncidentInsight.Web.Authorization;

/// <summary>
/// ログイン時に <see cref="ApplicationUser.Department"/> を Claim として Principal に埋め込む。
/// これを使って Policy ハンドラ / <see cref="DepartmentScope"/> が部署一致を判定する。
/// </summary>
public sealed class ApplicationUserClaimsPrincipalFactory
    : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
{
    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, roleManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        if (!string.IsNullOrWhiteSpace(user.Department))
        {
            identity.AddClaim(new Claim(AppClaimTypes.Department, user.Department));
        }
        return identity;
    }
}
