using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Identity;

namespace IncidentInsight.Web.Data;

/// <summary>
/// 初回起動時にロールと管理者アカウントを作成する
/// </summary>
public static class IdentitySeeder
{
    public static async Task SeedAsync(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
    {
        // ロールを作成
        foreach (var role in AppRoles.All)
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // 管理者アカウントを作成（存在しない場合のみ）
        const string adminEmail = "admin@hospital.local";
        const string adminPassword = "Admin1234";

        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            var admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                DisplayName = "システム管理者",
                Department = "管理部門",
                EmailConfirmed = true
            };
            var result = await userManager.CreateAsync(admin, adminPassword);
            if (result.Succeeded)
                await userManager.AddToRoleAsync(admin, AppRoles.Admin);
        }

        // リスクマネージャーアカウントを作成（デモ用）
        const string rmEmail = "riskmanager@hospital.local";
        const string rmPassword = "Risk1234";

        if (await userManager.FindByEmailAsync(rmEmail) == null)
        {
            var rm = new ApplicationUser
            {
                UserName = rmEmail,
                Email = rmEmail,
                DisplayName = "リスクマネージャー",
                Department = "医療安全管理室",
                EmailConfirmed = true
            };
            var result = await userManager.CreateAsync(rm, rmPassword);
            if (result.Succeeded)
                await userManager.AddToRoleAsync(rm, AppRoles.RiskManager);
        }
    }
}
