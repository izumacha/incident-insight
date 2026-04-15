using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

namespace IncidentInsight.Web.Data;

/// <summary>
/// 起動時にロールとデモアカウントを作成する。
/// デモアカウントは Development 環境かつ
/// appsettings.Development.json の SeedAccounts セクションが存在する場合のみ作成。
/// </summary>
public static class IdentitySeeder
{
    public static async Task SeedAsync(
        RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration)
    {
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var isDevelopment = string.Equals(environment, "Development", StringComparison.OrdinalIgnoreCase);

        // ロールを作成（全環境共通）
        foreach (var role in AppRoles.All)
        {
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // デモアカウントは Development かつ SeedAccounts 設定がある場合のみ作成
        if (!isDevelopment) return;

        var seedSection = configuration.GetSection("SeedAccounts");
        if (!seedSection.Exists()) return;

        var adminEmail    = seedSection["AdminEmail"];
        var adminPassword = seedSection["AdminPassword"];
        var rmEmail       = seedSection["RiskManagerEmail"];
        var rmPassword    = seedSection["RiskManagerPassword"];

        if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword)) return;

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

        if (!string.IsNullOrEmpty(rmEmail) && !string.IsNullOrEmpty(rmPassword)
            && await userManager.FindByEmailAsync(rmEmail) == null)
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
