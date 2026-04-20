// 自プロジェクトのモデル(ApplicationUser / AppRoles)を使う
using IncidentInsight.Web.Models;
// Identity の UserManager / RoleManager を使う
using Microsoft.AspNetCore.Identity;
// 設定(IConfiguration)読み込みを使う
using Microsoft.Extensions.Configuration;
// ログ出力を使う
using Microsoft.Extensions.Logging;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Data;

/// <summary>
/// 起動時にロールとデモアカウントを作成する。
/// デモアカウントは Development 環境かつ
/// appsettings.Development.json の SeedAccounts セクションが存在する場合のみ作成。
/// </summary>
public static class IdentitySeeder
{
    // 起動時に呼ばれる本体メソッド: ロール生成 + (開発時のみ)デモユーザー作成
    public static async Task SeedAsync(
        RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        ILogger? logger = null)
    {
        // 現在の環境名(Development / Production など)
        var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        // 開発環境かどうかのフラグ(大文字小文字を無視して比較)
        var isDevelopment = string.Equals(environment, "Development", StringComparison.OrdinalIgnoreCase);

        // ロールを作成（全環境共通）
        // 定義された全ロールを順に処理
        foreach (var role in AppRoles.All)
        {
            // 未作成のロールだけ新規作成
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));
        }

        // デモアカウントは Development かつ SeedAccounts 設定がある場合のみ作成
        // 本番環境ではここで終了
        if (!isDevelopment) return;

        // SeedAccounts セクションを取得
        var seedSection = configuration.GetSection("SeedAccounts");
        // セクションが無ければ何もせず終了
        if (!seedSection.Exists()) return;

        // 管理者アカウントの情報を取得
        var adminEmail    = seedSection["AdminEmail"];
        var adminPassword = seedSection["AdminPassword"];
        // リスクマネージャーアカウントの情報を取得
        var rmEmail       = seedSection["RiskManagerEmail"];
        var rmPassword    = seedSection["RiskManagerPassword"];

        // 管理者のメール or パスワードが未設定なら警告ログを出して終了
        if (string.IsNullOrEmpty(adminEmail) || string.IsNullOrEmpty(adminPassword))
        {
            logger?.LogWarning(
                "デモアカウントの作成をスキップしました。" +
                "appsettings.Development.json の SeedAccounts:AdminPassword が未設定です。" +
                "開発環境でログインするには、User Secrets またはローカルの appsettings.Development.json にパスワードを設定してください。" +
                "例: dotnet user-secrets set \"SeedAccounts:AdminPassword\" \"YourPassword1\" --project src/IncidentInsight.Web");
            return;
        }

        // 既存ユーザーがいない場合のみ管理者を新規作成
        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            // 新しい管理者ユーザーのインスタンスを作る
            var admin = new ApplicationUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                DisplayName = "システム管理者",
                Department = "管理部門",
                EmailConfirmed = true
            };
            // パスワード付きで作成(パスワードポリシーに合わない場合は失敗する)
            var result = await userManager.CreateAsync(admin, adminPassword);
            // 成功したら Admin ロールを割り当て
            if (result.Succeeded)
                await userManager.AddToRoleAsync(admin, AppRoles.Admin);
        }

        // リスクマネージャー設定があり、かつ未作成のときのみ作成
        if (!string.IsNullOrEmpty(rmEmail) && !string.IsNullOrEmpty(rmPassword)
            && await userManager.FindByEmailAsync(rmEmail) == null)
        {
            // リスクマネージャーユーザーのインスタンス
            var rm = new ApplicationUser
            {
                UserName = rmEmail,
                Email = rmEmail,
                DisplayName = "リスクマネージャー",
                Department = "医療安全管理室",
                EmailConfirmed = true
            };
            // パスワード付きで作成
            var result = await userManager.CreateAsync(rm, rmPassword);
            // 成功したら RiskManager ロールを割り当て
            if (result.Succeeded)
                await userManager.AddToRoleAsync(rm, AppRoles.RiskManager);
        }
    }
}
