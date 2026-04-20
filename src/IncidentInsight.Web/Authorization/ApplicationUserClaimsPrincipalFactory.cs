// Claim(ClaimsIdentity など)を使うためのライブラリ
using System.Security.Claims;
// 自プロジェクトのユーザー型を使う
using IncidentInsight.Web.Models;
// Identity の UserManager などを使う
using Microsoft.AspNetCore.Identity;
// IOptions を使う
using Microsoft.Extensions.Options;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Authorization;

/// <summary>
/// ログイン時に <see cref="ApplicationUser.Department"/> を Claim として Principal に埋め込む。
/// これを使って Policy ハンドラ / <see cref="DepartmentScope"/> が部署一致を判定する。
/// </summary>
public sealed class ApplicationUserClaimsPrincipalFactory
    : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
{
    // コンストラクタ: DI コンテナから Identity の依存を受け取って親クラスに渡す
    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, roleManager, optionsAccessor)
    {
    }

    // ログイン時に ClaimsIdentity を組み立てる本処理
    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        // 既定のクレーム(ID・メールなど)を親クラスで先に作る
        var identity = await base.GenerateClaimsAsync(user);
        // 部署が設定されているユーザーのみ部署クレームを追加
        if (!string.IsNullOrWhiteSpace(user.Department))
        {
            // 自社独自の「部署」クレームを追加(認可時に参照する)
            identity.AddClaim(new Claim(AppClaimTypes.Department, user.Department));
        }
        // 完成したクレーム情報を返す
        return identity;
    }
}
