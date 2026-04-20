// 自プロジェクトのモデル(Incident / PreventiveMeasure など)を使う
using IncidentInsight.Web.Models;
// 認可の基盤クラスを使う
using Microsoft.AspNetCore.Authorization;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Authorization;

/// <summary>
/// <see cref="SameDepartmentRequirement"/> をリソース型別に検証するハンドラ。
/// Admin / RiskManager は常に許可。Staff は <see cref="ApplicationUser.Department"/>
/// クレームとリソースの Department が一致した場合のみ許可。
/// </summary>
/// <remarks>
/// 認可の判定基準は **インシデントの発生部署** (<c>Incident.Department</c>)。
/// <see cref="PreventiveMeasure"/> / <see cref="CauseAnalysis"/> をリソースに渡す場合は、
/// 呼び出し側で <c>.Include(x =&gt; x.Incident)</c> を付けてナビゲーションを eager-load すること。
/// <see cref="PreventiveMeasure.ResponsibleDepartment"/> は「対策を担当する部署」であって
/// 発生部署とは別概念のため、認可基準に混入してはならない
/// (フォールバックすると silent な認可バグになる — Issue #29)。
/// Incident が未ロードの場合は fail-closed で拒否する。
/// </remarks>
public sealed class SameDepartmentHandler : AuthorizationHandler<SameDepartmentRequirement>
{
    // 認可要件を実際にチェックする処理本体
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SameDepartmentRequirement requirement)
    {
        // 管理者・リスクマネージャーは全部署横断で許可
        if (context.User.IsInRole(AppRoles.Admin) || context.User.IsInRole(AppRoles.RiskManager))
        {
            // 要件を満たしたと通知して終了
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // ユーザーの部署クレームを取り出す
        var userDept = context.User.FindFirst(AppClaimTypes.Department)?.Value;
        // 部署が無ければ Succeed を呼ばずに終了(fail-closed で拒否)
        if (string.IsNullOrWhiteSpace(userDept))
        {
            // 部署不明の Staff は他部署にアクセスできない
            return Task.CompletedTask;
        }

        // Incident が未ロードのケースは null のままとし、下流で fail-closed で弾く。
        // ResponsibleDepartment へのフォールバックは意図的に行わない (Issue #29)。
        // リソースの種類ごとに、判定に使う「発生部署」を取り出す
        var resourceDept = context.Resource switch
        {
            // インシデントそのもの → その発生部署
            Incident inc              => inc.Department,
            // 再発防止策 → 紐づくインシデントの発生部署(未ロードなら null)
            PreventiveMeasure measure => measure.Incident?.Department,
            // なぜなぜ分析 → 紐づくインシデントの発生部署(未ロードなら null)
            CauseAnalysis analysis    => analysis.Incident?.Department,
            // 直接部署名文字列が渡された場合
            string deptString         => deptString,
            // それ以外は許可しない
            _                         => null
        };

        // 部署が取得でき、かつ自分の部署と完全一致する場合のみ許可
        if (!string.IsNullOrWhiteSpace(resourceDept)
            && string.Equals(resourceDept, userDept, StringComparison.Ordinal))
        {
            // 要件を満たしたと通知
            context.Succeed(requirement);
        }

        // 判定処理を終了(Succeed が呼ばれていなければ拒否扱いになる)
        return Task.CompletedTask;
    }
}
