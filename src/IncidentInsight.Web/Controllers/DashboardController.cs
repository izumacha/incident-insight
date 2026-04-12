using IncidentInsight.Web.Data;
using IncidentInsight.Web.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Controllers;

public class DashboardController(AppDbContext db) : Controller
{
    public async Task<IActionResult> Index()
    {
        var incidents = db.IncidentReports.AsQueryable();

        var categoryStats = await incidents
            .GroupBy(i => i.CauseCategory)
            .Select(g => new CategoryStat { Category = g.Key.ToString(), Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .ToListAsync();

        var sixMonthsAgo = DateTime.UtcNow.AddMonths(-5);
        var monthlyStatsRaw = await incidents
            .Where(i => i.OccurredAt >= sixMonthsAgo)
            .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
            .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
            .OrderBy(g => g.Year).ThenBy(g => g.Month)
            .ToListAsync();

        var departmentStats = await incidents
            .GroupBy(i => i.Department)
            .Select(g => new DepartmentStat { Department = g.Key, Count = g.Count() })
            .OrderByDescending(g => g.Count)
            .Take(5)
            .ToListAsync();

        var totalIncidents = await incidents.CountAsync();
        var highRiskCount = await incidents.CountAsync(i => i.RecurrenceRisk >= 4);

        var vm = new DashboardViewModel
        {
            TotalIncidents = totalIncidents,
            OpenCountermeasures = await db.Countermeasures.CountAsync(c => !c.IsCompleted),
            HighRiskRatio = totalIncidents == 0 ? 0 : Math.Round((double)highRiskCount / totalIncidents * 100, 1),
            CategoryStats = categoryStats,
            DepartmentStats = departmentStats,
            MonthlyStats = monthlyStatsRaw.Select(x => new MonthlyStat
            {
                Month = $"{x.Year}-{x.Month:D2}",
                Count = x.Count
            }).ToList(),
            FourVersionComparisons =
            [
                new VersionComparison
                {
                    VersionName = "Version 1: 報告",
                    Focus = "事実の漏れなく記録",
                    Indicator = "報告登録率 / 記載漏れ率",
                    ImprovementAction = "入力必須項目を標準化し、記録品質を底上げ"
                },
                new VersionComparison
                {
                    VersionName = "Version 2: 原因分析",
                    Focus = "根本原因の可視化",
                    Indicator = "原因分類の偏り / 5Why記載率",
                    ImprovementAction = "部署横断レビューでヒューマンエラー以外の要因を抽出"
                },
                new VersionComparison
                {
                    VersionName = "Version 3: 防止策実行",
                    Focus = "実行遅延の抑制",
                    Indicator = "未完了防止策数 / 期限遅延率",
                    ImprovementAction = "担当・期限を明確化し、週次フォローで停滞を解消"
                },
                new VersionComparison
                {
                    VersionName = "Version 4: 効果検証",
                    Focus = "再発防止の有効性確認",
                    Indicator = "再発率 / 有効性スコア",
                    ImprovementAction = "評価日・評価コメントを運用し、対策を継続改善"
                }
            ]
        };

        return View(vm);
    }
}
