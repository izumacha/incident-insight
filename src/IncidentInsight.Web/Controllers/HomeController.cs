// Activity(トレース ID 取得)を使う
using System.Diagnostics;
// 部署スコープ拡張メソッドを使う
using IncidentInsight.Web.Authorization;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(Incidentなど)を使う
using IncidentInsight.Web.Models;
// enum を使う
using IncidentInsight.Web.Models.Enums;
// ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// 時刻源 / 再発サービスを使う
using IncidentInsight.Web.Services;
// 認可属性を使う
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底を使う
using Microsoft.AspNetCore.Mvc;
// EF Core 拡張を使う
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// ログイン必須でアクセスするダッシュボードコントローラ
[Authorize]
public class HomeController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // 再発検出ロジックのサービス
    private readonly IRecurrenceService _recurrence;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;

    // コンストラクタ: DI で依存を受け取る
    public HomeController(ApplicationDbContext db, IRecurrenceService recurrence, IClock clock)
    {
        _db = db;
        _recurrence = recurrence;
        _clock = clock;
    }

    // ダッシュボード画面。period で集計期間を切り替える
    public async Task<IActionResult> Index(string? period)
    {
        // period 未指定なら既定の「year」を使う
        period ??= "year";
        // 今日の日付(JST)
        var today = _clock.Today;
        // 今月の 1 日(月次集計の基準)
        var thisMonthStart = new DateTime(today.Year, today.Month, 1);

        // Period window for KPIs and trend chart
        // 期間指定(week/month/quarter/year)から集計開始日を算出
        var periodStart = period switch
        {
            "week"    => today.AddDays(-7),
            "month"   => today.AddMonths(-1),
            "quarter" => today.AddMonths(-3),
            _         => today.AddYears(-1)
        };

        // Staff は自部署のデータのみ。Admin / RiskManager はフィルタなし。
        // 読み取り専用クエリをユーザー部署スコープで絞る
        var incidents = _db.Incidents.AsNoTracking().ScopedByUser(User);
        // 対策側も同様に部署スコープで絞る
        var measures = _db.PreventiveMeasures.AsNoTracking().ScopedByUser(User);

        // KPI counts are aggregated server-side (no full-table materialization).
        // 期間内インシデント総数
        var totalIncidents = await incidents
            .CountAsync(i => i.OccurredAt >= periodStart);
        // 今月のインシデント件数
        var thisMonthIncidents = await incidents
            .CountAsync(i => i.OccurredAt >= thisMonthStart);
        // 未完了の対策件数
        var openMeasures = await measures
            .CountAsync(m => m.Status != MeasureStatus.Completed);
        // 期限超過の対策件数(未完了 かつ 期限が今日より前)
        var overdueMeasures = await measures
            .CountAsync(m => m.Status != MeasureStatus.Completed && m.DueDate < today);
        // 完了済みの対策件数
        var completedMeasures = await measures
            .CountAsync(m => m.Status == MeasureStatus.Completed);
        // 効果なしフラグが立っている対策件数(再発確認済み)
        var failedMeasures = await measures
            .CountAsync(m => m.RecurrenceObserved == true);

        // 最近のインシデント5件を発生日の新しい順に取得(関連も eager-load)
        var recentIncidents = await incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory)
            .Include(i => i.PreventiveMeasures)
            .OrderByDescending(i => i.OccurredAt)
            .Take(5)
            .ToListAsync();

        // 期限超過の対策一覧を期限日の古い順に取得(インシデントも eager-load)
        var overdueMeasureList = await measures
            .Include(m => m.Incident)
            .Where(m => m.Status != MeasureStatus.Completed && m.DueDate < today)
            .OrderBy(m => m.DueDate)
            .ToListAsync();

        // Trend chart is aggregated SQL-side (GroupBy → Year/Month or Date) so the
        // controller never materializes full-table incident rows just to count them.
        // トレンドチャート用の件数バケットを溜めるリスト
        var monthlyCounts = new List<MonthlyCount>();
        // 週表示の場合は日別集計
        if (period == "week")
        {
            // 過去 7 日間の範囲を作成
            var weekStart = today.AddDays(-6);
            var weekEnd = today.AddDays(1);
            // 日付ごとの件数を SQL 側でグループ化して取得
            var dailyGroups = await incidents
                .Where(i => i.OccurredAt >= weekStart && i.OccurredAt < weekEnd)
                .GroupBy(i => i.OccurredAt.Date)
                .Select(g => new { Day = g.Key, Count = g.Count() })
                .ToListAsync();
            // 高速検索用に辞書化
            var byDay = dailyGroups.ToDictionary(g => g.Day, g => g.Count);
            // 7 日間を古い方から順にラベル付きで並べる(無い日は 0 件として埋める)
            for (int i = 6; i >= 0; i--)
            {
                var day = today.AddDays(-i);
                byDay.TryGetValue(day, out var count);
                monthlyCounts.Add(new MonthlyCount { Label = day.ToString("M/d"), Count = count });
            }
        }
        // それ以外の期間は月別集計
        else
        {
            // 表示する月数(month=4, quarter=6, year=12)
            int months = period switch { "month" => 4, "quarter" => 6, _ => 12 };
            // 集計対象の最初の月の 1 日
            var firstMonthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-(months - 1));
            // 年月ごとの件数を SQL 側でグループ化して取得
            var monthlyGroups = await incidents
                .Where(i => i.OccurredAt >= firstMonthStart)
                .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
                .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
                .ToListAsync();
            // 高速検索用に (年,月) をキーに辞書化
            var byMonth = monthlyGroups.ToDictionary(g => (g.Year, g.Month), g => g.Count);
            // 古い月から順にラベル付きで並べる
            for (int i = months - 1; i >= 0; i--)
            {
                var monthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
                byMonth.TryGetValue((monthStart.Year, monthStart.Month), out var count);
                monthlyCounts.Add(new MonthlyCount { Label = monthStart.ToString("yyyy年M月"), Count = count });
            }
        }

        // 再発検出はサービスに集約。90 日ウィンドウは IncidentsController.Details (無制限) と
        // 業務ルールを揃えたまま、ダッシュボードでのみ時間窓を適用する。
        // 90 日以内の再発アラートを再発サービスから取得
        var recurrenceAlerts = await _recurrence.FindRecurrenceAlertsAsync(incidents, TimeSpan.FromDays(90));

        // ビュー用モデルに全ての KPI とリストを詰め込む
        var vm = new DashboardViewModel
        {
            Period = period,
            TotalIncidents = totalIncidents,
            ThisMonthIncidents = thisMonthIncidents,
            OpenMeasures = openMeasures,
            OverdueMeasures = overdueMeasures,
            CompletedMeasures = completedMeasures,
            FailedMeasures = failedMeasures,
            RecentIncidents = recentIncidents,
            OverdueMeasureList = overdueMeasureList,
            RecurrenceAlerts = recurrenceAlerts,
            MonthlyCounts = monthlyCounts
        };

        // ダッシュボードビューへモデルを渡して描画
        return View(vm);
    }

    // エラーページ。匿名アクセス可、キャッシュさせない
    [AllowAnonymous]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public IActionResult Error()
    {
        // リクエストを追跡できるようトレース ID を ViewModel に入れる
        var vm = new ErrorViewModel
        {
            RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
        };
        // エラービューを描画
        return View(vm);
    }
}
