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
    // 集計期間を識別する文字列定数（クエリパラメータと View のラベルで共用）
    private const string PeriodWeek    = "week";    // 直近 7 日間
    private const string PeriodMonth   = "month";   // 直近 1 か月
    private const string PeriodQuarter = "quarter"; // 直近 3 か月
    private const string PeriodYear    = "year";    // 直近 1 年（既定値）

    // ダッシュボードの「期限超過の対策一覧」アラートパネルに列挙する最大件数。
    // このパネルは全件を見せる画面ではなく代表例を数件示すだけの用途で、Views/Home/Index.cshtml
    // 側にも「カンバン全件表示へ」という導線がある(全件は PreventiveMeasuresController.Index の
    // MaxKanbanRows で上限管理済み)。以前はここで上限を付けずに期限超過対策を全件 DB から取得し、
    // View 側で Take(5) して表示件数だけ絞っていたため、期限超過対策が積み上がるほど
    // ダッシュボード(ログイン後の着地ページ)読み込みが重くなる無制限取得だった(§8/§9)。
    // View の Take(5) と重複していた「5」をここへ一本化し、クエリ自体を上限付きにする。
    // PreventiveMeasuresController.MaxKanbanRows と同様、テストと View 双方から参照できるよう public にする
    // (単一の参照元にするための§6要件。private だとテスト側で値を再度ハードコードする必要が出てしまう)。
    public const int OverdueAlertLimit = 5;

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
        period ??= PeriodYear;
        // 今日の日付(JST)
        var today = _clock.Today;
        // 今月の 1 日(月次集計の基準)
        var thisMonthStart = new DateTime(today.Year, today.Month, 1);

        // Period window for KPIs and trend chart
        // 期間指定(week/month/quarter/year)から集計開始日を算出。
        // week は KPI とトレンドチャート(下の weekStart = today.AddDays(-6))を
        // 同じ「直近7暦日(today-6〜today)」窓に揃える。month/quarter/year は
        // チャート側の窓を意図的にKPI期間より広く取る設計(下のコメント参照)だが、
        // week だけは "直近7日間" というコメント通りの同一窓であるべきで、
        // 以前は today.AddDays(-7) で実質8暦日分を数えており、境界日(today-7)の
        // インシデントが KPI 合計には含まれるのに折れ線グラフには表示されない
        // (グラフはtoday-6以降しか集計しない)という不整合があった。
        var periodStart = period switch
        {
            PeriodWeek    => today.AddDays(-6),
            PeriodMonth   => today.AddMonths(-1),
            PeriodQuarter => today.AddMonths(-3),
            _             => today.AddYears(-1)    // PeriodYear が既定
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
        // 期限超過の対策件数(未完了 かつ 期限が今日より前)。判定は唯一の定義 OverdueOn に委譲
        var overdueMeasures = await measures
            .CountAsync(PreventiveMeasure.OverdueOn(today));
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

        // 期限超過の対策一覧を期限日の古い順に取得(インシデントも eager-load)。判定は OverdueOn に委譲。
        // アラートパネルには代表例(OverdueAlertLimit件)だけ見せれば十分なため、ここで Take して
        // 上限を超える分は DB 側で切り捨てる(§8 一覧取得は必ず上限を持たせる)。
        // KPI の「期限超過対策」件数(OverdueMeasures)は上のCountAsyncで別途正確に数えているため、
        // ここで件数を絞っても KPI 表示の正確さには影響しない。
        var overdueMeasureList = await measures
            .Include(m => m.Incident)
            .Where(PreventiveMeasure.OverdueOn(today))
            .OrderBy(m => m.DueDate)
            .Take(OverdueAlertLimit)
            .ToListAsync();

        // Trend chart is aggregated SQL-side (GroupBy → Year/Month or Date) so the
        // controller never materializes full-table incident rows just to count them.
        // トレンドチャート用の件数バケットを溜めるリスト
        var monthlyCounts = new List<MonthlyCount>();
        // 週表示の場合は日別集計
        if (period == PeriodWeek)
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
            int months = period switch { PeriodMonth => 4, PeriodQuarter => 6, _ => 12 };
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
