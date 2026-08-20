// InvariantCulture(期待値の日付書式を実行環境のロケール・暦設定に依存させない)を使う
using System.Globalization;
using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Controllers;

public class HomeControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly HomeController _controller;
    // コントローラと同じ時刻源をシードデータでも使う。SystemClock は JST を返すため、
    // シード側だけ _clock.Today(ホストのローカル日付。CI の UTC コンテナでは JST と
    // 1 日ずれうる)を使うと、日付境界をまたぐ時間帯にテストが不安定になる。
    private readonly IClock _clock = new SystemClock();

    public HomeControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new HomeController(_db, new RecurrenceService(_clock), _clock);
        // Existing tests assume a privileged viewer; Staff-scope tests build their own.
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    private Incident MakeIncident(string dept = "内科病棟",
        IncidentTypeKind type = IncidentTypeKind.Medication,
        IncidentSeverity severity = IncidentSeverity.Level2,
        DateTime? occurredAt = null) => new()
    {
        Department = dept,
        IncidentType = type,
        Severity = severity,
        Description = "テスト",
        ReporterName = "テスト太郎",
        OccurredAt = occurredAt ?? _clock.Now,
        ReportedAt = _clock.Now
    };

    [Fact]
    public async Task Index_EmptyDb_ReturnsDashboardWithZeroCounts()
    {
        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.NotNull(vm);
        Assert.Equal(0, vm.TotalIncidents);
        Assert.Equal(0, vm.OpenMeasures);
        Assert.Equal(0, vm.OverdueMeasures);
    }

    [Fact]
    public async Task Index_PeriodYear_CountsAllYearIncidents()
    {
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: _clock.Today.AddMonths(-6)),
            MakeIncident(occurredAt: _clock.Today.AddMonths(-11)),
            MakeIncident(occurredAt: _clock.Today.AddYears(-2))  // 期間外
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("year") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(2, vm!.TotalIncidents);
        Assert.Equal("year", vm.Period);
    }

    // 未知の period（URL 改ざん・古いブックマーク等）が渡されても、集計窓だけでなく
    // ViewModel.Period まで既定値 "year" へ丸められることを確認する。丸めないと
    // ダッシュボードの期間切替ボタンがどれも選択中に見えず、表示中のデータ（1 年分）と
    // UI の状態が食い違ってしまう
    [Theory]
    [InlineData("bogus")]   // 未知の文字列
    [InlineData("")]        // 空文字
    [InlineData("Year")]    // 大文字違い（定数と完全一致しないので既定へ丸める）
    public async Task Index_UnknownPeriod_FallsBackToYear(string period)
    {
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: _clock.Today.AddMonths(-6)),   // 1 年窓の内側
            MakeIncident(occurredAt: _clock.Today.AddYears(-2))     // 1 年窓の外側
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(period) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // ViewModel には既定値の "year" が入り、View の期間切替ボタンが正しく選択表示される
        Assert.Equal(DashboardViewModel.PeriodYear, vm!.Period);
        // 集計窓も 1 年として扱われる（2 年前の 1 件は数えない）
        Assert.Equal(1, vm.TotalIncidents);
    }

    [Fact]
    public async Task Index_PeriodMonth_CountsLastMonthOnly()
    {
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: _clock.Today.AddDays(-15)),  // 期間内
            MakeIncident(occurredAt: _clock.Today.AddMonths(-3))  // 期間外
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("month") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(1, vm!.TotalIncidents);
    }

    [Fact]
    public async Task Index_PeriodWeek_KpiWindowMatchesChartWindow()
    {
        // 回帰テスト: 以前は KPI(TotalIncidents)の集計開始日が today.AddDays(-7) で
        // 実質8暦日分(today-7〜today)を数えていたが、直下の折れ線グラフ(MonthlyCounts)は
        // today.AddDays(-6)で7暦日分(today-6〜today)しか集計しておらず、
        // ちょうど境界のtoday-7に発生したインシデントはKPI合計には含まれるのに
        // グラフの7本のバーには1件も現れないという不整合があった。
        // 修正後は両方とも同じ7暦日窓(today-6〜today)を使うため、today-7のインシデントは
        // KPIからも除外され、グラフの日数(7)と整合する。
        _db.Incidents.AddRange(
            MakeIncident(occurredAt: _clock.Today.AddDays(-7)),  // 窓の外(境界日の1日前)
            MakeIncident(occurredAt: _clock.Today.AddDays(-6))   // 窓の中(境界日)
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("week") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // today-7 のインシデントは除外され、today-6 の1件だけがKPIに数えられる
        Assert.Equal(1, vm!.TotalIncidents);
        // グラフ側も同じ1件だけを today-6 の日に計上している
        Assert.Equal(7, vm.MonthlyCounts.Count);
        Assert.Equal(1, vm.MonthlyCounts.Sum(c => c.Count));
    }

    [Fact]
    public async Task Index_OverdueMeasures_CountsOnlyNotCompleted()
    {
        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        _db.PreventiveMeasures.AddRange(
            new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = "対策A",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当A",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Planned,
                DueDate = _clock.Today.AddDays(-5)  // overdue
            },
            new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = "対策B",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当B",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Completed,
                DueDate = _clock.Today.AddDays(-10)  // completed は除外
            }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(1, vm!.OverdueMeasures);
        Assert.Equal(1, vm.OpenMeasures);
        Assert.Equal(1, vm.CompletedMeasures);
    }

    [Fact]
    public async Task Index_OverdueMeasureList_IsCappedButKpiCountReflectsFullTotal()
    {
        // 回帰テスト: 以前は「期限超過の対策一覧」パネル用のクエリに上限がなく、
        // 画面には Take(5) で 5 件しか出さないにもかかわらず DB からは期限超過対策を
        // 全件フェッチしていた(§8 一覧取得は必ず上限を持たせる、に反する無制限取得)。
        // ここでは HomeController.OverdueAlertLimit(5) を超える件数の期限超過対策を用意し、
        // (1) OverdueMeasureList が上限件数までしか含まれないこと、
        // (2) KPI の OverdueMeasures(件数)は上限に関わらず全件を正しく数えていること、
        // の両方を確認する。
        const int overdueCountInDb = HomeController.OverdueAlertLimit + 3; // 上限(public 定数を直接参照)より多く用意する

        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        for (int i = 0; i < overdueCountInDb; i++)
        {
            _db.PreventiveMeasures.Add(new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = $"対策{i}",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Planned,
                DueDate = _clock.Today.AddDays(-1 - i) // すべて期限超過、期限日はバラける
            });
        }
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // KPI の総数は上限を超えても正確に全件(overdueCountInDb)を反映する
        Assert.Equal(overdueCountInDb, vm!.OverdueMeasures);
        // 一覧パネルは OverdueAlertLimit 件までしか返さない(DB 側で切り捨て済み)
        Assert.Equal(HomeController.OverdueAlertLimit, vm.OverdueMeasureList.Count);
    }

    [Fact]
    public async Task Index_RecurrenceDetection_AlertsForSameDeptTypeCategory()
    {
        var category = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var inc1 = MakeIncident(dept: "外科病棟", type: IncidentTypeKind.Medication, occurredAt: _clock.Today.AddDays(-10));
        var inc2 = MakeIncident(dept: "外科病棟", type: IncidentTypeKind.Medication, occurredAt: _clock.Today.AddDays(-20));
        _db.Incidents.AddRange(inc1, inc2);
        await _db.SaveChangesAsync();

        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = inc1.Id, CauseCategoryId = category.Id, Why1 = "原因1" },
            new CauseAnalysis { IncidentId = inc2.Id, CauseCategoryId = category.Id, Why1 = "原因2" }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.NotEmpty(vm!.RecurrenceAlerts);
        Assert.Contains(vm.RecurrenceAlerts, a => a.PatternDescription.Contains("外科病棟"));
        // 上限に達していないときは「ほか N 件」を出さない(総数 = 表示件数)
        Assert.Equal(vm.RecurrenceAlerts.Count, vm.RecurrenceAlertTotal);
        Assert.Equal(0, vm.HiddenRecurrenceAlertCount);
    }

    [Fact]
    public async Task Index_RecurrenceAlerts_AreCappedButTotalReflectsFullCount()
    {
        // 回帰テスト: 以前は再発アラートに表示上限が無く、Views/Home/Index.cshtml が
        // 検出されたパターンを全件 <li> で列挙していた。再発が積み上がった環境では
        // ログイン直後の着地ページに長大なリストが伸び、KPI やトレンドが画面外へ押し出される
        // (§8 一覧取得は必ず上限を持たせる)。ここでは上限を超える数の再発パターンを用意し、
        // (1) RecurrenceAlerts が上限件数までしか含まれないこと、
        // (2) RecurrenceAlertTotal は上限に関わらず検出総数を保持すること、
        // (3) 差分が HiddenRecurrenceAlertCount(「ほか N 件」の表示元)になること、
        // の 3 点を確認する。
        // さらに (4) 打ち切りで残るのが「類似インシデントの多い」重大パターンであること
        // (発生日が新しいだけの軽微なパターンに押し出されないこと)も固定する。
        const int patternCount = HomeController.RecurrenceAlertLimit + 3; // 上限より多いパターン数

        // 原因分類は 1 つで足りる(パターンの区別は部署で付ける)
        var category = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        // 部署ごとに「同部署・同種別・同原因」のインシデント群を作り、1 部署 = 1 再発パターンにする
        // (部署一覧は Incident 側の唯一の真実の源から取る)。
        // 群のサイズを部署ごとに変え(i 番目は i + 2 件 → 類似件数は i + 1 件)、
        // 「類似件数が多い ＝ 添字が大きい部署」という検証しやすい並びを作る。
        // 発生日は逆に添字が小さい部署ほど新しくして、日付順で打ち切ると結果が変わるようにする
        // (以前の実装なら添字の小さい軽微なパターンが残っていた)
        Assert.True(Incident.Departments.Length >= patternCount, "テストに必要な部署数が足りない");
        var incidentsByDept = new Dictionary<string, List<Incident>>();
        for (int i = 0; i < patternCount; i++)
        {
            var dept = Incident.Departments[i];
            // この部署の再発パターンを構成するインシデント群(i + 2 件)
            var group = new List<Incident>();
            for (int n = 0; n < i + 2; n++)
            {
                // 添字が小さい部署ほど新しい発生日にする(日付順の打ち切りとの差を出すため)
                group.Add(MakeIncident(dept: dept, occurredAt: _clock.Today.AddDays(-1 - i - n)));
            }
            // 後で原因分析を紐づけられるよう部署ごとに控えておく
            incidentsByDept[dept] = group;
            _db.Incidents.AddRange(group);
        }
        // Id を採番させるため、全部署分をまとめて 1 回だけ保存する
        await _db.SaveChangesAsync();

        // 各インシデントに同じ原因分類を紐づけて再発条件(原因カテゴリの重複)を満たす
        foreach (var incident in incidentsByDept.Values.SelectMany(group => group))
        {
            _db.CauseAnalyses.Add(new CauseAnalysis
            {
                IncidentId = incident.Id,
                CauseCategoryId = category.Id,
                Why1 = "原因"
            });
        }
        // なぜなぜ分析側もまとめて 1 回だけ保存する
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // 検出総数は上限に関わらず全パターンを数える
        Assert.Equal(patternCount, vm!.RecurrenceAlertTotal);
        // パネルへ渡すのは上限件数まで
        Assert.Equal(HomeController.RecurrenceAlertLimit, vm.RecurrenceAlerts.Count);
        // 載せきれなかった件数が「ほか N 件」として表示される
        Assert.Equal(patternCount - HomeController.RecurrenceAlertLimit, vm.HiddenRecurrenceAlertCount);

        // 残るのは (a) 類似件数が多い上位(= 添字が大きい部署)と、(b) 最新枠に確保される
        // 「最も新しく発生したパターン」(= 添字 0 の部署)。発生日順だけで打ち切ると
        // 添字の小さい軽微なパターンばかりが残り、重大度順だけで打ち切ると添字 0 が消えるため、
        // この検証で「重大度優先＋最新 1 枠」という選抜規則が両方向に固定される。
        // 表示順は重大度(類似件数)の降順
        var expectedDepartments = Enumerable
            // 重大度上位は (上限 - 最新枠 1) 件分。添字の大きい部署から降順に並ぶ
            .Range(patternCount - (HomeController.RecurrenceAlertLimit - 1), HomeController.RecurrenceAlertLimit - 1)
            .Reverse()
            .Select(i => Incident.Departments[i])
            // 最新枠の 1 件(添字 0 の部署)は類似件数が最少なので末尾に並ぶ
            .Append(Incident.Departments[0])
            .ToList();
        Assert.Equal(
            expectedDepartments,
            vm.RecurrenceAlerts.Select(a => a.CurrentIncident.Department).ToList());
        // 類似件数が降順に並んでいることも確認する(同点時の副次キーに依存しない形で)
        var similarCounts = vm.RecurrenceAlerts.Select(a => a.SimilarIncidents.Count).ToList();
        Assert.Equal(similarCounts.OrderByDescending(c => c).ToList(), similarCounts);
    }

    [Fact]
    public async Task Index_RecurrenceAlerts_KeepsNewestPatternEvenWhenLeastSevere()
    {
        // /code-review ultra 指摘対応の回帰テスト: 重大度(類似件数)順だけで打ち切ると、
        // 「今日初めて再発した」パターンが、類似件数の多い古いパターンに押し出されて
        // 恒久的に画面へ出てこない。再発検知はまさに新しく現れたパターンに気付くための
        // 機能なので、選抜の 1 枠は最新パターンに確保されることを固定する。
        var category = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        // 上限ぶんの「類似件数が多い(3 件ずつ)・やや古い」パターンで枠を埋める
        var incidents = new List<Incident>();
        for (int i = 0; i < HomeController.RecurrenceAlertLimit; i++)
        {
            for (int n = 0; n < 3; n++)
            {
                incidents.Add(MakeIncident(dept: Incident.Departments[i], occurredAt: _clock.Today.AddDays(-30 - n)));
            }
        }
        // そこへ「今日初めて再発した(類似 1 件だけ)・最も新しい」パターンを 1 つ足す
        var newestDept = Incident.Departments[HomeController.RecurrenceAlertLimit];
        incidents.Add(MakeIncident(dept: newestDept, occurredAt: _clock.Today));
        incidents.Add(MakeIncident(dept: newestDept, occurredAt: _clock.Today.AddDays(-1)));

        _db.Incidents.AddRange(incidents);
        await _db.SaveChangesAsync();

        // 全インシデントに同じ原因分類を紐づけて再発条件を満たす
        foreach (var incident in incidents)
        {
            _db.CauseAnalyses.Add(new CauseAnalysis
            {
                IncidentId = incident.Id,
                CauseCategoryId = category.Id,
                Why1 = "原因"
            });
        }
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // 上限件数までしか表示しないのは変わらない
        Assert.Equal(HomeController.RecurrenceAlertLimit, vm!.RecurrenceAlerts.Count);
        // 類似件数が最少でも、最新のパターンは必ず表示に残る
        Assert.Contains(vm.RecurrenceAlerts, a => a.CurrentIncident.Department == newestDept);
    }

    [Fact]
    public async Task Index_WeekPeriod_MonthlyCounts_Has7DailyLabels()
    {
        var result = await _controller.Index("week") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(7, vm!.MonthlyCounts.Count);
        // Daily labels should be in M/d format
        Assert.Matches(@"^\d{1,2}/\d{1,2}$", vm.MonthlyCounts.First().Label);

        // ドリルダウン期間: 週表示は 1 バケット = 1 日なので DateFrom と DateTo が同一日になる。
        // ラベル("M/d")には年が無いため、クリック遷移はこの ISO 日付を使う(年跨ぎ週でも安全)
        var oldestDay = _clock.Today.AddDays(-6);
        // 先頭バケット(最古の日)の開始日がその日の ISO 表記であること
        Assert.Equal(oldestDay.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), vm.MonthlyCounts.First().DateFrom);
        // 週表示では開始日と終了日が一致すること(1 日単位の絞り込み)
        Assert.Equal(vm.MonthlyCounts.First().DateFrom, vm.MonthlyCounts.First().DateTo);
        // 末尾バケットは今日であること
        Assert.Equal(_clock.Today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), vm.MonthlyCounts.Last().DateTo);
    }

    [Fact]
    public async Task Index_YearPeriod_MonthlyCounts_Has12MonthLabels()
    {
        var result = await _controller.Index("year") as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        Assert.Equal(12, vm!.MonthlyCounts.Count);
        Assert.Matches(@"^\d{4}年\d{1,2}月$", vm.MonthlyCounts.First().Label);

        // ドリルダウン期間: 月表示は 1 バケット = 1 か月。先頭バケットは 11 か月前の月
        var firstMonth = new DateTime(_clock.Today.Year, _clock.Today.Month, 1).AddMonths(-11);
        // 開始日は当月 1 日であること
        Assert.Equal(firstMonth.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), vm.MonthlyCounts.First().DateFrom);
        // 終了日は当月末日であること(一覧側の dateTo は「その日を含む」ため翌月 1 日ではない)
        Assert.Equal(firstMonth.AddMonths(1).AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), vm.MonthlyCounts.First().DateTo);
    }
}
