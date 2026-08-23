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
// テストでは何も出力しないロガー(NullLogger)を使うため
using Microsoft.Extensions.Logging.Abstractions;

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
        _controller = new HomeController(_db, new RecurrenceService(_clock, NullLogger<RecurrenceService>.Instance), _clock);
        // Existing tests assume a privileged viewer; Staff-scope tests build their own.
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    // 再発アラートのテストは「1 部署 = 1 再発パターン」でシードするため、必要な数の部署が
    // マスタ(Incident.Departments)に存在することが前提になる。上限値(RecurrenceAlertLimit)を
    // 引き上げたときに IndexOutOfRangeException で理由不明に落ちるのを避け、
    // 「何が足りないのか」が分かるメッセージで止める
    private static void RequireDepartments(int required) =>
        Assert.True(
            Incident.Departments.Length >= required,
            $"テストに必要な部署数が足りない(必要: {required} / 定義: {Incident.Departments.Length})");

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

        // すべて期限超過。期限日はバラけさせる(同値の場合は別テストが受け持つ)
        await SeedOverdueMeasuresAsync(
            incident.Id,
            Enumerable.Range(0, overdueCountInDb)
                .Select(i => (Id: (int?)null, DueDate: _clock.Today.AddDays(-1 - i)))
                .ToList());

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // KPI の総数は上限を超えても正確に全件(overdueCountInDb)を反映する
        Assert.Equal(overdueCountInDb, vm!.OverdueMeasures);
        // 一覧パネルは OverdueAlertLimit 件までしか返さない(DB 側で切り捨て済み)
        Assert.Equal(HomeController.OverdueAlertLimit, vm.OverdueMeasureList.Count);
    }

    [Fact]
    public async Task Index_RecentIncidents_SameOccurredAt_TruncatesByIdDescending()
    {
        // 回帰テスト: 「最近のインシデント」カードのクエリは OccurredAt の降順だけで並べて
        // 上限件数で打ち切っていた。OccurredAt は日付入力から作られるため同一日時の行が普通に
        // 並ぶが、DB は同値行の並び順を保証しないため、どの 5 件がカードに出るかがリロードの
        // たびに変わり得た。主キー Id を第 2 キー(第 1 キーと同じ降順)に置いて境界を決定的にする。
        // 期待値は「同一日時なら後から登録された(Id の大きい)ものが先」= インシデント一覧の
        // 既定並び順(OccurredAt 降順 → Id 降順)と一致する並び。
        const int incidentCount = HomeController.RecentIncidentsLimit + 3; // 上限より多く用意する

        // 全件まったく同じ発生日時にして、第 2 キーだけが順序を決める状況を作る
        var sameOccurredAt = _clock.Now;
        for (int i = 0; i < incidentCount; i++)
        {
            _db.Incidents.Add(MakeIncident(occurredAt: sameOccurredAt));
        }
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // カードは上限件数までしか返らない
        Assert.Equal(HomeController.RecentIncidentsLimit, vm!.RecentIncidents.Count);
        // 採用されるのは Id の大きい方から上限件数ぶんで、並びも Id の降順になる
        var expectedIds = _db.Incidents
            .Select(i => i.Id)
            .OrderByDescending(id => id)
            .Take(HomeController.RecentIncidentsLimit)
            .ToList();
        Assert.Equal(expectedIds, vm.RecentIncidents.Select(i => i.Id).ToList());
    }

    [Fact]
    public async Task Index_OverdueMeasureList_SameDueDate_TruncatesByIdAscending()
    {
        // 回帰テスト: 「期限超過の対策」パネルのクエリは DueDate の昇順だけで並べて上限件数で
        // 打ち切っていた。DueDate は日付単位で入力されるため「同じ期限日の対策」は大量に生まれ、
        // 第 2 キーが無いとパネルに出る 5 件が実行のたびに入れ替わって消し込みを追えなくなる。
        // 主キー Id を第 2 キー(第 1 キーと同じ昇順)に置いて、同じ期限日なら先に登録された
        // = より長く放置されている対策が出ることを固定する。
        // 第 2 キーを外すと落ちるように、Id を降順で明示して「投入順」と「Id の昇順」を
        // 意図的にずらしてある。こうしないと InMemory プロバイダでは投入順 = Id 昇順に
        // なってしまい、第 2 キーの有無で結果が変わらず回帰を検出できない。
        // 上の Index_OverdueMeasureList_IsCappedButKpiCountReflectsFullTotal が期限日を
        // バラけさせて上限だけを見ているのに対し、こちらは同値の場合を受け持つ。
        const int overdueCountInDb = HomeController.OverdueAlertLimit + 3; // 上限より多く用意する

        var incident = MakeIncident();
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // 全件まったく同じ期限日(かつ期限超過)にして、第 2 キーだけが順序を決める状況を作る
        var sameDueDate = _clock.Today.AddDays(-1);
        // Id は降順(大きい方から)に割り当てる = 投入順と Id の昇順が逆になる
        await SeedOverdueMeasuresAsync(
            incident.Id,
            Enumerable.Range(0, overdueCountInDb)
                .Select(i => (Id: (int?)(overdueCountInDb - i), DueDate: sameDueDate))
                .ToList());

        var result = await _controller.Index(null) as ViewResult;
        var vm = result?.Model as DashboardViewModel;

        // パネルは上限件数までしか返らない
        Assert.Equal(HomeController.OverdueAlertLimit, vm!.OverdueMeasureList.Count);
        // 採用されるのは Id の小さい方から上限件数ぶんで、並びも Id の昇順になる
        var expectedIds = _db.PreventiveMeasures
            .Select(m => m.Id)
            .OrderBy(id => id)
            .Take(HomeController.OverdueAlertLimit)
            .ToList();
        Assert.Equal(expectedIds, vm.OverdueMeasureList.Select(m => m.Id).ToList());
    }

    /// <summary>
    /// 期限超過の対策をまとめて投入する共通ヘルパー。
    /// </summary>
    /// <remarks>
    /// 上限まわりの 2 つのテスト(件数の打ち切りと、期限日が同値のときの打ち切り境界)が
    /// 同じ形の対策を投入するため、投入手順をここへ集約する(§6 DRY)。
    /// 違うのは「期限日をどう散らすか」と「Id を明示するか」の 2 点だけなので、
    /// その 2 つを要素ごとに受け取る。
    /// </remarks>
    /// <param name="incidentId">対策をぶら下げるインシデントの ID。</param>
    /// <param name="specs">
    /// 対策 1 件ぶんの指定。Id を明示すると投入順と Id の昇順を意図的にずらせる
    /// (タイブレーカーが効いているかを検出するために必要)。null なら DB 側の採番に任せる。
    /// </param>
    private async Task SeedOverdueMeasuresAsync(
        int incidentId,
        IReadOnlyList<(int? Id, DateTime DueDate)> specs)
    {
        // 指定された件数ぶん対策を組み立てる
        for (var i = 0; i < specs.Count; i++)
        {
            // 期限超過(Planned のまま期限日が過去)の対策を 1 件作る
            var measure = new PreventiveMeasure
            {
                IncidentId = incidentId,
                Description = $"対策{i}",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = "内科",
                Status = MeasureStatus.Planned,
                DueDate = specs[i].DueDate
            };
            // Id の指定があれば明示的に割り当てる(投入順と Id 順をずらすため)
            if (specs[i].Id is { } explicitId) measure.Id = explicitId;
            // 追跡対象に加える
            _db.PreventiveMeasures.Add(measure);
        }
        // まとめて 1 回で保存する
        await _db.SaveChangesAsync();
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
        RequireDepartments(patternCount);
        // 後で原因分析を紐づけられるよう、作ったインシデントを順に控えておく
        // (部署ごとの引き当ては不要なので、姉妹テストと同じくフラットなリストで持つ)
        var incidents = new List<Incident>();
        for (int i = 0; i < patternCount; i++)
        {
            var dept = Incident.Departments[i];
            // この部署の再発パターンを構成するインシデント群(i + 2 件)
            for (int n = 0; n < i + 2; n++)
            {
                // 添字が小さい部署ほど新しい発生日にする(日付順の打ち切りとの差を出すため)
                incidents.Add(MakeIncident(dept: dept, occurredAt: _clock.Today.AddDays(-1 - i - n)));
            }
        }
        _db.Incidents.AddRange(incidents);
        // Id を採番させるため、全部署分をまとめて 1 回だけ保存する
        await _db.SaveChangesAsync();

        // 各インシデントに同じ原因分類を紐づけて再発条件(原因カテゴリの重複)を満たす
        foreach (var incident in incidents)
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
        // 上限ぶんの部署 + 最新パターン用に 1 部署ぶん、計 上限 + 1 部署を使う
        RequireDepartments(HomeController.RecurrenceAlertLimit + 1);

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
    public async Task Index_RecurrenceAlerts_DoesNotDuplicateWhenNewestIsAlsoMostSevere()
    {
        // 最新パターンが重大度上位にも入っている場合、最新枠の差し替えは不要
        // (差し替えてしまうと同じパターンが 2 行並び、代わりに別のパターンが 1 つ黙って消える)。
        // 上限より多いパターンを用意し、最新かつ最も類似件数の多いパターンを 1 つ混ぜて、
        // 表示に重複が無いこと・件数どおり別々のパターンが並ぶことを確認する。
        const int patternCount = HomeController.RecurrenceAlertLimit + 2;
        RequireDepartments(patternCount);

        var category = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var incidents = new List<Incident>();
        // 添字 0 の部署は「最新かつ最多(4 件 = 類似 3 件)」にして、重大度上位にも最新枠にも該当させる
        for (int n = 0; n < 4; n++)
        {
            incidents.Add(MakeIncident(dept: Incident.Departments[0], occurredAt: _clock.Today.AddDays(-n)));
        }
        // 残りの部署は「やや古い・類似 2 件(3 件ずつ)」で埋める
        for (int i = 1; i < patternCount; i++)
        {
            for (int n = 0; n < 3; n++)
            {
                incidents.Add(MakeIncident(dept: Incident.Departments[i], occurredAt: _clock.Today.AddDays(-20 - n)));
            }
        }

        _db.Incidents.AddRange(incidents);
        await _db.SaveChangesAsync();

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

        // 上限件数ぶんが表示される
        Assert.Equal(HomeController.RecurrenceAlertLimit, vm!.RecurrenceAlerts.Count);
        // 同じパターンが 2 度並んでいない(最新枠の差し替えが不要な場合に差し替えていないこと)
        var displayedIds = vm.RecurrenceAlerts.Select(a => a.CurrentIncident.Id).ToList();
        Assert.Equal(displayedIds.Distinct().Count(), displayedIds.Count);
        // 最新かつ最多のパターンは当然表示に含まれる
        Assert.Contains(vm.RecurrenceAlerts, a => a.CurrentIncident.Department == Incident.Departments[0]);
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
