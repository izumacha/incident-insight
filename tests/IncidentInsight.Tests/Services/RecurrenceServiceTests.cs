// ApplicationDbContext を使えるようにする（InMemory データベースのセットアップに必要）
using IncidentInsight.Web.Data;
// Incident / CauseAnalysis / CauseCategory などのモデルを使えるようにする
using IncidentInsight.Web.Models;
// IncidentTypeKind / IncidentSeverity などの列挙型を使えるようにする
using IncidentInsight.Web.Models.Enums;
// テスト対象の RecurrenceService を使えるようにする
using IncidentInsight.Web.Services;
// EF Core の InMemory プロバイダを使えるようにする
using Microsoft.EntityFrameworkCore;

// テストクラスが所属する名前空間（テストプロジェクトの Services フォルダ配下）
namespace IncidentInsight.Tests.Services;

/// <summary>
/// RecurrenceService（再発検知サービス）の単体テストクラス。
/// InMemory データベースを使い、DB 接続なしで高速に検証する。
/// IDisposable を実装してテスト後に DbContext を確実に解放する。
/// </summary>
public class RecurrenceServiceTests : IDisposable
{
    // テスト専用の InMemory データベースコンテキスト（テストごとに独立した DB を持つ）
    private readonly ApplicationDbContext _db;
    // テスト対象のサービス（SystemClock を注入して今日の日付を取得させる）
    private readonly RecurrenceService _svc;

    /// <summary>
    /// コンストラクタ: テストごとに新しい InMemory DB と RecurrenceService を生成する。
    /// Guid.NewGuid() で DB 名を一意にし、並列テストでの衝突を防ぐ。
    /// </summary>
    public RecurrenceServiceTests()
    {
        // テスト専用の InMemory DB オプションを構築する（毎回ユニークな名前を使う）
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()) // テストごとに独立した DB を作る
            .Options;
        // DbContext を生成する（InMemory なので実際の DB 接続は不要）
        _db = new ApplicationDbContext(options);
        // RecurrenceService を生成する（SystemClock を渡して現在日時を取得させる）
        _svc = new RecurrenceService(new SystemClock());
    }

    /// <summary>
    /// テスト後のリソース解放。DbContext の接続やメモリを確実に閉じる。
    /// </summary>
    public void Dispose() => _db.Dispose(); // DbContext を破棄してリソースを解放する

    /// <summary>
    /// テスト用インシデントを生成するヘルパーメソッド。
    /// 各テストで共通して使うインシデントの雛形を返す純粋関数。
    /// </summary>
    /// <param name="dept">部署名（例: "内科病棟"）</param>
    /// <param name="type">インシデント種別（例: Medication）</param>
    /// <param name="occurredAt">発生日時</param>
    /// <returns>テスト用の Incident インスタンス</returns>
    private static Incident MakeIncident(string dept, IncidentTypeKind type, DateTime occurredAt)
        => new()
        {
            Department = dept,                          // 部署名をセットする
            IncidentType = type,                        // インシデント種別をセットする
            Severity = IncidentSeverity.Level1,         // 重症度は固定値（テストでは任意の値）
            Description = "テスト",                     // 状況説明（PHI テスト対象外なので簡略化）
            ReporterName = "テスト太郎",                 // 報告者名（PHI テスト対象外なので簡略化）
            OccurredAt = occurredAt,                    // 発生日時をセットする
            ReportedAt = occurredAt                     // 報告日時（テストでは発生日時と同じにする）
        };

    /// <summary>
    /// 同じ部署・同じ種別・同じ原因分類を持つインシデントが再発候補として返されることを検証する。
    /// 部署が異なる / 種別が異なる候補は含まれないことも合わせて確認する。
    /// </summary>
    [Fact]
    public async Task FindRecurrencesForIncident_ReturnsSimilar_SameDeptTypeCauseOverlap()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存して Id を確定させる

        // 対象インシデント（基準となるインシデント）を作成する
        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-5));
        // 期待する一致候補（同部署・同種別・5 日前以上に発生）
        var match = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-30));
        // 除外される候補: 部署が異なる
        var diffDept = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        // 除外される候補: インシデント種別が異なる
        var diffType = MakeIncident("内科病棟", IncidentTypeKind.Fall, DateTime.Today.AddDays(-10));
        // 4 件のインシデントをまとめて DB に追加する
        _db.Incidents.AddRange(target, match, diffDept, diffType);
        // DB に保存して各インシデントの Id を確定させる
        await _db.SaveChangesAsync();

        // 各インシデントに原因分析を紐づける（全員同じカテゴリ）
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = target.Id, CauseCategoryId = cat.Id, Why1 = "w1" },   // 対象
            new CauseAnalysis { IncidentId = match.Id, CauseCategoryId = cat.Id, Why1 = "w1" },    // 一致候補
            new CauseAnalysis { IncidentId = diffDept.Id, CauseCategoryId = cat.Id, Why1 = "w1" }, // 部署違い
            new CauseAnalysis { IncidentId = diffType.Id, CauseCategoryId = cat.Id, Why1 = "w1" }  // 種別違い
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // サービスが CauseAnalyses を参照できるよう、対象インシデントを Include して再読込する
        // (InMemory の EF Core では AsNoTracking + Include が必要)
        var loaded = await _db.Incidents
            .AsNoTracking()                             // 変更追跡を無効にして読み込む
            .Include(i => i.CauseAnalyses)              // 原因分析をまとめて読み込む（eager load）
            .FirstAsync(i => i.Id == target.Id);        // 対象インシデントだけを取得する

        // サービスを呼び出して再発候補を取得する（時間窓なし = 無制限）
        var result = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        // 結果は 1 件だけであることを確認する（match のみが一致するはず）
        Assert.Single(result);
        // その 1 件が match であることを Id で確認する
        Assert.Equal(match.Id, result[0].Id);
    }

    /// <summary>
    /// 時間窓（within パラメータ）を指定した場合と指定しない場合で
    /// 返される候補件数が変わることを検証する。
    /// 90 日以内は 1 件、無制限は 2 件が期待される。
    /// </summary>
    [Fact]
    public async Task FindRecurrencesForIncident_AppliesTimeWindow_WhenWithinProvided()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 対象インシデント（今日発生）
        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today);
        // 90 日以内に収まる候補（10 日前）
        var inWindow = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        // 90 日窓外の候補（120 日前）
        var outOfWindow = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-120));
        // 3 件のインシデントを DB に追加する
        _db.Incidents.AddRange(target, inWindow, outOfWindow);
        // DB に保存して Id を確定させる
        await _db.SaveChangesAsync();

        // 各インシデントに原因分析を紐づける
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = target.Id, CauseCategoryId = cat.Id, Why1 = "w1" },       // 対象
            new CauseAnalysis { IncidentId = inWindow.Id, CauseCategoryId = cat.Id, Why1 = "w1" },     // 窓内
            new CauseAnalysis { IncidentId = outOfWindow.Id, CauseCategoryId = cat.Id, Why1 = "w1" }   // 窓外
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // サービスが CauseAnalyses を参照できるよう、対象インシデントを Include して再読込する
        var loaded = await _db.Incidents
            .AsNoTracking()                             // 変更追跡を無効にして読み込む
            .Include(i => i.CauseAnalyses)              // 原因分析をまとめて読み込む
            .FirstAsync(i => i.Id == target.Id);        // 対象インシデントだけを取得する

        // 時間窓 90 日を指定してサービスを呼び出す（窓外の outOfWindow は除外される）
        var within90 = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents, TimeSpan.FromDays(90));
        // 時間窓なし（null）でサービスを呼び出す（全候補が対象になる）
        var unbounded = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        // 90 日窓指定では 1 件（inWindow のみ）が返されることを確認する
        Assert.Single(within90);
        // その 1 件が inWindow であることを Id で確認する
        Assert.Equal(inWindow.Id, within90[0].Id);
        // 時間窓なしでは 2 件（inWindow + outOfWindow）が返されることを確認する
        Assert.Equal(2, unbounded.Count);
    }

    /// <summary>
    /// 対象インシデントに原因分析が 1 件もない場合、空リストが返されることを検証する。
    /// 原因分類が特定できなければ再発判定は不可能なので、空リストが正しい動作。
    /// </summary>
    [Fact]
    public async Task FindRecurrencesForIncident_ReturnsEmpty_WhenTargetHasNoCauseAnalyses()
    {
        // 原因分析なしのインシデントを作成して DB に追加する
        var target = MakeIncident("内科病棟", IncidentTypeKind.Medication, DateTime.Today);
        _db.Incidents.Add(target); // インシデントを DB に追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // CauseAnalyses を Include して再読込する（空コレクションが返るはず）
        var loaded = await _db.Incidents
            .AsNoTracking()                             // 変更追跡を無効にして読み込む
            .Include(i => i.CauseAnalyses)              // 原因分析をまとめて読み込む（空になるはず）
            .FirstAsync(i => i.Id == target.Id);        // 対象インシデントだけを取得する

        // 原因分析がないのでサービスを呼び出す
        var result = await _svc.FindRecurrencesForIncidentAsync(loaded, _db.Incidents);

        // 原因分類が 0 件の場合は空リストが返されることを確認する
        Assert.Empty(result);
    }

    /// <summary>
    /// FindRecurrenceAlertsAsync が直近インシデントをグループ化して
    /// 再発アラートを 1 件生成することを検証する。
    /// アラートには CurrentIncident（最新）と SimilarIncidents（類似）が含まれる。
    /// PatternDescription に部署名が含まれることも確認する。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_GroupsRecentIncidents_IntoAlerts()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 最新インシデント（10 日前: 直近 90 日以内）
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        // 過去インシデント（20 日前: 直近 90 日以内）
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-20));
        // 2 件のインシデントを DB に追加する
        _db.Incidents.AddRange(a, b);
        // DB に保存して Id を確定させる
        await _db.SaveChangesAsync();

        // 各インシデントに原因分析を紐づける（同じカテゴリ・異なる Why1）
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w1" }, // 最新用
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w2" }  // 過去用
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // 直近 90 日を時間窓として再発アラートを取得する
        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        // アラートが 1 件だけ生成されることを確認する（a が b の再発アラートをトリガー）
        Assert.Single(alerts);
        // アラートの CurrentIncident が最新インシデント a であることを確認する
        Assert.Equal(a.Id, alerts[0].CurrentIncident.Id);
        // アラートの SimilarIncidents に過去インシデント b が含まれることを確認する
        Assert.Contains(alerts[0].SimilarIncidents, s => s.Id == b.Id);
        // PatternDescription に部署名「外科病棟」が含まれることを確認する
        Assert.Contains("外科病棟", alerts[0].PatternDescription);
    }

    /// <summary>
    /// ダッシュボードの再発アラート候補クエリが MaxAlertCandidateRows 件で打ち切られ、
    /// 上限を超えた分は「発生日が最も古い候補」から切り捨てられることを検証する。
    /// 上限が無いと、運用年数が長い環境でダッシュボード表示のたびに全期間の
    /// インシデントをメモリへ読み込んでしまう(§8 一覧取得の上限)ための回帰テスト。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_CapsCandidateFetch_DroppingOldestBeyondLimit()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 最新インシデント(10 日前: 直近 90 日以内 → アラートのトリガーになる)
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10));
        // 原因分析を紐づける(候補との一致条件を満たすため)
        a.CauseAnalyses.Add(new CauseAnalysis { CauseCategoryId = cat.Id, Why1 = "w" });
        _db.Incidents.Add(a); // 最新インシデントを追加する

        // 上限と同数(MaxAlertCandidateRows 件)の「90 日窓の外・かつ最古候補より新しい」
        // 一致候補を敷き詰める(発生日: 100 日前から 1 日ずつ古くしていく)
        for (var i = 0; i < RecurrenceService.MaxAlertCandidateRows; i++)
        {
            // 上限を埋めるための一致候補を 1 件作る
            var filler = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-100 - i));
            // 同じ原因分類を紐づけて候補条件(部署・種別・原因分類の一致)を満たす
            filler.CauseAnalyses.Add(new CauseAnalysis { CauseCategoryId = cat.Id, Why1 = "w" });
            // 候補を DB に追加する
            _db.Incidents.Add(filler);
        }

        // 最古の一致候補(5 年前)。上限打ち切りで最初に切り捨てられるべき 1 件
        var oldest = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddYears(-5));
        // 同じ原因分類を紐づける(切り捨てが無ければ一致候補になる条件を満たす)
        oldest.CauseAnalyses.Add(new CauseAnalysis { CauseCategoryId = cat.Id, Why1 = "w" });
        _db.Incidents.Add(oldest); // 最古候補を追加する
        await _db.SaveChangesAsync(); // まとめて DB に保存する

        // 直近 90 日を時間窓として再発アラートを取得する
        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        // アラートは最新インシデント a をトリガーに 1 件だけ生成されること
        Assert.Single(alerts);
        // 上限内の新しい候補(100 日前の filler)は類似リストに含まれること
        Assert.Contains(alerts[0].SimilarIncidents, s => s.OccurredAt == DateTime.Today.AddDays(-100));
        // 上限打ち切りで最古の候補は類似リストから除外されていること
        Assert.DoesNotContain(alerts[0].SimilarIncidents, s => s.Id == oldest.Id);
    }

    /// <summary>
    /// 再発アラートの PatternDescription が、インシデント種別を英語の enum 名ではなく
    /// 日本語ラベル（例: "投薬ミス"）で表示することを検証する。
    /// 医療現場の日本語 UI に生の enum 名（"Medication" 等）が漏れる回帰を防ぐ。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_PatternDescription_UsesJapaneseTypeLabel()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 同部署・同種別（Medication = "投薬ミス"）の 2 件を直近 90 日以内に作成する
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-10)); // 最新
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-20)); // 過去
        // 2 件のインシデントを DB に追加する
        _db.Incidents.AddRange(a, b);
        // DB に保存して Id を確定させる
        await _db.SaveChangesAsync();

        // 各インシデントに同じ原因分類の原因分析を紐づける（再発として一致させる）
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w1" }, // 最新用
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w2" }  // 過去用
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // 直近 90 日を時間窓として再発アラートを取得する
        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        // アラートが 1 件生成されることを確認する
        Assert.Single(alerts);
        // PatternDescription に日本語ラベル「投薬ミス」が含まれることを確認する
        Assert.Contains("投薬ミス", alerts[0].PatternDescription);
        // 生の英語 enum 名「Medication」が漏れていないことを確認する（回帰防止）
        Assert.DoesNotContain("Medication", alerts[0].PatternDescription);
    }

    /// <summary>
    /// 直近窓外のインシデントのみ存在する場合、再発アラートが生成されないことを検証する。
    /// 古すぎる（90 日超）インシデントは再発候補に含まれない。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_RespectsRecentWindow()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 両インシデントとも 90 日窓外（100 日前と 200 日前）のため、アラートは生成されない
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-100));
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-200));
        // 2 件のインシデントを DB に追加する
        _db.Incidents.AddRange(a, b);
        // DB に保存して Id を確定させる
        await _db.SaveChangesAsync();

        // 各インシデントに原因分析を紐づける
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w1" }, // 100 日前
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w2" }  // 200 日前
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // 直近 90 日を時間窓として再発アラートを取得する（両者とも窓外なのでアラートなし）
        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        // 窓外のみ存在する場合はアラートが 0 件であることを確認する
        Assert.Empty(alerts);
    }

    /// <summary>
    /// 3 件すべてが互いに類似する場合に重複アラートが発生せず、
    /// 1 件のアラートに集約されることを検証する。
    /// 最古のインシデントから順にアラートが割り当てられ、残りは処理済みとして除外される。
    /// </summary>
    [Fact]
    public async Task FindRecurrenceAlerts_DedupesAcrossAlerts_WhenIncidentsPairUp()
    {
        // テスト用の原因分類カテゴリを作成して DB に保存する
        var cat = new CauseCategory { Name = "ヒューマンエラー", DisplayOrder = 1 };
        _db.CauseCategories.Add(cat); // カテゴリを追加する
        await _db.SaveChangesAsync(); // DB に保存する

        // 最新インシデント（5 日前）
        var a = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-5));
        // 中間インシデント（15 日前）
        var b = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-15));
        // 最古インシデント（25 日前）
        var c = MakeIncident("外科病棟", IncidentTypeKind.Medication, DateTime.Today.AddDays(-25));
        // 3 件のインシデントを DB に追加する
        _db.Incidents.AddRange(a, b, c);
        // DB に保存して Id を確定させる
        await _db.SaveChangesAsync();

        // 3 件すべてに同じカテゴリ・同じ Why1 の原因分析を紐づける
        _db.CauseAnalyses.AddRange(
            new CauseAnalysis { IncidentId = a.Id, CauseCategoryId = cat.Id, Why1 = "w" }, // 最新
            new CauseAnalysis { IncidentId = b.Id, CauseCategoryId = cat.Id, Why1 = "w" }, // 中間
            new CauseAnalysis { IncidentId = c.Id, CauseCategoryId = cat.Id, Why1 = "w" }  // 最古
        );
        // 原因分析を DB に保存する
        await _db.SaveChangesAsync();

        // 直近 90 日を時間窓として再発アラートを取得する
        var alerts = await _svc.FindRecurrenceAlertsAsync(_db.Incidents, TimeSpan.FromDays(90));

        // 3 件が互いに類似していても、重複を省いて 1 件のアラートだけが生成されることを確認する
        Assert.Single(alerts);
        // そのアラートの CurrentIncident が最新インシデント a であることを確認する
        // (FindRecurrenceAlertsAsync は新しい順に巡回し、最初に見つけた未処理の件を採用する)
        Assert.Equal(a.Id, alerts[0].CurrentIncident.Id);
        // SimilarIncidents が 2 件（b と c）含まれることを確認する
        Assert.Equal(2, alerts[0].SimilarIncidents.Count);
    }
}
