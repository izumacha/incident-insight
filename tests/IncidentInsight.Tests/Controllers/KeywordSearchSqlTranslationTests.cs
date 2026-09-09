// ユーザーコンテキストと認可サービスを組み立てるテストヘルパー
using IncidentInsight.Tests.Helpers;
// 検索を持つ 3 つのコントローラ
using IncidentInsight.Web.Controllers;
// DbContext
using IncidentInsight.Web.Data;
// エンティティ(Incident / PreventiveMeasure / AuditLog)
using IncidentInsight.Web.Models;
// enum(重症度・インシデント種別・対策種別)
using IncidentInsight.Web.Models.Enums;
// 一覧の ViewModel
using IncidentInsight.Web.Models.ViewModels;
// 時刻源(SystemClock)・再発検知サービス
using IncidentInsight.Web.Services;
// ViewResult を判定するため
using Microsoft.AspNetCore.Mvc;
// DbContextOptionsBuilder / EnsureCreatedAsync
using Microsoft.EntityFrameworkCore;
// SQLite のインメモリ接続を自分で開いて保持するため
using Microsoft.Data.Sqlite;
// テストでは何も出力しないロガー(NullLogger)を使うため
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// 一覧のフリーワード検索が<b>実際に SQL へ翻訳できること</b>を、関係データベースの
/// プロバイダ(SQLite)で確かめる。
/// </summary>
/// <remarks>
/// <para><b>なぜ InMemory では足りないのか。</b> 他の検索テストが使う InMemory プロバイダには
/// SQL が無く、式ツリーを<b>アプリ内の LINQ として</b>そのまま実行する。つまり
/// 「EF Core がこの式を SQL へ翻訳できるか」を一度も試していない。
/// <c>KeywordSearchPredicate</c> は述語を<b>手で組み立てた式ツリー</b>として返すので、
/// 組み立て方を間違えると本番(SQLite / SQL Server / PostgreSQL)でだけ
/// <c>InvalidOperationException</c>(翻訳不能)になり、InMemory のテストは全件緑のまま通る
/// ——このリポジトリが繰り返し避けている「CI の緑が判断材料にならない」形そのもの。</para>
///
/// <para><b>大文字小文字の扱いも同時に見ている。</b> SQLite の <c>Contains</c> は
/// <c>instr()</c> へ翻訳され<b>大文字小文字を区別する</b>。小文字で保存して小文字で引くこの形は、
/// 両辺の大文字化が SQL の <c>upper()</c> として実際に効いていなければ 0 件になる。
/// 使う文字を ASCII に限っているのは、SQLite の <c>upper()</c> が ASCII しか畳まないため
/// (<c>KeywordSearchPredicate</c> の「残る境界 3」)。</para>
///
/// <para><b>PostgreSQL / SQL Server までは確かめていない</b>(CI に DB を立てていないため)。
/// ただし翻訳の失敗はプロバイダ非依存の共通部分(<c>Relational</c>)で起きるので、
/// 関係データベースのプロバイダを 1 つ通せば「組み立て方が翻訳可能な形か」は押さえられる。</para>
/// </remarks>
public class KeywordSearchSqlTranslationTests : IAsyncLifetime
{
    // インメモリの SQLite は「最後の接続が閉じるとデータベースごと消える」ので、
    // テストの間ずっと開いたままにする接続を 1 本持つ
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    // 上の接続を使う DbContext(各テストから使う)
    private ApplicationDbContext _db = null!;

    /// <summary>接続を開き、スキーマを作ってから検索対象のデータを 1 件ずつ入れる。</summary>
    public async Task InitializeAsync()
    {
        // インメモリのデータベースを生存させるために接続を開く
        await _connection.OpenAsync();
        // 開いたままの接続を使う DbContext を組み立てる
        _db = new ApplicationDbContext(
            new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(_connection).Options);
        // マイグレーション履歴ではなく現在のモデルからスキーマを作る
        // (見たいのはクエリの翻訳だけなので、移行の再現までは要らない)
        await _db.Database.EnsureCreatedAsync();

        // 状況説明・報告者名をどちらも小文字 ASCII にしたインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "handover memo lost",
            ReporterName = "sato",
            OccurredAt = TestFixtures.Today
        };
        // 担当者名・担当部署をどちらも小文字 ASCII にした対策を、そのインシデントにぶら下げる
        incident.PreventiveMeasures.Add(new PreventiveMeasure
        {
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "sato",
            ResponsibleDepartment = "labo",
            DueDate = TestFixtures.Today.AddDays(30),
            Priority = 2
        });
        // インシデント(と対策)を保存する
        _db.Incidents.Add(incident);
        // 変更者名を小文字 ASCII にした監査ログを 1 件用意する
        _db.AuditLogs.Add(new AuditLog
        {
            EntityName = "Incident",
            Operation = "Modified",
            ChangedBy = "sato",
            EntityKey = "1",
            ChangedAt = TestFixtures.Today
        });
        // ここまでの投入をまとめて確定する
        await _db.SaveChangesAsync();
    }

    /// <summary>DbContext と、生かしておいた接続を後片付けする。</summary>
    public async Task DisposeAsync()
    {
        // DbContext を先に閉じる
        await _db.DisposeAsync();
        // 最後に接続を閉じる(この時点でインメモリのデータベースは消える)
        await _connection.DisposeAsync();
    }

    // 状況説明・報告者名の 2 列を OR で束ねた述語が SQL へ翻訳でき、
    // 小文字で保存した値に小文字のキーワードで一致することを確かめる
    [Theory]
    [InlineData("handover")]    // 状況説明の列に一致するキーワード
    [InlineData("sato")]        // 報告者名の列に一致するキーワード
    public async Task IncidentsIndex_KeywordSearch_TranslatesToSql(string keyword)
    {
        // SQLite を使う DbContext でインシデント一覧のコントローラを組み立てる
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(TestFixtures.Clock, NullLogger<RecurrenceService>.Instance),
            TestFixtures.Clock,
            NullLogger<IncidentsController>.Instance);
        // 全部署を見られる管理者として実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        // 一覧をキーワードで絞り込む(翻訳できなければここで例外になる)
        var result = await controller.Index(keyword, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        // SQL 側でも両辺が大文字化されていれば 1 件ヒットする
        Assert.Equal(1, vm!.TotalCount);
    }

    // 担当者名・担当部署の 2 列を OR で束ねた述語について、上と同じことを確かめる
    [Theory]
    [InlineData("sato")]        // 担当者名の列に一致するキーワード
    [InlineData("labo")]        // 担当部署の列に一致するキーワード
    public async Task PreventiveMeasuresIndex_KeywordSearch_TranslatesToSql(string keyword)
    {
        // SQLite を使う DbContext でカンバンのコントローラを組み立てる
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            TestFixtures.Clock,
            NullLogger<PreventiveMeasuresController>.Instance);
        // 全部署を見られる管理者として実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        // カンバンを担当者キーワードで絞り込む(翻訳できなければここで例外になる)
        var result = await controller.Index(null, keyword, null, null, null);

        // SQL 側でも両辺が大文字化されていれば 1 件ヒットする
        var view = Assert.IsType<ViewResult>(result);
        var measures = Assert.IsType<List<PreventiveMeasure>>(view.Model);
        Assert.Single(measures);
    }

    // 列が 1 つだけ(OR で束ねない)の述語についても、同じことを確かめる
    // ——束ねる経路だけを見ていると、1 列の経路が翻訳できなくなっても気づけない
    [Fact]
    public async Task AuditLogsIndex_KeywordSearch_TranslatesToSql()
    {
        // SQLite を使う DbContext で監査ログのコントローラを組み立てる
        var controller = new AuditLogsController(_db);
        // 監査ログを閲覧できる管理者として実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        // 変更者キーワードで絞り込む(翻訳できなければここで例外になる)
        var result = await controller.Index(null, null, "sato", null, null, null, 1) as ViewResult;
        var vm = result?.Model as AuditLogListViewModel;

        // SQL 側でも両辺が大文字化されていれば 1 件ヒットする
        Assert.Equal(1, vm!.TotalCount);
    }
}
