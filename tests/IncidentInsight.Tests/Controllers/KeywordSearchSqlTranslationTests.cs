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
// 発行された SQL を拾うログの絞り込みに LogLevel を使う
using Microsoft.Extensions.Logging;
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
    // EF Core が実際に発行したコマンド(パラメータ一覧 + SQL 本文)をためる。
    // xUnit はテストごとにクラスを作り直すので、テスト間で混ざらない
    private readonly List<string> _commandLog = new();

    /// <summary>接続を開き、スキーマを作ってから検索対象のデータを 1 件ずつ入れる。</summary>
    public async Task InitializeAsync()
    {
        // インメモリのデータベースを生存させるために接続を開く
        await _connection.OpenAsync();
        // 開いたままの接続を使う DbContext を組み立てる。
        // 発行されたコマンドを拾えるようにしておく(下のパラメータ化の検査で読む)
        _db = new ApplicationDbContext(
            new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlite(_connection)
                .LogTo(_commandLog.Add, new[] { DbLoggerCategory.Database.Command.Name }, LogLevel.Information)
                .Options);
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

        // **どのキーワードにも一致しない行を、エンティティごとに 1 件ずつ置く。**
        // 一致する行だけを入れて「1 件返ること」を確かめる形だと、
        // 述語がクエリから丸ごと消えても同じ 1 件が返るため全件緑のまま通る
        // ——このクラスの目的(手で組み立てた式が翻訳器まで届いていること)が
        // 黙って検証されなくなり、痕跡はテスト件数にも出ない(実測)。
        var unrelatedIncident = new Incident
        {
            Department = "外科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level1,
            Description = "ward round done",
            ReporterName = "tanaka",
            OccurredAt = TestFixtures.Today
        };
        // 一致しない側にも対策をぶら下げる(カンバンの検索も 2 件から 1 件へ絞る形にするため)
        unrelatedIncident.PreventiveMeasures.Add(new PreventiveMeasure
        {
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "tanaka",
            ResponsibleDepartment = "ward",
            DueDate = TestFixtures.Today.AddDays(30),
            Priority = 2
        });
        // 一致しないインシデント(と対策)も保存する
        _db.Incidents.Add(unrelatedIncident);

        // 変更者名を小文字 ASCII にした監査ログを 1 件用意する(こちらがヒットする側)
        _db.AuditLogs.Add(new AuditLog
        {
            EntityName = "Incident",
            Operation = "Modified",
            ChangedBy = "sato",
            EntityKey = "1",
            ChangedAt = TestFixtures.Today
        });
        // キーワードに一致しない監査ログも 1 件置く(上と同じ理由)
        _db.AuditLogs.Add(new AuditLog
        {
            EntityName = "Incident",
            Operation = "Modified",
            ChangedBy = "tanaka",
            EntityKey = "2",
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

        // SQL 側でも両辺が大文字化されていれば、一致する 1 件だけが返る
        var view = Assert.IsType<ViewResult>(result);
        var measures = Assert.IsType<List<PreventiveMeasure>>(view.Model);
        var measure = Assert.Single(measures);
        // 返ってきたのが一致する側であることまで確かめる(件数だけだと取り違えに気づけない)
        Assert.Equal("sato", measure.ResponsiblePerson);
    }

    // キーワードが SQL に**リテラルとして埋め込まれず、パラメータとして渡る**ことを固定する。
    //
    // これは KeywordSearchPredicate の remarks が組み立て方の理由として挙げている性質だが、
    // **理由を書いただけでは守られない**: 判定を Expression.Constant で組み立て直すと
    // EF Core はキーワードを SQL 本文へ literal として展開する(Parameters は空になる)のに、
    // 他のテストは「1 件返ること」しか見ていないので全件緑のまま通る(実測)。
    // そのとき起きること:
    //   - 利用者が入力した検索語が、DB コマンドのログへそのまま載る(CLAUDE.md §9)
    //   - 検索語ごとに別のクエリ文字列になり、PostgreSQL / SQL Server の実行計画キャッシュが汚れる
    //
    // 見るのは「発行された SQL 本文」だけにする ——EF のログはヘッダ行に
    // `[Parameters=[@__normalized_0='?' ...]]` を出すので、そこまで含めて探すと
    // (a) パラメータ参照の検査がヘッダだけで満たされて骨抜きになり、
    // (b) EnableSensitiveDataLogging を有効にした瞬間、正しくパラメータとして渡した値まで
    //     「リテラルが埋まっている」と誤検出する。
    [Fact]
    public async Task KeywordSearch_PassesTheKeywordAsAParameter_NotAsALiteral()
    {
        // 種データ投入時のコマンドを捨て、これから流す検索のぶんだけを見る
        _commandLog.Clear();
        // SQLite を使う DbContext でインシデント一覧のコントローラを組み立てる
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(TestFixtures.Clock, NullLogger<RecurrenceService>.Instance),
            TestFixtures.Clock,
            NullLogger<IncidentsController>.Instance);
        // 全部署を見られる管理者として実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());

        // 大文字化されると "SATO" になるキーワードで検索する
        await controller.Index("sato", null, null, null, null, null, null, null, 1);

        // 拾ったコマンドから、両辺の大文字化が現れている SELECT(＝検索本体)を取り出す
        var searchSql = _commandLog
            .Select(ExtractSqlBody)
            .FirstOrDefault(sql => sql.Contains("upper(", StringComparison.OrdinalIgnoreCase));
        // 検索の SQL を 1 本も拾えなければ、この検査は何も見ていない(fail-closed)
        Assert.NotNull(searchSql);
        // ヘッダ行(パラメータ一覧)を実際に落とせていることを確かめる。
        // ここが残ると下の「@__ があること」がヘッダだけで満たされ、検査が骨抜きになる
        Assert.DoesNotContain("Parameters=", searchSql, StringComparison.Ordinal);

        // 大文字化したキーワードが SQL 本文に直接現れていないこと(＝リテラル展開されていない)
        Assert.DoesNotContain("SATO", searchSql, StringComparison.Ordinal);
        // 代わりに EF Core のパラメータ参照(@__ で始まる)が現れていること
        Assert.Contains("@__", searchSql, StringComparison.Ordinal);
    }

    /// <summary>
    /// EF Core のコマンドログ 1 件から、SQL 本文だけを取り出す。
    /// </summary>
    /// <remarks>
    /// ログ 1 件は「ログレベルと EventId の行」「<c>Executed DbCommand (0ms)
    /// [Parameters=[...], CommandType='Text', ...]</c> の行」「SQL 本文(複数行)」の並び。
    /// <b>先頭 1 行を落とすだけでは足りない</b> ——パラメータ一覧を載せた行が残り、
    /// 「SQL 本文にパラメータ参照があるか」の検査がその行だけで満たされてしまう。
    /// そこで <c>Executed DbCommand</c> の行を見つけ、その<b>次の行から</b>を本文とする。
    /// 見つからなければ空を返し、呼び出し側の fail-closed な検査で落とす。
    /// </remarks>
    /// <param name="logEntry">EF Core が 1 コマンドにつき 1 回渡してくるログ文字列。</param>
    /// <returns>SQL 本文(見つからなければ空文字列)。</returns>
    private static string ExtractSqlBody(string logEntry)
    {
        // 行に分ける(改行コードの違いは下の Trim で吸収する)
        var lines = logEntry.Split('\n');
        // パラメータ一覧を載せているヘッダ行の位置を探す
        var headerIndex = Array.FindIndex(lines, line => line.Contains("Executed DbCommand", StringComparison.Ordinal));
        // ヘッダが無い形式に変わっていたら、本文を取り出せないので空を返す
        if (headerIndex < 0) return string.Empty;
        // ヘッダの次の行から先が SQL 本文
        return string.Join("\n", lines.Skip(headerIndex + 1));
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
