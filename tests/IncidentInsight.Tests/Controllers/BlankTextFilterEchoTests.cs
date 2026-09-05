// テスト用ヘルパー(ユーザーコンテキストの付与など)を使う
using IncidentInsight.Tests.Helpers;
// テスト対象のコントローラ群
using IncidentInsight.Web.Controllers;
// DbContext を使う
using IncidentInsight.Web.Data;
// 画面用 ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// ViewResult を使う
using Microsoft.AspNetCore.Mvc;
// EF Core 拡張(InMemory の構成)
using Microsoft.EntityFrameworkCore;
// InMemoryEventId は InMemory プロバイダの警告 ID を参照するために必要
using Microsoft.EntityFrameworkCore.Diagnostics;
// テストでは何も出力しないロガー(NullLogger)を使うため
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// 「絞り込みに使わなかったテキスト入力は画面へ返さない」を、自由記述の絞り込みを持つ
/// 3 画面ぶんまとめて固定する(issue #204 課題 2)。
///
/// <para><b>何が壊れていたのか。</b> <c>?search=%20</c> のような空白のみの入力は
/// <c>SearchFilter.HasValue</c> が <c>false</c> なので<b>絞り込みには使われない</b>のに、
/// 受け取った値がそのまま ViewModel / ViewBag へ載っていた。結果、
/// <c>&lt;input value=&quot;…&quot;&gt;</c> に見えない値が残り、ページャのリンクが全部
/// <c>?search=%20&amp;page=N</c> になる ——バッジ・パネルは「絞り込み無し」と言っているのに
/// URL だけが値を運び続ける、という食い違い。</para>
///
/// <para><b>なぜ 1 ファイルにまとめるのか。</b> <c>UnlistedFilterValuePolicyTests</c> と同じ理由。
/// この規則は 3 画面に同じ形で現れるので、各 <c>*ControllerTests</c> へ散らすと
/// 「今どの画面が守れているか」を一覧できなくなり、次に自由記述の絞り込みを足す人が
/// また別の扱いを選んでしまう(実際そうなっていた: 発生部署・原因分類・監査ログの
/// エンティティ名／操作は既に守っていたのに、テキスト側だけが外れていた)。</para>
///
/// <para><b>あちらのファイルと役割が違う。</b> <c>UnlistedFilterValuePolicyTests</c> が
/// 答えるのは「<b>ドロップダウンが表せない</b>値をどうするか」で、選択肢を持たない
/// テキスト入力は対象外。ここが見るのはその手前の「使わなかった値を画面へ返さない」
/// だけ ——規則の正本は <c>Models/Validation/SearchFilter.Adopted</c> の解説。</para>
/// </summary>
public class BlankTextFilterEchoTests : IDisposable
{
    // 3 画面とも同じ InMemory DB を共有する(1 テストにつき 1 インスタンス)
    private readonly ApplicationDbContext _db;

    // 末尾スペースごとの貼り付け・IME の誤入力・ブラウザのオートフィルで生じる「空白のみ」の入力
    private const string BlankInput = "   ";

    public BlankTextFilterEchoTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            // InMemory プロバイダはトランザクションを持たないため出る警告を無視する
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        // テスト用の DbContext を作る
        _db = new ApplicationDbContext(options);
    }

    // テスト終了時に DbContext を解放する
    public void Dispose() => _db.Dispose();

    // --- /Incidents: フリーワード検索 -----------------------------------------

    // /Incidents を扱うコントローラを用意する(検索語・並び順の両方の検査で使う)
    private IncidentsController BuildIncidentsController()
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new Web.Services.RecurrenceService(
                new Web.Services.SystemClock(),
                NullLogger<Web.Services.RecurrenceService>.Instance),
            new Web.Services.SystemClock(),
            NullLogger<IncidentsController>.Instance);
        // 部署スコープの影響を切り離すため、全部署を見られる Admin で実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 組み立て済みのコントローラを返す
        return controller;
    }

    // /Incidents の一覧を検索語だけ指定して引き、ViewModel を取り出す
    private async Task<IncidentListViewModel> IndexIncidentsAsync(string? search)
    {
        // 依存の組み立ては共通のファクトリに任せる
        var controller = BuildIncidentsController();
        // 検索語以外の絞り込みは指定しない
        var result = await controller.Index(search, null, null, null, null, null, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }

    // 空白のみの検索語は画面へ返さない。返すと入力欄に見えない値が残り、
    // ページャの RouteValues["search"] に載ってリンクが全部その値を運ぶ
    [Theory]
    // 空文字(フォームを空のまま送信した場合)
    [InlineData("")]
    // 空白のみ
    [InlineData(BlankInput)]
    public async Task Incidents_BlankSearch_IsNotEchoedBack(string search)
    {
        // 空白のみの検索語で一覧を引く
        var vm = await IndexIncidentsAsync(search);

        // 画面へ返さない(絞り込みに使っていない値なので)
        Assert.Null(vm.Search);
    }

    // 実際に絞り込みへ使った検索語はそのまま画面へ戻す(入力欄と「絞り込み中」の表示のため)。
    // 「空白なら null」だけを見ると、常に null を返す変異が素通りする
    [Fact]
    public async Task Incidents_RealSearch_IsEchoedBack()
    {
        // 利用者が実際に入力した検索語で一覧を引く
        var vm = await IndexIncidentsAsync("転倒");

        // 受け取った値がそのまま戻る(加工もしない)
        Assert.Equal("転倒", vm.Search);
    }

    // --- /Incidents: 並び順 ---------------------------------------------------

    // 並び順(?sortBy=)は自由記述ではなく閉じた語彙だが、<b>「採用しなかった値を画面へ
    // 返さない」という不変条件は同じ</b>なので、同じファイルで固定する(issue #209)。
    //
    // <para>受け付けない値でも並び替えは既定(最新順)で動き、&lt;select&gt; も
    // 「最新順」を指すため画面の表示は食い違わない。それでも echo してはいけないのは、
    // <b>3 つ目の利用側であるページャ</b>が値を運ぶため ——
    // Views/Incidents/Index.cshtml の RouteValues["sortBy"] は
    // PagerViewModel.RouteValuesFor が null しか落とさないので、
    // ?sortBy=bogus がページャのリンク全部に付いて回る(?search=%20 と同じ壊れ方)。
    // 判定は Models/Validation/IncidentSortOrder.Adopted に集約してある。</para>

    // /Incidents の一覧を並び順だけ指定して引き、ViewModel を取り出す
    private async Task<IncidentListViewModel> IndexIncidentsBySortOrderAsync(string? sortBy)
    {
        // 検索語のときと同じ依存の組み立て方を使う(実際の依存をそのまま渡す)
        var controller = BuildIncidentsController();
        // 並び順以外の絞り込みは指定しない
        var result = await controller.Index(null, null, null, null, null, null, null, sortBy, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }

    // 受け付けない並び順は画面へ返さない
    [Theory]
    // 綴り違い・URL の改ざん
    [InlineData("bogus")]
    // 空文字(?sortBy= だけを付けた場合)
    [InlineData("")]
    // 空白のみ
    [InlineData(BlankInput)]
    // 大文字小文字違い(照合は序数比較なので受け付けない)
    [InlineData("Severity")]
    public async Task Incidents_UnsupportedSortBy_IsNotEchoedBack(string sortBy)
    {
        // 受け付けない並び順で一覧を引く
        var vm = await IndexIncidentsBySortOrderAsync(sortBy);

        // 並び替えに使っていない値なので画面へ返さない
        Assert.Null(vm.SortBy);
    }

    // 実際に適用した並び順はそのまま画面へ戻す(ドロップダウンの現在値と、ページャで
    // 引き継ぐため)。「受け付けないなら null」だけを見ると、常に null を返す変異が素通りする
    [Theory]
    [InlineData("latest")]
    [InlineData("severity")]
    [InlineData("overdue")]
    public async Task Incidents_SupportedSortBy_IsEchoedBack(string sortBy)
    {
        // 利用者が実際に選んだ並び順で一覧を引く
        var vm = await IndexIncidentsBySortOrderAsync(sortBy);

        // 受け取った値がそのまま戻る
        Assert.Equal(sortBy, vm.SortBy);
    }

    // 未指定のときも画面へは何も載せない(ページャの URL に ?sortBy=latest を足さない)
    [Fact]
    public async Task Incidents_NoSortBy_LeavesTheValueEmpty()
    {
        // 並び順を指定せずに一覧を引く
        var vm = await IndexIncidentsBySortOrderAsync(null);

        // 利用者は何も選んでいないので URL にも残さない
        Assert.Null(vm.SortBy);
    }

    // --- /AuditLogs: 変更者・対象キー -----------------------------------------

    // /AuditLogs の一覧を自由記述の 2 条件だけ指定して引き、ViewModel を取り出す
    private async Task<AuditLogListViewModel> IndexAuditLogsAsync(string? changedBy, string? entityKey)
    {
        // 監査ログ画面は DbContext だけに依存する
        var controller = new AuditLogsController(_db);
        // 監査ログは管理者専用なので Admin で実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // エンティティ名・操作種別・期間は指定しない
        var result = await controller.Index(null, null, changedBy, entityKey, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<AuditLogListViewModel>(result!.Model);
    }

    // 空白のみの変更者・対象キーは画面へ返さない。
    // この画面もページャの RouteValues をこの 2 つから組み立てるので、症状は /Incidents と同じ
    [Theory]
    // 空文字
    [InlineData("")]
    // 空白のみ
    [InlineData(BlankInput)]
    public async Task AuditLogs_BlankFreeTextFilters_AreNotEchoedBack(string blank)
    {
        // 自由記述の 2 条件をどちらも空白のみで指定する
        var vm = await IndexAuditLogsAsync(blank, blank);

        // どちらも画面へ返さない
        Assert.Null(vm.ChangedBy);
        Assert.Null(vm.EntityKey);
    }

    // 実際に絞り込みへ使った値はそのまま画面へ戻す(常に null を返す変異を落とすため)
    [Fact]
    public async Task AuditLogs_RealFreeTextFilters_AreEchoedBack()
    {
        // 利用者が実際に入力した値で一覧を引く
        var vm = await IndexAuditLogsAsync("admin", "42");

        // 受け取った値がそのまま戻る
        Assert.Equal("admin", vm.ChangedBy);
        Assert.Equal("42", vm.EntityKey);
    }

    // --- /PreventiveMeasures: 担当者・担当部署 ---------------------------------

    // /PreventiveMeasures のカンバンを自由記述の 2 条件だけ指定して引き、
    // 画面へ戻る絞り込み値(担当者, 担当部署)を取り出す
    private async Task<(object? Responsible, object? ResponsibleDepartment)> IndexMeasureFiltersAsync(
        string? responsible, string? responsibleDepartment)
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new Web.Services.SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        // 部署スコープの影響を切り離すため、全部署を見られる Admin で実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 状態・期限の絞り込みは指定しない
        await controller.Index(null, responsible, responsibleDepartment, null, null);
        // ViewBag は dynamic なので、静的な型の変数へ受けてから返す
        object? echoedResponsible = controller.ViewBag.FilterResponsible;
        object? echoedDepartment = controller.ViewBag.FilterResponsibleDepartment;
        return (echoedResponsible, echoedDepartment);
    }

    // 空白のみの担当者・担当部署は画面へ返さない。
    // この画面にページャは無いが、値が残ると再送信のたびに空白が運ばれ続ける
    [Theory]
    // 空文字
    [InlineData("")]
    // 空白のみ
    [InlineData(BlankInput)]
    public async Task PreventiveMeasures_BlankFreeTextFilters_AreNotEchoedBack(string blank)
    {
        // 自由記述の 2 条件をどちらも空白のみで指定する
        var (responsible, responsibleDepartment) = await IndexMeasureFiltersAsync(blank, blank);

        // どちらも画面へ返さない
        Assert.Null(responsible);
        Assert.Null(responsibleDepartment);
    }

    // 実際に絞り込みへ使った値はそのまま画面へ戻す(常に null を返す変異を落とすため)
    [Fact]
    public async Task PreventiveMeasures_RealFreeTextFilters_AreEchoedBack()
    {
        // 利用者が実際に入力した値でカンバンを引く
        var (responsible, responsibleDepartment) = await IndexMeasureFiltersAsync("田中", "医療安全室");

        // 受け取った値がそのまま戻る
        Assert.Equal("田中", responsible);
        Assert.Equal("医療安全室", responsibleDepartment);
    }
}
