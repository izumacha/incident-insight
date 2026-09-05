// テスト用ヘルパー(ユーザーコンテキスト・固定時刻・Razor 走査・リポジトリのパス)を使う
using IncidentInsight.Tests.Helpers;
// テスト対象のコントローラ
using IncidentInsight.Web.Controllers;
// DbContext を使う
using IncidentInsight.Web.Data;
// エンティティ(インシデント・予防策)を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別・対策の状態)を使う
using IncidentInsight.Web.Models.Enums;
// テスト対象の規則(並び順の受け付け)を使う
using IncidentInsight.Web.Models.Validation;
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
/// <c>/Incidents</c> の並び順 <c>?sortBy=</c> について、<b>規則が実際に配線されているか</b>を
/// 固定する(規則そのものは <c>Models.IncidentSortOrderTests</c>、規則の正本は
/// <see cref="IncidentSortOrder"/> の解説。issue #209)。
///
/// <para><b>何が壊れていたのか。</b> <c>?sortBy=bogus</c> のような受け付けない値は
/// 並び替えに<b>使われない</b>のに、受け取った値がそのまま ViewModel へ載っていた。
/// <c>Views/Incidents/Index.cshtml</c> は <c>RouteValues["sortBy"] = Model.SortBy</c> と
/// 書いており、<c>PagerViewModel.RouteValuesFor</c> が落とすのは <c>null</c> だけなので、
/// <b>ページャのリンクが全部 <c>?sortBy=bogus&amp;page=N</c> になる</b> ——
/// 画面の <c>&lt;select&gt;</c> は「最新順」を指しているのに URL だけが別のことを言う、
/// という <c>?search=%20</c> とまったく同じ食い違い(issue #204 課題 2)。</para>
///
/// <para><b>なぜ 3 種類の検査を 1 ファイルに置くのか。</b> この規則は
/// 「受け付ける値の一覧」「並び替えの適用」「画面への echo」「選択肢の描画」の
/// 4 か所が<b>揃って初めて</b>成立する。どれか 1 つでも別の判定を書くと
/// 「メニューは A を指しているのに並びは B」「選んでも効かない項目」といった
/// 無言の劣化になるので、揃っていることを 1 か所で見渡せるようにしておく。</para>
/// </summary>
public class IncidentSortOrderPolicyTests : IDisposable
{
    // 1 テストにつき 1 インスタンスの InMemory DB
    private readonly ApplicationDbContext _db;

    // 「今日」を固定する。期限超過の並び替えは IClock.Today と対策の期日を比べるため、
    // 実時刻のままだと実行日によって結果が変わる
    private static readonly DateTime Today = TestFixtures.Today;

    public IncidentSortOrderPolicyTests()
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

    // --- 画面への echo: 採用しなかった値を返さない ----------------------------

    // 受け付けない並び順は画面へ返さない。返すとページャのリンクが全部その値を運ぶ
    [Theory]
    // 綴り違い・URL の改ざん
    [InlineData("bogus")]
    // 空文字(?sortBy= だけを付けた場合)
    [InlineData("")]
    // 空白のみ
    [InlineData("   ")]
    // 大文字小文字違い(受け付けないので既定の最新順で表示される)
    [InlineData("Severity")]
    public async Task Index_UnsupportedSortBy_IsNotEchoedBack(string sortBy)
    {
        // 受け付けない並び順で一覧を引く
        var vm = await IndexAsync(sortBy);

        // 並び替えに使っていない値なので画面へ返さない
        Assert.Null(vm.SortBy);
    }

    // 実際に適用した並び順はそのまま画面へ戻す(ドロップダウンの現在値と、
    // ページャで引き継ぐため)。「受け付けないなら null」だけを見ると、
    // 常に null を返す変異が素通りする
    [Theory]
    [InlineData("latest")]
    [InlineData("severity")]
    [InlineData("overdue")]
    public async Task Index_SupportedSortBy_IsEchoedBack(string sortBy)
    {
        // 利用者が実際に選んだ並び順で一覧を引く
        var vm = await IndexAsync(sortBy);

        // 受け取った値がそのまま戻る
        Assert.Equal(sortBy, vm.SortBy);
    }

    // 未指定のときも画面へは何も載せない(ページャの URL に ?sortBy=latest を足さない)
    [Fact]
    public async Task Index_NoSortBy_LeavesTheValueEmpty()
    {
        // 並び順を指定せずに一覧を引く
        var vm = await IndexAsync(null);

        // 利用者は何も選んでいないので URL にも残さない
        Assert.Null(vm.SortBy);
    }

    // --- 並び替えの適用: 選択肢の値が実際に効く -------------------------------

    // 重症度の高い順を選ぶと、実際にその順で並ぶ
    [Fact]
    public async Task Index_SortBySeverity_OrdersBySeverityDescending()
    {
        // 重症度の違う 2 件を、発生日は「軽い方が新しい」順で作る。
        // こうしておくと、既定(最新順)のままなら軽い方が先に来るので
        // 「並び替えが効いていない」状態と区別できる
        await SeedIncidentAsync(IncidentSeverity.Level1, occurredAt: Today);
        await SeedIncidentAsync(IncidentSeverity.Level4, occurredAt: Today.AddDays(-5));

        // 重症度の高い順で一覧を引く
        var vm = await IndexAsync(IncidentSortOrder.Severity);

        // 重い方が先頭に来る
        Assert.Equal(
            new[] { IncidentSeverity.Level4, IncidentSeverity.Level1 },
            vm.Incidents.Select(i => i.Severity));
    }

    // 未完了の期限超過対策あり優先を選ぶと、実際にその順で並ぶ
    [Fact]
    public async Task Index_SortByOverdue_PutsOverdueIncidentsFirst()
    {
        // 期限内の対策を持つ 1 件を「新しい発生日」で作る。
        // 既定(最新順)ならこちらが先頭に来るので、並び替えが効いたことが分かる
        var onTime = await SeedIncidentAsync(IncidentSeverity.Level1, occurredAt: Today);
        await SeedMeasureAsync(onTime, dueDate: Today.AddDays(7), MeasureStatus.Planned);
        // 期限を過ぎた未完了の対策を持つ 1 件を「古い発生日」で作る
        var overdue = await SeedIncidentAsync(IncidentSeverity.Level1, occurredAt: Today.AddDays(-5));
        await SeedMeasureAsync(overdue, dueDate: Today.AddDays(-1), MeasureStatus.Planned);

        // 期限超過あり優先で一覧を引く
        var vm = await IndexAsync(IncidentSortOrder.Overdue);

        // 期限超過を持つ方が先頭に来る
        Assert.Equal(overdue.Id, vm.Incidents.First().Id);
    }

    // 受け付けない値では既定(発生日の新しい順)に倒れる。
    // 「echo しない」だけを直して並び替えの既定枝を壊す変異をここが落とす
    [Fact]
    public async Task Index_UnsupportedSortBy_FallsBackToTheLatestOrder()
    {
        // 発生日の違う 2 件を作る
        var older = await SeedIncidentAsync(IncidentSeverity.Level5, occurredAt: Today.AddDays(-5));
        var newer = await SeedIncidentAsync(IncidentSeverity.Level0, occurredAt: Today);

        // 受け付けない並び順で一覧を引く
        var vm = await IndexAsync("bogus");

        // 重症度ではなく発生日の新しい順(＝既定)で並ぶ
        Assert.Equal(new[] { newer.Id, older.Id }, vm.Incidents.Select(i => i.Id));
    }

    // --- 表示側(Razor)の配線 ---------------------------------------------------

    // ビューの並び順ドロップダウンが、受け付ける値の一覧そのものから選択肢を作っている。
    //
    // <para>コントローラ級のテストは ViewModel までしか見ないので、<b>ビューが選択肢を
    // どこから取るか</b>は見ていない。静的な &lt;option&gt; を並べ直しても上の Assert は
    // すべて素通りし、画面だけが元の壊れ方(綴りの写しが 2 か所にある状態)へ戻る
    // ——コントローラが受け付ける値と画面が出す値がずれると、メニューにあるのに
    // 選んでも効かない項目や、逆に画面から到達できない並び順が生まれる。</para>
    //
    // <para>判定は対象の &lt;select&gt; ブロックだけを見て、<b>Razor のコメントを
    // 取り除いてから</b>行う(コメントで検査を満たしたり破ったりできないようにする。
    // 走査の理由の正本は <see cref="RazorSource"/>)。</para>
    [Fact]
    public void IndexView_BuildsSortOptionsFromTheSingleSourceOfTruth()
    {
        // 並び順ドロップダウンのブロックを切り出す
        var selectBlock = ExtractSortBySelectBlock();

        // 受け付ける値の一覧を回して選択肢を作っていること。
        // 照合は識別子の境界まで見る(部分文字列だと別名への差し替えを見逃す)
        Assert.True(
            RazorSource.ContainsIdentifier(selectBlock, $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Options)}"),
            "Views/Incidents/Index.cshtml の並び順の選択肢は "
            + $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Options)} から作ること。"
            + $"実際のブロック: {selectBlock}");

        // 現在値の判定も適用側とまったく同じ関数を通していること。
        // 別の判定を書くと「メニューは A を指しているのに並びは B」になる
        Assert.True(
            RazorSource.ContainsIdentifier(selectBlock, $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Effective)}"),
            "Views/Incidents/Index.cshtml の selected は "
            + $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Effective)} で判定すること。"
            + $"実際のブロック: {selectBlock}");
    }

    // 並び順の綴りがビューに直接書かれていない。
    //
    // <para>上の検査だけでは足りない —— 一覧を回す foreach を残したまま静的な
    // &lt;option value="severity"&gt; を<b>足す</b>ことができ、そのとき綴りの写しが
    // 復活する(片方だけ直せば無言で効かなくなる元の状態)。値の出所を 1 つに保つには、
    // ブロックの中に生の綴りが現れないことまで見る必要がある。</para>
    [Fact]
    public void IndexView_DoesNotHardcodeSortKeys()
    {
        // 並び順ドロップダウンのブロックを切り出す
        var selectBlock = ExtractSortBySelectBlock();

        // 受け付けるどの値も、文字列リテラルとしてブロックに現れないこと
        Assert.All(IncidentSortOrder.Options, option =>
            Assert.False(selectBlock.Contains($"\"{option.Value}\"", StringComparison.Ordinal),
                $"Views/Incidents/Index.cshtml に並び順の綴り \"{option.Value}\" が直接書かれている。"
                + $"綴りの唯一の真実の源は {nameof(IncidentSortOrder)} で、写しを持つと"
                + "片方だけ直したときに「選んでも効かない項目」になる(issue #209)。"));
    }

    // --- ここから下はテストを組み立てるための道具 -----------------------------

    // 一覧ビューの並び順ドロップダウン(<select name="sortBy">)のブロックを取り出す
    private static string ExtractSortBySelectBlock()
    {
        // 対象ビューの Razor ソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = File.ReadAllText(viewPath);

        // 対象ドロップダウンの開始タグを探す(name 属性が目印)
        var selectStart = source.IndexOf("<select name=\"sortBy\"", StringComparison.Ordinal);
        // 見つからなければビューの構造が変わっている。検出網が黙って死なないよう fail-closed で落とす
        Assert.True(selectStart >= 0,
            "Views/Incidents/Index.cshtml に <select name=\"sortBy\"> が見つからない。"
            + "この検査はこのブロックの中身だけを見るので、目印を変えるならこのテストも"
            + "同じ変更セットで直すこと。");
        // 対応する閉じタグまでを切り出す(select は入れ子にならないので最初の </select> でよい)
        var selectEnd = source.IndexOf("</select>", selectStart, StringComparison.Ordinal);
        Assert.True(selectEnd > selectStart,
            "Views/Incidents/Index.cshtml の <select name=\"sortBy\"> に対応する </select> が見つからない。");

        // Razor のコメント(@* ... *@)を落として返す
        return RazorSource.StripComments(source[selectStart..selectEnd]);
    }

    // 一覧に出るだけの最小限のインシデントを 1 件保存する
    private async Task<Incident> SeedIncidentAsync(IncidentSeverity severity, DateTime occurredAt)
    {
        // 並び替えの検証に必要な列(重症度・発生日)だけを変え、他は固定値にする
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = severity,
            Description = "説明",
            ReporterName = "報告者",
            OccurredAt = occurredAt
        };
        // 追加して保存する
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 呼び出し側が Id を使えるよう返す
        return incident;
    }

    // 指定したインシデントへ予防策を 1 件ぶら下げる(期限超過の並び替え用)
    private async Task SeedMeasureAsync(Incident incident, DateTime dueDate, MeasureStatus status)
    {
        // 期限超過の判定に効く列(期日・状態)だけを引数で変える
        _db.PreventiveMeasures.Add(new PreventiveMeasure
        {
            IncidentId = incident.Id,
            Description = "対策",
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "内科病棟",
            MeasureType = MeasureTypeKind.ShortTerm,
            Status = status,
            DueDate = dueDate
        });
        // ここまでの変更を確定させる
        await _db.SaveChangesAsync();
    }

    // /Incidents の一覧を並び順だけ指定して引き、ViewModel を取り出す
    private async Task<IncidentListViewModel> IndexAsync(string? sortBy)
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)。
        // 時刻だけは固定する —— 期限超過の並び替えが実行日に依存しないようにするため
        var clock = new FixedClock(Today);
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new Web.Services.RecurrenceService(
                clock,
                NullLogger<Web.Services.RecurrenceService>.Instance),
            clock,
            NullLogger<IncidentsController>.Instance);
        // 部署スコープの影響を切り離すため、全部署を見られる Admin で実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 並び順以外の絞り込みは指定しない
        var result = await controller.Index(null, null, null, null, null, null, null, sortBy, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }
}
