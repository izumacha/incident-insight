// Razor のソースを走査するのに正規表現を使う
using System.Text.RegularExpressions;
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
/// <para><b>「採用しなかった値を画面へ返さない」だけは別のファイルが持つ。</b>
/// あの不変条件は <c>/Incidents</c> の並び順に固有ではなく、自由記述の検索語や
/// 他の一覧画面と<b>まったく同じ規則</b>なので、
/// <c>BlankTextFilterEchoTests</c> に集めてある ——あちらの解説が書いているとおり、
/// 画面ごと・入力ごとにファイルを分けると「今どの入力が守れているか」を
/// 一覧できなくなり、次に同じ性質の入力を足す人がまた別の扱いを選んでしまう。
/// ここが見るのは並び順に固有の配線 ——<b>並び替えが実際に効くこと</b>と、
/// <b>ビューが受け付ける値の一覧そのものから選択肢を作ること</b>。</para>
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

    // 選択肢に載っているどの並び順も、実際に「他とは違う並び」を生む。
    //
    // <para><b>なぜ要るのか。</b> 綴りを 1 か所に集めても、<b>その値を実際に並び替える
    // switch の枝</b>が対応しているかは誰も見ていなかった。実測では
    // <c>Options</c> へ 1 件足すだけ(<c>switch</c> は触らない)の変異が全件緑のまま通り、
    // 画面には新しい項目が出て URL にも載るのに、並びは既定のまま ——
    // この PR が無くそうとした「選んでも効かない項目」がそのまま再現した。</para>
    //
    // <para><b>判定は「他の並び順と結果が違うこと」</b>にする。期待する並びを
    // 選択肢ごとに書き並べると、値を足した人がそこも書き足さない限り検査に入らない
    // (＝同じ穴が残る)。データを「3 つの並びがすべて違う」ように作っておけば、
    // <c>switch</c> の枝が無い値は既定と同じ並びになって<b>必ず衝突する</b>。</para>
    [Fact]
    public async Task Index_EveryOfferedSortOrder_ProducesADistinctOrdering()
    {
        // 3 つの並び順の結果がすべて違うようにデータを作る。
        // 発生日: A > B > C / 重症度: B > C > A / 期限超過: C だけが該当
        var a = await SeedIncidentAsync(IncidentSeverity.Level0, occurredAt: Today);
        var b = await SeedIncidentAsync(IncidentSeverity.Level5, occurredAt: Today.AddDays(-1));
        var c = await SeedIncidentAsync(IncidentSeverity.Level3a, occurredAt: Today.AddDays(-2));
        // 期限を過ぎた未完了の対策を C にだけぶら下げる
        await SeedMeasureAsync(c, dueDate: Today.AddDays(-1), MeasureStatus.Planned);
        // 他の 2 件は期限内の対策を持たせる(対策の有無そのものが並びを決めないことを明示する)
        await SeedMeasureAsync(a, dueDate: Today.AddDays(7), MeasureStatus.Planned);
        await SeedMeasureAsync(b, dueDate: Today.AddDays(7), MeasureStatus.Planned);

        // 選択肢ごとに、実際に返ってくる Id の並びを集める
        var orderingsByOption = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var option in IncidentSortOrder.Options)
        {
            // その並び順で一覧を引く
            var vm = await IndexAsync(option.Value);
            // 並びを 1 本の文字列にして比較しやすくする
            orderingsByOption[option.Value] = string.Join(",", vm.Incidents.Select(i => i.Id));
        }

        // 同じ並びになった選択肢の組が無いこと。
        // あるということは、その値に対応する switch の枝が無く既定へ落ちている
        var duplicated = orderingsByOption
            .GroupBy(entry => entry.Value, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => string.Join(" と ", group.Select(entry => entry.Key)))
            .ToList();
        Assert.True(duplicated.Count == 0,
            $"並び順 {string.Join(" / ", duplicated)} が同じ並びを返している。"
            + $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Options)} に値を足したなら、"
            + $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)} の並び替えの switch にも"
            + "対応する枝を足すこと(枝が無いと既定へ落ち、メニューにあるのに選んでも効かない項目になる)。");
        // 参考: 実際に 3 通りの並びが観測できていること(データの作り方が壊れていたら落とす)
        Assert.Equal(IncidentSortOrder.Options.Count, orderingsByOption.Values.Distinct(StringComparer.Ordinal).Count());
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

        // ブロックの中の foreach が「何を」回しているかをすべて取り出す。
        // 「ブロックのどこかに名前が出てくるか」では足りない ——実測でも、
        // foreach の対象を IncidentSortOrder.Options.Take(1) にする変異や、
        // 別の一覧を回しつつ data-count="@IncidentSortOrder.Options.Count" のような
        // 囮の属性を足す変異が、その書き方では全件緑のまま通った
        var loopSources = RazorSource.ExtractForeachSources(selectBlock);

        // 解析できた数がブロック内の foreach の数と一致していることを先に確かめる。
        // ExtractForeachSources は解析できないループを読み飛ばすので、ずれたまま使うと
        // 「出所の検査だけが素通りする」fail-open になる
        var loopCount = RazorSource.CountForeach(selectBlock);
        Assert.True(loopSources.Count == loopCount,
            $"Views/Incidents/Index.cshtml の並び順の <select> にある foreach {loopCount} 件のうち "
            + $"{loopSources.Count} 件しか解析できていない。解析できないループは検査から外れるので、"
            + "書き方を揃えるか ExtractForeachSources を直すこと。");
        // foreach が無ければ選択肢を組み立てていない(静的な option だけになっている)
        Assert.True(loopSources.Count > 0,
            "Views/Incidents/Index.cshtml の並び順の <select> に選択肢を組み立てる foreach が無い。");

        // 回している対象が受け付ける値の一覧「そのもの」であること。
        // 含むかどうかでは足りない —— 実測では IncidentSortOrder.Options.Take(1) のように
        // 一部だけ回す変異が全件緑のまま通り、画面からは「重症度高順」「未完了対策あり優先」が
        // 消えて到達できなくなった(絞り込みや並べ替えを挟むのも同じ)。
        // 並び自体も定義の一部(先頭が既定)なので、ビューで加工させない
        Assert.All(loopSources, loop => Assert.Equal(
            $"{nameof(IncidentSortOrder)}.{nameof(IncidentSortOrder.Options)}", loop.Trim()));

        // ブロックが作る <option> はループの中の 1 つだけであること。
        // 静的な <option> を足す変異(綴りを定数で書けば下の検査もすり抜ける)は
        // ここで件数が増えて落ちる
        var optionTags = OptionTag.Matches(selectBlock);
        Assert.True(optionTags.Count == 1,
            $"Views/Incidents/Index.cshtml の並び順の <select> に <option> が {optionTags.Count} 件ある。"
            + "選択肢はループが作る 1 つだけにすること(静的な <option> を足すと、"
            + "受け付ける値の一覧に無い項目や重複した項目が画面に出る)。");

        // 現在値は「コントローラが実際に適用した並び順」と比べていること。
        // ビュー側で判定をやり直すと「メニューは A を指しているのに並びは B」になりうる。
        // 属性値は単一引用符でも書けるのでどちらの引用符でも拾う
        var selectedExpressions = SelectedAttribute.Matches(selectBlock)
            .Select(match => match.Groups["value"].Value).ToList();
        Assert.True(selectedExpressions.Count == optionTags.Count,
            $"Views/Incidents/Index.cshtml の並び順の <option> {optionTags.Count} 件のうち "
            + $"{selectedExpressions.Count} 件にしか selected 属性が無い。"
            + "現在値を示さないと select は先頭の項目を指し、実際の並びと食い違う。");
        Assert.All(selectedExpressions, expression => Assert.True(
            RazorSource.ContainsIdentifier(expression, $"Model.{nameof(IncidentListViewModel.EffectiveSortOrder)}"),
            $"Views/Incidents/Index.cshtml の selected は Model.{nameof(IncidentListViewModel.EffectiveSortOrder)} "
            + $"と比べること。実際の式: {expression}"));
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
        // 属性値として書かれている文字列をすべて取り出す。
        // 二重引用符しか見ないと、単一引用符で書いた <option value='severity'> が
        // 検査から外れる(実測で全件緑のまま通った。Models.MeasurePrioritySelectTests が
        // 同じ理由で両方の引用符を拾っている)
        var attributeValues = QuotedAttributeValue.Matches(selectBlock)
            .Select(match => match.Groups["value"].Value)
            .ToList();

        // 受け付けるどの値も、属性値として直接書かれていないこと
        Assert.All(IncidentSortOrder.Options, option =>
            Assert.False(attributeValues.Contains(option.Value, StringComparer.Ordinal),
                $"Views/Incidents/Index.cshtml に並び順の綴り {option.Value} が直接書かれている。"
                + $"綴りの唯一の真実の源は {nameof(IncidentSortOrder)} で、写しを持つと"
                + "片方だけ直したときに「選んでも効かない項目」になる(issue #209)。"));
    }

    // --- ここから下はテストを組み立てるための道具 -----------------------------

    // <option> の開始タグ(件数を数えるのに使う)
    private static readonly Regex OptionTag = new("<option", RegexOptions.Compiled);

    // selected 属性の値。属性値は二重引用符でも単一引用符でも書けるので両方を拾う
    private static readonly Regex SelectedAttribute =
        new("""selected\s*=\s*(?:"(?<value>[^"]*)"|'(?<value>[^']*)')""", RegexOptions.Compiled);

    // 引用符でくくられた属性値(どの属性かは問わない)。綴りの直書きを探すのに使う
    private static readonly Regex QuotedAttributeValue =
        new("""=\s*(?:"(?<value>[^"]*)"|'(?<value>[^']*)')""", RegexOptions.Compiled);

    // 一覧ビューの並び順ドロップダウン(<select name="sortBy">)のブロックを取り出す。
    // 切り出しの手順そのものは 3 つの検査で共通なので RazorSource が持つ(§6 DRY)
    private static string ExtractSortBySelectBlock()
    {
        // 対象ビューの Razor ソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");

        // 並び順の <select> ブロックだけを(コメントを落として)取り出す
        return RazorSource.ExtractSelectBlock(
            File.ReadAllText(viewPath), "<select name=\"sortBy\"", "Views/Incidents/Index.cshtml");
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
