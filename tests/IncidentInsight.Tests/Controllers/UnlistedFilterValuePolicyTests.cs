// ClaimsPrincipal(実行ロール)をテストから指定するために使う
using System.Security.Claims;
// Razor ソースからコメントと foreach の対象を取り出すために使う
using System.Text.RegularExpressions;
using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
// SearchFilter は「空値の門番」をソースで照合するときに名前を借りるために使う
using IncidentInsight.Web.Models.Validation;
using IncidentInsight.Web.Models.ViewModels;
using IncidentInsight.Web.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
// InMemoryEventId は InMemory プロバイダの警告 ID を参照するために必要
using Microsoft.EntityFrameworkCore.Diagnostics;
// テストでは何も出力しないロガー(NullLogger)を使うため
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// 「適用中の絞り込み値をドロップダウンが表せない」ときの扱いを、一覧 3 画面ぶんまとめて固定する。
///
/// <para><b>なぜ 1 ファイルにまとめるのか(issue #192)。</b> この判断は画面ごとに書かれていて
/// 三者三様になっていた。規則そのものは <c>Models/Validation/SearchFilter</c> の解説に
/// 表として集約してあるが、<b>文章は放っておけば実装から離れる</b>。ここが実際の挙動を
/// 突き合わせるので、どれかの画面が表と違う振る舞いに変われば落ちる。
/// 各 <c>*ControllerTests</c> へ散らすと「3 画面が今どうなっているか」を一覧できなくなり、
/// 次に一覧画面を足す人がまた別の方式を選んでしまう。</para>
///
/// <para><b>失敗したときは</b>、実装だけを直すのではなく <c>SearchFilter</c> の表も
/// 同じ変更セットで直すこと(片方だけ直すと、次はもう食い違いに気付けない)。</para>
///
/// <para>共通する壊れ方はどの画面でも同じ: 一致する <c>&lt;option&gt;</c> が無いと
/// ブラウザは <c>&lt;select&gt;</c> を先頭の「(全て)」の位置に置くため、絞り込みが効いたまま
/// 画面だけが「絞り込み無し」に見え、<b>そのフォームを再送信した瞬間に絞り込みが解除される</b>。
/// したがってどの画面でも守るべき不変条件は 1 つ——<b>「絞り込みに使った値は必ず選択肢にある」</b>。
/// 補完(選択肢を増やす)と不採用(絞り込みをやめる)は、その不変条件を満たす 2 通りの解でしかない。</para>
///
/// <para><b>個別の <c>*ControllerTests</c> と重なるケースがあるのは承知のうえ。</b>
/// <c>/AuditLogs</c> と <c>/PreventiveMeasures</c> の 3 件は、各コントローラのテストにも
/// 同趣旨のものがある。それでもここへ置くのは、この 2 つが答えている問いが違うため:
/// 個別のテストは「その画面が仕様どおり動くか」、ここは<b>「3 画面の方式の割り当てが
/// 表のとおりか」</b>。方式を 1 画面だけ変えると個別のテストは新しい仕様に合わせて
/// 書き換えられて緑のままだが、ここは<b>表と食い違ったまま落ちる</b>——それが狙いで、
/// 落ちたときに直すべきは実装か表のどちらかだと分かる。<b>重複そのものが検出器</b>なので、
/// 「DRY だから」という理由でこちら側を消さないこと(消すと表を守るものが無くなる)。</para>
///
/// <para><b>ここで固定できない境界: 照合順序(collation)によるずれ。</b>
/// <c>/Incidents</c> の実装は、許可リストの判定を C# の<b>序数比較</b>で、
/// どの行が一致するかの判定を<b>DB の照合順序</b>で行う。分担をこう切った理由は
/// <c>IncidentsController.ResolveDepartmentFilterAsync</c> の解説に書いてある
/// (ここに書き写すと、実装が動いたときにこちらが古くなる)。
/// アプリ側の分担は序数比較なので <b>InMemory でもそのまま動かせる</b> ——
/// <c>Incidents_DepartmentStoredWithVariantSpelling_StaysReachable</c> が固定する。</para>
///
/// <para>一方、<b>DB 側の分担はここでは動かせない</b>。InMemory も序数比較なので、
/// 照合順序が大文字小文字を区別しない配備先だけで通る枝には入らない。該当するのは
/// 「取り出した綴りを 1 件に決める並べ替え」「その綴りが既に選択肢にあるときに
/// 補完を省く判定」、そして<b>「取り出した綴りが空白のみなら採用しない門番」</b>
/// (照合順序が幅ゼロ空白等を無視可能な文字として扱う配備先でのみ到達。issue #202)で、
/// いずれも実測で「消しても全件緑」だった。最後の 1 つだけは形をソースで見張っている
/// (<c>DepartmentResolvers_GateTheAdoptedValueOnHasValue</c>) ——姉妹メソッドと
/// 対になった非対称が戻るのを防ぐため。
/// プロバイダ依存の挙動はこの repo が繰り返し当たっている死角なので、
/// <b>この付近を触る差分はレビューで「どちらの比較規則で判定しているか」
/// 「同値行の並びを固定しているか」を確かめること。</b></para>
/// </summary>
public class UnlistedFilterValuePolicyTests : IDisposable
{
    // 3 画面とも同じ InMemory DB を共有する(1 テストにつき 1 インスタンス)
    private readonly ApplicationDbContext _db;

    // 現在の許可リスト(Incident.Departments)には無いが、過去の行が持ちうる部署名。
    // CLAUDE.md が「部署の値追加は static 配列を更新(マイグレーション不要)」と明記しているとおり
    // この配列は可変なので、運用で部署名を入れ替えるとこういう値が実データに残る
    private const string RetiredDepartment = "旧・第 3 病棟";

    // 実データのどこにも存在しない部署名(打ち間違い・URL 改ざん・古いブックマークの想定)
    private const string UnknownDepartment = "存在しない部署";

    public UnlistedFilterValuePolicyTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            // InMemory プロバイダはトランザクションを持たないため出る警告を無視する
            // (本番の SQLite / SQL Server / PostgreSQL では正常に動作する)
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        // テスト用の DbContext を作る
        _db = new ApplicationDbContext(options);
    }

    // テスト終了時に DbContext を解放する
    public void Dispose() => _db.Dispose();

    // --- 共通のセットアップ ---------------------------------------------------

    // 指定した発生部署のインシデントを 1 件保存して返す
    private async Task<Incident> SeedIncidentAsync(string department)
    {
        // 一覧に出るだけの最小限のインシデントを作る
        var incident = new Incident
        {
            Department = department,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者",
            // 実行日時に依存させないため固定日を使う
            OccurredAt = TestFixtures.Today
        };
        // 追加して保存する
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 呼び出し側が Id を使えるよう返す
        return incident;
    }

    // /Incidents を扱うコントローラを用意する。
    // 実行ロールは呼び出し側が渡す —— 既定を Admin にして呼び出し側で上書きさせると、
    // AttachUser が ControllerContext を作り直すため「2 回目が勝つ」ことに依存した
    // 二重配線になる。部署スコープを見るテストの担保がその暗黙の順序に乗るのは避けたい
    private IncidentsController NewIncidentsController(ClaimsPrincipal? user = null)
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(new SystemClock(), NullLogger<RecurrenceService>.Instance),
            new SystemClock(),
            NullLogger<IncidentsController>.Instance);
        // 指定が無ければ全部署を見られる Admin(部署スコープの影響を切り離すため)
        UserContextHelper.AttachUser(controller, user ?? UserContextHelper.Admin());
        // 組み立てたコントローラを返す
        return controller;
    }

    // /Incidents の一覧を引いて ViewModel を取り出す
    private async Task<IncidentListViewModel> IndexIncidentsAsync(string? department)
    {
        // 部署以外の絞り込みは指定せずに一覧を引く
        var result = await NewIncidentsController()
            .Index(null, department, null, null, null, null, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }

    // 指定した担当部署の予防策を 1 件保存する(対策はインシデントに紐づくので親も用意する)
    private async Task SeedMeasureAsync(string responsibleDepartment)
    {
        // 親インシデントを先に作る(発生部署は担当部署の選択肢とは無関係なので現行の値でよい)
        var incident = await SeedIncidentAsync("ICU");
        // 担当部署のドロップダウンは実データから作られるので、その生成元になる 1 件を保存する
        _db.PreventiveMeasures.Add(new PreventiveMeasure
        {
            IncidentId = incident.Id,
            Description = "対策",
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = responsibleDepartment,
            MeasureType = MeasureTypeKind.ShortTerm,
            Status = MeasureStatus.Planned,
            DueDate = TestFixtures.Today
        });
        // ここまでの変更を確定させる
        await _db.SaveChangesAsync();
    }

    // /PreventiveMeasures の一覧を引いて、担当部署ドロップダウンの選択肢を取り出す
    private async Task<List<string>> IndexMeasureDepartmentOptionsAsync(string? responsibleDepartment)
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        // 部署スコープの影響を切り離すため、全部署を見られる Admin で実行する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 担当部署以外の絞り込みは指定せずに一覧を引く
        await controller.Index(null, null, responsibleDepartment, null, null);
        // ViewBag は dynamic なので、いったん静的な型の変数へ受けてから返す
        // (dynamic のままだと呼び出し側でラムダを渡す LINQ がコンパイルできない)
        object rawOptions = controller.ViewBag.ResponsibleDepartmentOptions;
        // 選択肢の一覧として取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<List<string>>(rawOptions);
    }

    // --- /Incidents: 実データにあれば補完 ------------------------------------

    // issue #192 の再現手順そのもの。許可リストから外れた過去の部署名で絞り込んだとき、
    // 絞り込みが効いたまま select が「部署（全て）」を指す状態にならないことを固定する
    [Fact]
    public async Task Incidents_RetiredDepartmentThatStillExists_IsKeptAndBackfilledIntoOptions()
    {
        // 過去の部署名を持つ行と、現行の部署名を持つ行を 1 件ずつ用意する
        await SeedIncidentAsync(RetiredDepartment);
        await SeedIncidentAsync("ICU");

        // 古いブックマーク相当のリクエスト(?department=旧・第 3 病棟)
        var vm = await IndexIncidentsAsync(RetiredDepartment);

        // 絞り込みは維持される(過去データへ到達できなくなってはいけない)
        Assert.Equal(1, vm.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal(RetiredDepartment, i.Department));
        // 画面へも同じ値が戻る(「絞り込み中」の表示と実状態を一致させるため)
        Assert.Equal(RetiredDepartment, vm.Department);
        // そして選択肢に補完されている ——これが無いと再送信で無言解除される
        Assert.Contains(RetiredDepartment, vm.DepartmentOptions);
    }

    // 補完した値は選択肢の先頭に置く(「部署（全て）」の直後)。
    // 末尾へ足すと選択肢が多い画面でスクロールしないと現在値が見えず、
    // 「選ばれていない」と誤解した利用者が別の値を選んで絞り込みを失う
    [Fact]
    public async Task Incidents_BackfilledDepartment_IsPlacedFirst()
    {
        // 過去の部署名を持つ行を用意する
        await SeedIncidentAsync(RetiredDepartment);

        // その値で絞り込む
        var vm = await IndexIncidentsAsync(RetiredDepartment);

        // 補完された値が選択肢の先頭に来ている
        Assert.Equal(RetiredDepartment, vm.DepartmentOptions[0]);
    }

    // --- /Incidents: 実データに無ければ採用しない -----------------------------

    // 打ち間違い・URL 改ざんのように実データのどこにも無い値は、絞り込みに使わず画面へも返さない。
    // 補完してしまうと、存在しない部署がドロップダウンに現れて選べるようになる
    [Fact]
    public async Task Incidents_UnknownDepartment_IsNotAppliedAndNotEchoedBack()
    {
        // 現行の部署名を持つ行だけを用意する
        await SeedIncidentAsync("ICU");

        // 実在しない部署名で絞り込もうとする
        var vm = await IndexIncidentsAsync(UnknownDepartment);

        // 絞り込みは掛からない(0 件ではなく全件が返る)
        Assert.Equal(1, vm.TotalCount);
        // 画面へも返さない(返すと「絞り込み中」バッジだけが出る食い違いになる)
        Assert.Null(vm.Department);
        // 選択肢にも足さない(存在しない部署を選べるようにしない)
        Assert.DoesNotContain(UnknownDepartment, vm.DepartmentOptions);
        // 空の選択肢も現れない。
        // 「実データに無い」と判定した値を捨て損ねると、DB から取れなかった値(null)が
        // そのまま選択肢へ入り、画面には中身の無い <option> が「部署（全て）」の直下に並ぶ。
        // 利用者にはどちらも空欄に見えるので、押しても何も起きない項目として残る。
        // 上の 3 つの Assert はこの壊れ方を素通りさせた(変異で実測)ため、明示的に固定する
        Assert.All(vm.DepartmentOptions, option => Assert.False(string.IsNullOrWhiteSpace(option),
            "部署の選択肢に空の項目を入れない(画面では「部署（全て）」と見分けが付かない)。"));
    }

    // 現行の許可リストに載っている値は、追加の問い合わせ無しでそのまま採用する。
    // 併せて、選択肢が Incident.Departments から作られていること(勝手な増減が無いこと)も見る
    [Fact]
    public async Task Incidents_ListedDepartment_IsAppliedAndOptionsStayAsDeclared()
    {
        // 許可リストの先頭にある部署を使う(値そのものを書き写さない)
        var listed = Incident.Departments[0];
        // その部署のインシデントを 1 件用意する
        await SeedIncidentAsync(listed);

        // 通常の絞り込み操作
        var vm = await IndexIncidentsAsync(listed);

        // 絞り込みは効き、値も画面へ戻る
        Assert.Equal(1, vm.TotalCount);
        Assert.Equal(listed, vm.Department);
        // 選択肢は許可リストそのまま(補完も削除も起きていない)
        Assert.Equal(Incident.Departments, vm.DepartmentOptions);
    }

    // 許可リストと大文字小文字だけが違う綴りで保存された行にも到達できる。
    // Staff の部署クレームは自由記述で EnforceKnownDepartment の対象外なので、
    // Department が "icu" の行は実在しうる。ここで許可リスト側の "ICU" へ畳むと、
    // 大文字小文字を区別する SQLite(既定)/ PostgreSQL では 0 件になり、
    // 「絞り込み無しなら見えている行が、絞り込むと消える」壊れ方になる。
    // どの行が一致するかの判定は DB に委ね、アプリ側は序数比較に統一している
    // (InMemory も序数比較なので、この経路はここで動かせる)
    [Fact]
    public async Task Incidents_DepartmentStoredWithVariantSpelling_StaysReachable()
    {
        // 許可リストの "ICU" と大文字小文字だけが違う綴りで保存された行を用意する
        await SeedIncidentAsync("icu");

        // 保存されている綴りそのままで絞り込む
        var vm = await IndexIncidentsAsync("icu");

        // 行に到達できる(アプリ側で "ICU" へ畳むとここが 0 件になる)
        Assert.Equal(1, vm.TotalCount);
        // 採用されるのは保存されている綴り
        Assert.Equal("icu", vm.Department);
        // 許可リストに(序数で)無いので選択肢へ補完されている
        // ——これが無いと select が「部署（全て）」を指し、再送信で無言解除される
        Assert.Equal("icu", vm.DepartmentOptions[0]);
    }

    // 採用しなかったことを画面へ伝える。
    // 理由(採用しない条件がデータ側の状態に依存すること、黙るとどう取り違えられるか)は
    // Models/Validation/SearchFilter の解説が正本
    [Fact]
    public async Task Incidents_WhenDepartmentIsNotAdopted_TheScreenIsToldAboutIt()
    {
        // 現行の部署名を持つ行だけを用意する
        await SeedIncidentAsync("ICU");

        // 実データに無い部署名で絞り込もうとする
        var vm = await IndexIncidentsAsync(UnknownDepartment);

        // 採用しなかったことが画面へ伝わっている
        Assert.True(vm.DepartmentFilterIgnored);
    }

    // 入力そのものが無い(または空白のみの)ときは「採用しなかった」ではない。
    // ここを区別しないと、絞り込みを使っていない普通の一覧表示でも注意書きが出続け、
    // 利用者は読まなくなる ——出しっぱなしの警告は無いのと同じ
    [Theory]
    // 未指定
    [InlineData(null)]
    // 空文字
    [InlineData("")]
    // 空白のみ
    [InlineData("   ")]
    public async Task Incidents_WhenNoDepartmentWasRequested_NoNoticeIsShown(string? department)
    {
        // 一覧に 1 件だけ用意する
        await SeedIncidentAsync("ICU");

        // 部署を指定せずに(または空白のみで)一覧を引く
        var vm = await IndexIncidentsAsync(department);

        // 注意書きは出さない
        Assert.False(vm.DepartmentFilterIgnored);
    }

    // 採用できた場合も注意書きは出さない(過去の部署名で絞り込めているケース)
    [Fact]
    public async Task Incidents_WhenDepartmentIsAdopted_NoNoticeIsShown()
    {
        // 許可リストから外れた過去の部署名を持つ行を用意する
        await SeedIncidentAsync(RetiredDepartment);

        // その値で絞り込む(補完されて採用される)
        var vm = await IndexIncidentsAsync(RetiredDepartment);

        // 絞り込めているので注意書きは不要
        Assert.False(vm.DepartmentFilterIgnored);
    }

    // 許可リストに載っている部署は、該当インシデントが 1 件も無くても絞り込む。
    // この経路（載っている値の即時採用）が抜けると、実在確認へ回って「実データに無い」と
    // 判定され、利用者は 0 件ではなく全件を見せられたうえ「1 件も無いため絞り込まずに」と
    // 説明される ——絞り込んでいない条件について語る、事実と違う案内になる。
    // 他の /Incidents のテストはどれも先に該当行を用意しているので、この組み合わせだけ
    // 検出網の外にあった（実測: 即時採用の 2 行を消しても全件緑）
    [Fact]
    public async Task Incidents_ListedDepartmentWithNoRows_StillFiltersInsteadOfShowingEverything()
    {
        // 許可リストから 2 つ選び、片方にだけインシデントを用意する。
        // 添字を決め打ちしない —— 部署一覧はマイグレーション無しで編集できる可変の配列なので、
        // 1 件に絞られた配備では検査したい方針ではなく添字の例外で落ちてしまう
        var seeded = Incident.Departments[0];
        var empty = Incident.Departments.FirstOrDefault(d => d != seeded);
        Assert.True(empty != null, "この検査には許可リストに 2 つ以上の部署が要る。");
        await SeedIncidentAsync(seeded);

        // 1 件も無い方の部署で絞り込む
        var vm = await IndexIncidentsAsync(empty);

        // 絞り込みは効いて 0 件になる(全件が返ってはいけない)
        Assert.Equal(0, vm.TotalCount);
        // 値も画面へ戻る(select が「部署（全て）」を指さない)
        Assert.Equal(empty, vm.Department);
        // 採用しているので注意書きは出さない
        Assert.False(vm.DepartmentFilterIgnored);
    }

    // 空白のみの入力は「絞り込み無し」。SearchFilter.HasValue の規則がこの経路でも効いていることと、
    // 空白が選択肢へ補完されない(＝空白だけの選択肢が現れない)ことを同時に固定する
    [Fact]
    public async Task Incidents_WhitespaceOnlyDepartment_IsNoFilterAndAddsNoOption()
    {
        // 現行の部署名を持つ行を用意する
        await SeedIncidentAsync("ICU");

        // 末尾スペースごとの貼り付け・IME の誤入力を想定した空白のみの入力
        var vm = await IndexIncidentsAsync("   ");

        // 絞り込みは掛からない(全件が返る)
        Assert.Equal(1, vm.TotalCount);
        // 画面へも返さない
        Assert.Null(vm.Department);
        // 選択肢は許可リストのまま(空白の選択肢が増えていない)
        Assert.Equal(Incident.Departments, vm.DepartmentOptions);
    }

    // 実在確認は「見えている範囲」だけで行う。スコープを外すと、Staff が ?department= を
    // 総当たりして他部署にインシデントがあるかどうかを推測できてしまう(§9 最小公開)
    [Fact]
    public async Task Incidents_Staff_CannotLearnAboutRetiredDepartmentOutsideOwnScope()
    {
        // 他部署にだけ、過去の部署名を持つ行がある状態を作る
        await SeedIncidentAsync(RetiredDepartment);
        // Staff 本人の部署の行も 1 件用意する(一覧が空にならないようにする)
        await SeedIncidentAsync("ICU");

        // 自部署 ICU の Staff としてアクセスする(ロールは組み立て時に指定する)
        var controller = NewIncidentsController(UserContextHelper.Staff("ICU"));
        var result = await controller.Index(null, RetiredDepartment, null, null, null, null, null, null, 1) as ViewResult;
        var vm = Assert.IsType<IncidentListViewModel>(result!.Model);

        // 見える範囲の外なので「存在しない値」と同じ扱いになる。
        // 選択肢に出ないので、部署名の存在そのものが画面から読み取れない
        Assert.DoesNotContain(RetiredDepartment, vm.DepartmentOptions);
        Assert.Null(vm.Department);
    }

    // --- /Incidents: 原因分類はマスタにあれば補完 -----------------------------

    // 親カテゴリ 1 件とその子カテゴリ 1 件を用意し、(親, 子)を返す。
    // 親には子と紛らわしくない名前を付けておく(補完の見出しが「親名 > 子名」であることを
    // 子の名前だけで判定できないようにするため)
    private async Task<(CauseCategory Parent, CauseCategory Child)> SeedCauseCategoryTreeAsync()
    {
        // 大分類(ドロップダウンに並ぶ側)
        var parent = new CauseCategory { Name = "ヒューマンファクター", DisplayOrder = 1 };
        // 小分類(ドロップダウンには並ばないが絞り込みには使える側)
        var child = new CauseCategory { Name = "確認不足", DisplayOrder = 1, Parent = parent };
        // まとめて保存する
        _db.CauseCategories.AddRange(parent, child);
        await _db.SaveChangesAsync();
        // 呼び出し側が Id を使えるよう返す
        return (parent, child);
    }

    // 指定した原因分類の分析を 1 件持つインシデントを保存する
    private async Task SeedIncidentWithCauseAnalysisAsync(CauseCategory category)
    {
        // 一覧に出るだけの最小限のインシデントを用意する
        var incident = await SeedIncidentAsync("ICU");
        // その分類のなぜなぜ分析をぶら下げる(絞り込みが実際に一致する状態を作る)
        _db.CauseAnalyses.Add(new CauseAnalysis
        {
            IncidentId = incident.Id,
            CauseCategoryId = category.Id,
            Why1 = "なぜ1"
        });
        await _db.SaveChangesAsync();
    }

    // /Incidents の一覧を原因分類だけで絞り込んで ViewModel を取り出す
    private async Task<IncidentListViewModel> IndexByCauseCategoryAsync(int? causeCategoryId)
    {
        // 原因分類以外の絞り込みは指定しない
        var result = await NewIncidentsController()
            .Index(null, null, null, null, null, null, causeCategoryId, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }

    // issue #195 の再現手順そのもの。子カテゴリの id で絞り込んだとき、
    // 絞り込みが効いたまま select が「原因分類（全て）」を指す状態にならないことを固定する
    [Fact]
    public async Task Incidents_ChildCauseCategory_IsKeptAndBackfilledIntoOptions()
    {
        var (_, child) = await SeedCauseCategoryTreeAsync();
        await SeedIncidentWithCauseAnalysisAsync(child);

        // 子カテゴリの id で絞り込む(詳細画面のリンクや古いブックマークからの到達を想定)
        var vm = await IndexByCauseCategoryAsync(child.Id);

        // 絞り込みは維持される(画面へも返るのでページャの URL に載り、バッジも出る)
        Assert.Equal(child.Id, vm.CauseCategoryId);
        // かつ選択肢に現れる ——「絞り込みに使った値は必ず選択肢にある」
        Assert.Contains(vm.CauseCategoryOptions, o => o.Value == child.Id.ToString());
        // 実際に絞り込みが効いている(その分析を持つ 1 件だけが出る)
        Assert.Single(vm.Incidents);
        // 採用したので注意書きは出さない
        Assert.False(vm.CauseCategoryFilterIgnored);
    }

    // 補完した子カテゴリは「親名 > 子名」で並べる。裸の子名だと、他の行が親カテゴリ名なので
    // 親と対等の分類に見える。表記は CauseCategory.FormatFullName(既存の規則)へ委ねている
    [Fact]
    public async Task Incidents_BackfilledChildCauseCategory_IsLabelledWithItsParent()
    {
        var (parent, child) = await SeedCauseCategoryTreeAsync();
        await SeedIncidentWithCauseAnalysisAsync(child);

        var vm = await IndexByCauseCategoryAsync(child.Id);

        // 補完された選択肢を取り出す
        var backfilled = Assert.Single(vm.CauseCategoryOptions, o => o.Value == child.Id.ToString());
        // 見出しは親子関係の読める表記。書式そのものは既存の規則から引く
        // (ここへ "親 > 子" と書き写すと、区切り文字を変えたときにこちらだけ古くなる)
        Assert.Equal(CauseCategory.FormatFullName(parent.Name, child.Name), backfilled.Text);
    }

    // 補完は「(全て)」の直後＝先頭に置く。末尾だとスクロールしないと現在値が見えず、
    // 「選ばれていない」と誤解した利用者が別の値を選んで絞り込みを失う(部署と同じ規則)
    [Fact]
    public async Task Incidents_BackfilledChildCauseCategory_IsPlacedFirst()
    {
        var (_, child) = await SeedCauseCategoryTreeAsync();
        await SeedIncidentWithCauseAnalysisAsync(child);
        // 補完が末尾でも先頭でも成り立たないよう、親カテゴリをもう 1 件足しておく
        _db.CauseCategories.Add(new CauseCategory { Name = "設備要因", DisplayOrder = 2 });
        await _db.SaveChangesAsync();

        var vm = await IndexByCauseCategoryAsync(child.Id);

        // 先頭が補完した子カテゴリであること
        Assert.Equal(child.Id.ToString(), vm.CauseCategoryOptions[0].Value);
    }

    // 親カテゴリの id はもともと選択肢に並んでいる。補完で 2 つ並べないことを固定する
    // (同じ id が 2 行あると、どちらを選んでも同じ結果になる紛らわしい選択肢が残る)
    [Fact]
    public async Task Incidents_ParentCauseCategory_IsAppliedWithoutDuplicatingItsOption()
    {
        var (parent, child) = await SeedCauseCategoryTreeAsync();
        await SeedIncidentWithCauseAnalysisAsync(child);

        // 親の id で絞り込む(「親を選ぶと子も拾う」仕様どおり子の分析も一致する)
        var vm = await IndexByCauseCategoryAsync(parent.Id);

        // 絞り込みは維持され、注意書きは出ない
        Assert.Equal(parent.Id, vm.CauseCategoryId);
        Assert.False(vm.CauseCategoryFilterIgnored);
        // 選択肢にちょうど 1 回だけ現れる。見出しは親カテゴリ名のまま(補完していない)
        var option = Assert.Single(vm.CauseCategoryOptions, o => o.Value == parent.Id.ToString());
        Assert.Equal(parent.Name, option.Text);
        // 子の分析を持つインシデントも拾えている
        Assert.Single(vm.Incidents);
    }

    // マスタに無い id は採用しない。絞り込みも掛けず、画面へも値を返さない
    // (返すと「絞り込み中」バッジが出てページャの URL にも載る食い違いになる)
    [Fact]
    public async Task Incidents_UnknownCauseCategory_IsNotAppliedAndNotEchoedBack()
    {
        var (parent, _) = await SeedCauseCategoryTreeAsync();
        await SeedIncidentAsync("ICU");

        // どの分類にも当たらない id で絞り込む(打ち間違い・URL 改ざん・削除済み分類の想定)
        var vm = await IndexByCauseCategoryAsync(parent.Id + 10_000);

        // 画面へ返さない
        Assert.Null(vm.CauseCategoryId);
        // 選択肢は親カテゴリのままで、存在しない id は並ばない
        Assert.Equal(new[] { parent.Id.ToString() }, vm.CauseCategoryOptions.Select(o => o.Value));
        // 絞り込みは掛かっていないので全件が出る(0 件ではない)
        Assert.Single(vm.Incidents);
        // ただし黙って落とさず、採用しなかったことを画面へ伝える
        Assert.True(vm.CauseCategoryFilterIgnored);
    }

    // 未指定は「絞り込み無し」であって「採用しなかった」ではない。
    // ここを取り違えると、絞り込みを使っていない普通の一覧表示で警告が出続ける
    [Fact]
    public async Task Incidents_WhenNoCauseCategoryWasRequested_NoNoticeIsShown()
    {
        await SeedCauseCategoryTreeAsync();
        await SeedIncidentAsync("ICU");

        var vm = await IndexByCauseCategoryAsync(null);

        Assert.Null(vm.CauseCategoryId);
        Assert.False(vm.CauseCategoryFilterIgnored);
    }

    // 実在確認は原因分類マスタに対して行い、部署スコープは掛けない。
    // 掛けると「自部署にまだ 1 件も無い分類で絞り込めない」という実害だけが出る
    // (0 件と「絞り込めない」は別物。マスタは PHI ではなく、登録画面が全ロールへ
    //  子カテゴリまで並べているので隠せてもいない ——理由の正本は SearchFilter の表)
    [Fact]
    public async Task Incidents_Staff_CanFilterByCategoryWithNoRowsInOwnScope()
    {
        var (_, child) = await SeedCauseCategoryTreeAsync();
        // その分類の分析は他部署にだけある状態を作る
        var otherIncident = await SeedIncidentAsync("外来");
        _db.CauseAnalyses.Add(new CauseAnalysis
        {
            IncidentId = otherIncident.Id,
            CauseCategoryId = child.Id,
            Why1 = "なぜ1"
        });
        // Staff 本人の部署にも別のインシデントを 1 件置く
        await SeedIncidentAsync("ICU");
        await _db.SaveChangesAsync();

        // 自部署 ICU の Staff としてその分類で絞り込む
        var controller = NewIncidentsController(UserContextHelper.Staff("ICU"));
        var result = await controller.Index(null, null, null, null, null, null, child.Id, null, 1) as ViewResult;
        var vm = Assert.IsType<IncidentListViewModel>(result!.Model);

        // 絞り込みは成立する(選択肢にも並ぶ)。結果が 0 件になるのは正しい振る舞いで、
        // 「絞り込めないので全件」とは意味が違う
        Assert.Equal(child.Id, vm.CauseCategoryId);
        Assert.Contains(vm.CauseCategoryOptions, o => o.Value == child.Id.ToString());
        Assert.False(vm.CauseCategoryFilterIgnored);
        Assert.Empty(vm.Incidents);
    }

    // --- /AuditLogs: 採用しない ----------------------------------------------

    // 監査ログのエンティティ名はコード側で閉じた集合(AuditedEntities)で、過去行も必ずその中に収まる。
    // 許可リスト外は不正入力として扱い、絞り込みも画面への echo back もしない
    [Fact]
    public async Task AuditLogs_UnlistedEntityName_IsNotAppliedAndNotEchoedBack()
    {
        // 監査対象から外れたエンティティ名を持つ過去行を用意する
        _db.AuditLogs.Add(new AuditLog
        {
            EntityName = "RetiredEntity",
            Operation = "Modified",
            ChangedBy = "admin",
            EntityKey = "1",
            ChangedAt = TestFixtures.Today
        });
        await _db.SaveChangesAsync();

        // 古いブックマーク相当のリクエスト
        var controller = new AuditLogsController(_db);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        var result = await controller.Index("RetiredEntity", null, null, null, null, null, 1) as ViewResult;
        var vm = Assert.IsType<AuditLogListViewModel>(result!.Model);

        // 絞り込みは掛からず全件が返る(「採用しない」方式)
        Assert.Equal(1, vm.TotalCount);
        // 画面へも返さない
        Assert.Null(vm.EntityName);
    }

    // 操作種別もエンティティ名とまったく同じ「閉じた集合＋採用しない」方式。
    // SearchFilter の表が /AuditLogs の行で 2 つとも名指ししているので、片方だけ固定して
    // 「表は 2 つと言っているのにテストは 1 つ」という状態を作らない
    // (表と検出網が食い違ったら、次はもう表を信じられなくなる)
    [Fact]
    public async Task AuditLogs_UnlistedOperation_IsNotAppliedAndNotEchoedBack()
    {
        // 許可リストに無い操作種別を持つ行を用意する
        _db.AuditLogs.Add(new AuditLog
        {
            EntityName = "Incident",
            Operation = "Purged",
            ChangedBy = "admin",
            EntityKey = "1",
            ChangedAt = TestFixtures.Today
        });
        await _db.SaveChangesAsync();

        // 許可リスト外の操作種別で絞り込もうとする
        var controller = new AuditLogsController(_db);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        var result = await controller.Index(null, "Purged", null, null, null, null, 1) as ViewResult;
        var vm = Assert.IsType<AuditLogListViewModel>(result!.Model);

        // 絞り込みは掛からず全件が返る
        Assert.Equal(1, vm.TotalCount);
        // 画面へも返さない
        Assert.Null(vm.Operation);
    }

    // --- /PreventiveMeasures: 補完 -------------------------------------------

    // 担当部署は自由記述で許可リストが存在せず、選択肢は実データから件数上限付きで作る。
    // 上限で切り捨てられた値も表せないため、適用値は無条件に補完する(それしか採れない)
    [Fact]
    public async Task PreventiveMeasures_ResponsibleDepartmentNotInOptions_IsBackfilled()
    {
        // 選択肢の生成元になる対策を 1 件用意する
        await SeedMeasureAsync("医療安全室");

        // 実データのどの対策にも無い担当部署で絞り込む
        var options = await IndexMeasureDepartmentOptionsAsync(UnknownDepartment);

        // 自由記述なので「実在しない」と判定する手段が無く、適用値はそのまま補完される。
        // /Incidents と方式が違うのは値の集合の性質が違うため(SearchFilter の表を参照)
        Assert.Equal(UnknownDepartment, options[0]);
    }

    // 既に選択肢にある値で絞り込んでも、選択肢が二重にならない。
    // 補完の手順は共有ヘルパ(EnsureAppliedValueIsSelectable)にあり、その中の
    // 「既にあれば足さない」判定を消すと、担当部署のドロップダウンに同じ項目が 2 つ並ぶ。
    // 補完側(値が無い場合)しか試していないとこの経路は無防備になる ——
    // ヘルパは 2 画面が共有しているので、抜けたときの影響範囲も 2 倍になる
    [Fact]
    public async Task PreventiveMeasures_ResponsibleDepartmentAlreadyInOptions_IsNotDuplicated()
    {
        // 選択肢の生成元になる対策を 1 件用意する
        await SeedMeasureAsync("医療安全室");

        // 実データから選択肢に載る値で絞り込む
        var options = await IndexMeasureDepartmentOptionsAsync("医療安全室");

        // 選択肢にちょうど 1 回だけ現れる
        Assert.Equal(1, options.Count(d => d == "医療安全室"));
    }

    // 未指定・空白のみの担当部署は選択肢へ足さない。
    //
    // この画面は「補完するかどうか」を絞り込みの有無で分けない(担当部署は自由記述で、
    // 実在しないと判定する手段が無いため)。したがって絞り込みに使っていない値も
    // そのまま共有ヘルパ EnsureAppliedValueIsSelectable へ届く ——
    // 空値の門番を消すと「担当部署（全て）」の直下に画面上は見分けの付かない空の項目が並び、
    // 押しても何も起きない選択肢として残る。
    //
    // issue #202 で呼び出し側にあった同じ判定の写しを外したので、この門番はヘルパの中の
    // 1 か所だけになった。以前は呼び出し側が手前で弾いていたため「門番を消しても全件緑」
    // だったが、これで機械的に見張られる不変条件になる
    [Theory]
    // 未指定(絞り込みを使わずに一覧を開いた場合)
    [InlineData(null)]
    // 空文字
    [InlineData("")]
    // 空白のみ(末尾スペースごとの貼り付け・IME の誤入力を想定)
    [InlineData("   ")]
    public async Task PreventiveMeasures_BlankResponsibleDepartment_AddsNoOption(string? responsibleDepartment)
    {
        // 選択肢の生成元になる対策を 1 件用意する
        await SeedMeasureAsync("医療安全室");

        // 絞り込みに使えない値で一覧を引く
        var options = await IndexMeasureDepartmentOptionsAsync(responsibleDepartment);

        // 選択肢は実データから作られたものだけ(空の項目が増えていない)
        Assert.Equal(new[] { "医療安全室" }, options);
        // 空の項目が無いことも明示的に固定する。上の Equal だけだと、将来 実データ側の
        // 選択肢が増えて期待値を並べ直すときに、この不変条件ごと緩みやすい
        Assert.All(options, option => Assert.False(string.IsNullOrWhiteSpace(option),
            "担当部署の選択肢に空の項目を入れない(画面では「担当部署（全て）」と見分けが付かない)。"));
    }

    // --- 表示側(Razor)がコントローラの結論を実際に使っているか -----------------

    // 上のコントローラ級テストは ViewModel までしか見ないので、**ビューが選択肢を
    // どこから取るか**は見ていない。実測すると、ビューを元どおり
    // `@foreach (var d in Incident.Departments)` へ戻しても上の Assert は素通りし、
    // 画面だけが issue #192 の壊れ方に戻る(補完した値の option が消えて select が
    // 「部署（全て）」を指す)。コントローラで正しく決めた結論を表示側が使わなければ
    // 意味がないので、その配線だけを Razor のソースから直接確かめる。
    //
    // 検査は対象の <select> ブロックだけを見て、<b>Razor のコメントを取り除いてから</b>
    // 判定する。素朴に書くと 3 通りに素通りした(いずれも実測):
    //   (a) ファイル全体を対象に「必要な文字列を含むか」を見ると、コメントに
    //       `@* TODO: Model.DepartmentOptions へ移行 *@` と書くだけで満たせる。
    //   (b) 「1 行に foreach と静的配列」で違反を探すと、2 行に折り返せば当たらない。
    //   (c) ブロックへ絞ってもコメントを残したままだと、(a) と同じことが
    //       <b>ブロックの中の</b>コメントでできてしまう(実際 /PreventiveMeasures の
    //       select には元からコメントが 1 つ入っている)。
    // コメントを落としたうえでブロック全体を文字列として見れば、どこで改行しようと
    // コメントに何を書こうと結論は変わらない。
    //
    // 判定は「<b>foreach が回している対象</b>がコントローラの用意した名前を含むか」に絞る。
    // 「禁止する名前を含まないか」という書き方はしない —— 画面ごとに「ありえない書き換え」を
    // 予想して列挙することになり、/PreventiveMeasures では実際に空振りしていた
    // (その画面が Incident.Departments を参照する筋書きは無く、検査が常に真だった)。
    // 回している対象そのものを見れば、別の何に差し替えられても落ちる。
    //
    // 走査対象を「その画面の 1 ブロック」に限るのは、静的配列の参照自体は他の画面
    // (登録・編集フォーム)では正しい書き方だから ——一律に禁じると正しいコードを咎める
    // 検出網になり、いずれ緩められる(この repo が繰り返し避けている形)。
    //
    // <b>対象は「補完」方式の 2 画面</b>。補完はコントローラが選択肢を増やして初めて
    // 意味を持つので、表示側が別の出所から選択肢を作った瞬間に効果が消える。
    // /AuditLogs を対象にしないのは方式が「採用しない」だから ——増やす選択肢が
    // 無く、ビューは許可リストをそのまま並べるのが正しい。ここに並んでいないことが
    // 「見落とし」ではなく「方式上いらない」であることを明記しておく
    [Theory]
    // /Incidents: 発生部署。選択肢は ViewModel(IncidentListViewModel.DepartmentOptions)から取る
    [InlineData("Incidents", "department", "Model.DepartmentOptions", "Model.Department")]
    // /Incidents: 原因分類。選択肢は ViewModel(IncidentListViewModel.CauseCategoryOptions)から取る。
    // この画面は元から ViewModel 経由だったが、コントローラが選択肢を増やすようになった
    // (子カテゴリの補完。issue #195)以上、出所を静的な一覧へ戻されると効果が消える
    [InlineData("Incidents", "causeCategoryId", "Model.CauseCategoryOptions", "Model.CauseCategoryId")]
    // /PreventiveMeasures: 担当部署。選択肢は ViewBag.ResponsibleDepartmentOptions から取る
    [InlineData("PreventiveMeasures", "responsibleDepartment", "ResponsibleDepartmentOptions", "ViewBag.FilterResponsibleDepartment")]
    public void BackfillingScreens_BuildOptionsFromTheControllersResult(
        string viewFolder, string selectName, string requiredSource, string appliedValue)
    {
        // 対象ビューの Razor ソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var viewPath = Path.Combine(RepositoryPaths.Views, viewFolder, "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = File.ReadAllText(viewPath);

        // 対象ドロップダウンの開始タグを探す(name 属性が目印)
        var selectStart = source.IndexOf($"<select name=\"{selectName}\"", StringComparison.Ordinal);
        // 見つからなければ、ビューの構造が変わったか目印が消えている。
        // 「見るべきブロックが無い＝緑」にすると検出網が黙って死ぬので fail-closed で落とす
        Assert.True(selectStart >= 0,
            $"{viewFolder}/Index.cshtml に <select name=\"{selectName}\"> が見つからない。"
            + "この検査はこのブロックの中身だけを見るので、目印を変えるならこのテストも"
            + "同じ変更セットで直すこと。");
        // 対応する閉じタグまでを切り出す(select は入れ子にならないので最初の </select> でよい)
        var selectEnd = source.IndexOf("</select>", selectStart, StringComparison.Ordinal);
        Assert.True(selectEnd > selectStart, $"{viewFolder}/Index.cshtml の <select> に対応する </select> が見つからない。");
        // Razor のコメント(@* ... *@)を取り除く。コメントで検査を満たしたり破ったりできないようにする
        var selectBlock = RazorComment.Replace(source[selectStart..selectEnd], string.Empty);

        // ブロックの中の foreach が「何を」回しているかをすべて取り出す
        var loopSources = ExtractForeachSources(selectBlock);

        // 解析できた数が、ブロック内の foreach の数と一致していることを先に確かめる。
        // ExtractForeachSources はヘッダに " in " が見つからないループを読み飛ばすが、
        // ExtractLoopBodies は波括弧しか見ないので同じループを本体として拾う。
        // 両者がずれると「出所の検査だけが素通りする」fail-open になる ——実測でも、
        // `@foreach (var d in` と対象を 2 行に分けた 2 つ目のループを足すと
        // loopSources が 1 件のままで全件緑のまま通った。
        // 解析できない書き方が現れたらここで落として、書き方か解析のどちらを直すか人に決めさせる
        var loopCount = RazorSource.CountForeach(selectBlock);
        Assert.True(loopSources.Count == loopCount,
            $"{viewFolder}/Index.cshtml の <select name=\"{selectName}\"> にある foreach {loopCount} 件のうち "
            + $"{loopSources.Count} 件しか解析できていない。解析できないループは検査から外れるので、"
            + "書き方を揃えるか ExtractForeachSources を直すこと。");
        // foreach が無ければ選択肢を組み立てていない(静的な option だけになっている)
        Assert.True(loopSources.Count > 0,
            $"{viewFolder}/Index.cshtml の <select name=\"{selectName}\"> に "
            + "選択肢を組み立てる foreach が見つからない。");

        // すべてのループがコントローラの用意した名前を回している。
        // 照合は「部分文字列を含むか」ではなく識別子の境界まで見る(ContainsIdentifier)。
        // 含むかだけで見ると、DepartmentOptions を DepartmentOptionsRaw のような
        // 別の名前へ差し替えても前置詞が一致して通ってしまう。
        // 別の出所へ差し替えても、2 つ目のループを足しても、ここで落ちる ——
        // コントローラが補完した値に一致する option が無くなったり、
        // 別の出所の選択肢が混ざったりすると、再送信で絞り込みが無言で解除されるため(issue #192)。
        // <optgroup> でのグルーピングなど、意図して複数の出所を使うようになったときは
        // この検査を「どこまで許すか」から書き直すこと
        Assert.All(loopSources, loop => Assert.True(ContainsIdentifier(loop, requiredSource),
            $"{viewFolder}/Index.cshtml の選択肢は {requiredSource} から作る。"
            + $"実際に回しているのは: {loop}"));

        // 適用中の値を selected に結び付けている。
        // 選択肢を正しく並べても、どれが現在値かを示さなければ症状はまったく同じになる
        // ——ブラウザは先頭の「(全て)」を選択状態にし、再送信で絞り込みが解除される。
        // 実測でも、selected="@(Model.Department == d)" を消す変異は
        // 「回している対象」だけを見ていた頃の検査を全件緑で素通りした。
        //
        // 判定は「ループが作る <option> の selected 属性」だけを見る。範囲を絞る理由が 2 つある:
        //   - ブロック全体に対して「Model.Department を含むか」と書くと、
        //     "Model.DepartmentOptions" を回す foreach の行がそれを満たして空振りする
        //     (実測: selected の中身を Model.Search に差し替えても全件緑で通った)。
        //   - ブロック内の最初の selected を見るだけでも足りない。静的な「(全て)」の option へ
        //     selected="@(Model.Department == null)" を足してループ側から外すと、
        //     最初の 1 つが条件を満たして通ってしまう ——そして絞り込み中は常に
        //     「(全て)」が選ばれる、という issue #192 そのものの状態になる。
        // ループ本体に限れば、どちらの逃げ道も塞がる
        var loopBodies = ExtractLoopBodies(selectBlock);
        // 本体の数もループの数と一致していること(片方だけ拾えている状態を許さない)
        Assert.True(loopBodies.Count == loopCount,
            $"{viewFolder}/Index.cshtml の foreach {loopCount} 件のうち "
            + $"{loopBodies.Count} 件しか本体を取り出せていない。");
        Assert.True(loopBodies.Count > 0,
            $"{viewFolder}/Index.cshtml の <select name=\"{selectName}\"> の foreach に本体が無い。");
        // すべてのループ本体を見る。最初の 1 つだけだと、2 つ目のループ(「補完した値を先に、
        // 続けて許可リストを」のような分割)が丸ごと検査から外れる ——実測でも、
        // selected を持たない 2 つ目のループを足すと全件緑のまま通った
        Assert.All(loopBodies, body =>
        {
            // ループ本体が作る <option> の数と、selected 属性の数が一致していること。
            // 最初の 1 つだけを見ると、本体が 2 つの <option> を出して片方にしか
            // selected を付けない書き方が素通りする ——現在値を持つ側に付いていなければ
            // select は先頭の「(全て)」を指し、再送信で絞り込みが無言で解除される
            var optionCount = Regex.Matches(body, "<option").Count;
            var selectedExpressions = ExtractAttributeValues(body, "selected");
            Assert.True(optionCount > 0,
                $"{viewFolder}/Index.cshtml のループ本体に <option> が無い。");
            Assert.True(selectedExpressions.Count == optionCount,
                $"{viewFolder}/Index.cshtml のループが作る <option> {optionCount} 件のうち "
                + $"{selectedExpressions.Count} 件にしか selected 属性が無い。"
                + "現在値を示さないと select は先頭の「(全て)」を指し、"
                + "再送信で絞り込みが無言で解除される(issue #192)。");
            // そのすべてが適用中の値と比べていること
            Assert.All(selectedExpressions, expression =>
                Assert.True(ContainsIdentifier(expression, appliedValue),
                    $"{viewFolder}/Index.cshtml の selected は {appliedValue} と比べること。"
                    + $"実際の式: {expression}"));
        });
    }

    // Razor のコメント(@* ... *@)を落とす正規表現。判定の前にコメントを取り除くのは、
    // コメントで検査を満たしたり破ったりできないようにするため(理由の正本は RazorSource)。
    // 定義そのものは登録・編集フォーム側の走査(UnlistedDepartmentSavePolicyTests)と共有する
    private static readonly Regex RazorComment = RazorSource.Comment;

    // 「採用しなかったことを画面へ伝える」旗の命名規約。ViewModel のプロパティ名の接尾辞で、
    // 下の 2 つの Razor 走査はこの規約で拾った旗の 1 つずつに掛かる
    private const string IgnoredFlagSuffix = "FilterIgnored";

    // 旗の名前を ViewModel から機械的に導く。
    //
    // なぜ書き並べないのか。 下の 2 つの検査(注意書きが描画されるか /
    // パネルを開くが「適用中」とは言わないか)は旗ごとに掛ける必要がある。
    // ここを [InlineData] の手書きにすると、3 つ目の旗を足した人が行を足し忘れた瞬間に
    // その旗だけが両方の検査から黙って外れる(fail-open)。この repo が
    // AuditSaveChangesInterceptor.AuditedEntities や LengthGovernedEntityTypes で
    // 繰り返し避けている「写しを持つ」形そのものなので、同じやり方で導出にする。
    // 実際この差分の 1 つ前の版がその状態で、CauseCategoryFilterIgnored を
    // 誰も読まない書き込み専用のプロパティにしても全件緑のまま通った。
    //
    // 1 つも拾えなければ落とす —— 命名規約ごと変えると「対象ゼロ＝全件緑」で
    // 検出網が黙って死ぬため(fail-closed)。ただしこの門番だけでは
    // 「旗のうち 1 つだけが規約から外れる」改名を捕まえられない(残りが拾えるので 0 件にならない)。
    // そこは判定の手がかりを変えた <see cref="IgnoredFilterFlags_CoverEveryFlagTheControllerSets"/>
    // が受け持つ。
    //
    // 覆っているのは /Incidents の 1 画面だけ(この導出も、照合も、下の 2 つの
    // Razor 走査も、IncidentListViewModel / IncidentsController.cs /
    // Views/Incidents/Index.cshtml を名指ししている)。「旗を足せば必ず検査に入る」のは
    // この画面の中の話で、別の一覧画面が旗を持ち始めても自動では入らない。
    // 一般化していないのは、現在この方式(「採用しない」ときに知らせる)を採っているのが
    // この画面だけだから —— /PreventiveMeasures は無条件補完で、そもそも「採用しない」枝が
    // 無いので旗を持たない(SearchFilter の表を参照)。選択肢の出所を見る
    // BackfillingScreens_BuildOptionsFromTheControllersResult は 2 画面に掛かるが、
    // あちらは ViewModel と ViewBag という別々の受け渡し方を [InlineData] で吸収している。
    // 2 画面目が旗を持ったときは、この 3 つの入り口を画面ごとに引数化すること
    // (そうしないと、その画面の旗だけが誰にも読まれない書き込み専用のプロパティになる)
    public static TheoryData<string> IgnoredFilterFlags()
    {
        // 命名規約に当てはまる bool のプロパティだけを拾う
        var flags = DeclaredIgnoredFilterFlags();

        // 1 つも見つからないのは「旗が無くなった」より「命名規約が変わった」可能性が高い。
        // 黙って 0 件の Theory にすると検出網が消えるので、ここで落として人に決めさせる
        Assert.True(flags.Count > 0,
            $"{nameof(IncidentListViewModel)} に *{IgnoredFlagSuffix} という名前の bool プロパティが 1 つも無い。"
            + "命名規約を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、旗ごとに掛かるはずの Razor の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var flag in flags) data.Add(flag);
        return data;
    }

    // ViewModel に宣言されている旗の名前(命名規約で拾い、並びを固定して返す)
    private static List<string> DeclaredIgnoredFilterFlags() =>
        typeof(IncidentListViewModel)
            .GetProperties()
            .Where(p => p.PropertyType == typeof(bool) && p.Name.EndsWith(IgnoredFlagSuffix, StringComparison.Ordinal))
            .Select(p => p.Name)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

    // 上の導出(命名規約)が旗を取りこぼしていないことを、判定とは独立な手がかりで照合する。
    //
    // 手がかりはコントローラのソース: 「採用しなかったか」は必ず解決関数が返す
    // <c>Ignored</c> から ViewModel へ写されるので、<c>… = ….Ignored</c> という代入が
    // 旗の実際の一覧になる。これは命名規約とは別の宣言箇所なので、
    // 片方だけが狭まったときに食い違いとして現れる。
    //
    // なぜ要るのか(実測)。 命名規約だけに頼ると、旗を 2 つ持つ状態で
    // 片方を規約から外れた名前(<c>CauseCategoryIgnoredFlag</c> など)へ改名すると、
    // もう片方が拾えるぶん「0 件」にはならず、上の門番をすり抜けて
    // 改名した旗だけが 2 つの Razor 走査から黙って外れた。
    // 同じ手がかりでガードを書くと導出が狭まったときにガードも一緒に狭まるので、
    // この repo が LengthGovernedTypes_CoverEveryOwnedDbSet でやっているのと同じく手がかりを変える
    [Fact]
    public void IgnoredFilterFlags_CoverEveryFlagTheControllerSets()
    {
        // コントローラのソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var controllerPath = Path.Combine(
            RepositoryPaths.WebProject, "Controllers", $"{nameof(IncidentsController)}.cs");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(controllerPath), $"コントローラのソースが見つからない: {controllerPath}");
        var source = File.ReadAllText(controllerPath);

        // 「<ViewModel のプロパティ> = <解決結果>.Ignored」という代入を全部拾う。
        // 走査の前にコメントを落とすのは、下の門番の照合と同じ理由 ——ただしこちらで効くのは
        // 「満たせる」ではなく「咎める」方向で、`// 例: SeverityFilterIgnored = severityFilter.Ignored`
        // のような普通の説明コメントを 1 行足すだけで、正しいコードのまま
        // 下の Assert.Equal が幽霊の旗を拾って落ちた(実測)。
        // 正しいコードを咎める検出網はいずれ緩められるので、同じ CSharpComment を通す
        var assigned = Regex.Matches(CSharpComment.Replace(source, string.Empty), @"(?<flag>\w+)\s*=\s*\w+\.Ignored\b")
            .Select(m => m.Groups["flag"].Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 代入が 1 つも読めないなら、書き方が変わって手がかりが死んでいる。
        // 「違反ゼロ＝緑」にせず落として、書き方かこの検査のどちらを直すか人に決めさせる
        Assert.True(assigned.Count > 0,
            $"{nameof(IncidentsController)} に「… = ….Ignored」の代入が 1 つも見つからない。"
            + "書き方を変えたなら、この照合も同じ変更セットで直すこと。");

        // 2 つの宣言箇所が一致していること。ずれていれば、命名規約から外れた旗があるか、
        // 逆に画面へ渡らなくなった旗が ViewModel に残っている
        Assert.Equal(DeclaredIgnoredFilterFlags(), assigned);
    }

    // 発生部署の 2 つの解決メソッドが、DB から読んだ綴りを採用する前に
    // SearchFilter.HasValue の門番へ通していることをソースで見張る(issue #202)。
    //
    // なぜランタイムのテストで固定できないのか。ResolveDepartmentFilterAsync が
    // 空白のみの綴りを受け取るのは、照合順序が幅ゼロ空白(U+200B)等を無視可能な文字として
    // 扱う配備先だけ ——絞り込み値は手前で HasValue を通っており非空白を 1 文字は含むので、
    // 序数比較では空白のみの行に一致しない。テストの InMemory も序数比較なのでこの枝には入らない。
    // 上の「固定できない境界」に挙げた 2 つと同じ性質で、実測でも門番を消して全件緑だった。
    //
    // 門番が要る理由(空白のみを採用すると、補完が空値を足さないぶん「絞り込みは効いているのに
    // 一致する <option> が無い」状態が残り、再送信で絞り込みが黙って解除される)は
    // 実装側のコメントが正本 ——ここへ書き写すと、方針を変えたときにこちらが古くなる。
    // ここで固定するのは<b>2 つの解決メソッドの形が揃っていること</b>だけ。
    // どちらも同じ壊れ方(採用した値が選択肢に無い)をするので、片方だけ門番を外すと
    // 非対称が戻り、次に読む人がどちらを手本にしてよいか分からなくなる
    [Theory]
    // 一覧の絞り込み側(採用しないと絞り込みが解除される)
    [InlineData("ResolveDepartmentFilterAsync")]
    // 登録・編集の保存側(採用しないと保存された発生部署が書き換わる)
    [InlineData("ResolveDepartmentSaveSelection")]
    public void DepartmentResolvers_GateTheAdoptedValueOnHasValue(string methodName)
    {
        // コントローラのソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var controllerPath = Path.Combine(
            RepositoryPaths.WebProject, "Controllers", $"{nameof(IncidentsController)}.cs");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(controllerPath), $"コントローラのソースが見つからない: {controllerPath}");
        var source = File.ReadAllText(controllerPath);

        // 対象メソッドの本文だけを切り出す(ファイル全体を見ると、他のメソッドにある
        // 同じ形の判定を数えてしまい、片方を外しても気付けない)
        var body = ExtractMethodBody(source, methodName);

        // DB から読んだ綴り(どちらのメソッドでも storedDepartment)を採用する前に
        // 空値の門番を通していること。null 判定へ戻す・門番ごと消す、のどちらでも落ちる。
        // 空白の有無に依存しない形で探すのは、注意書きの走査(下)と同じ理由 ——
        // 完全一致で書くと `HasValue( storedDepartment )` のような同じ働きの書き方を落とし、
        // 次の人が動いているコードを「直し」に行く検出網になる(dotnet format でも赤くなる)
        var gate = Regex.IsMatch(
            body,
            $@"!\s*{nameof(SearchFilter)}\.{nameof(SearchFilter.HasValue)}\s*\(\s*storedDepartment\s*\)");
        // 落ちたときに何を求めているかが分かるよう、他の Assert と同じ形で理由を書く
        Assert.True(gate,
            $"{methodName} が採用する値(storedDepartment)を "
            + $"{nameof(SearchFilter)}.{nameof(SearchFilter.HasValue)} の門番へ通していない。"
            + "姉妹メソッドと同じ形を保つこと(理由は実装側のコメントが正本)。"
            + "門番の書き方を変えたなら、この照合も同じ変更セットで直すこと。");
    }

    // C# のコメント(行コメントとブロックコメント)。
    // 検査の前に落とすのは、コメントで検査を満たせないようにするため ——
    // 実測では、門番を storedDepartment == null へ戻したうえで直前に
    // 「// 門番は !SearchFilter.HasValue(storedDepartment) で行う」と 1 行足すだけで
    // 下の Assert.Contains が成立し、全件緑のまま門番を差し戻せた。
    // Razor 側は RazorSource.Comment が同じ穴を塞いでいる(あちらの解説に同種の実測がある)。
    // 共有ヘルパへ移さないのは、C# 用の利用側がこの 1 か所しか無いため
    // (RazorSource の解説が言う「3 つ目の利用側が出たときに移す」に従う)
    private static readonly Regex CSharpComment =
        new(@"//[^\r\n]*|/\*.*?\*/", RegexOptions.Singleline | RegexOptions.Compiled);

    // 指定した名前のメソッドの本文を、コメントを落としたうえで切り出す。
    // 正規表現で「次のメソッドまで」を狙うと、宣言の書き方(戻り値の型・async の有無)に
    // 引きずられて静かに空文字を返しうるので、見つからない場合は fail-closed で落とす
    private static string ExtractMethodBody(string source, string methodName)
    {
        // 先にコメントを落とす。これで波かっこの数え方もコメント内の中かっこに乱されない
        var code = CSharpComment.Replace(source, string.Empty);

        // メソッド宣言の位置を探す(呼び出しではなく宣言を狙うため、名前の直後が引数リストで
        // かつ行頭からインデントだけが先行する形に限る)
        var declaration = Regex.Match(code, $@"^[ \t]+(?:private|public|internal).*\b{Regex.Escape(methodName)}\s*\(", RegexOptions.Multiline);
        // 宣言が読めないなら、書き方が変わって手がかりが死んでいる。
        // 「違反ゼロ＝緑」にせず落として、書き方かこの検査のどちらを直すか人に決めさせる
        Assert.True(declaration.Success,
            $"{nameof(IncidentsController)} に {methodName} の宣言が見つからない。"
            + "書き方を変えたなら、この照合も同じ変更セットで直すこと。");

        // 対応する波かっこまでを切り出す。数え方は同じファイルの ExtractBraceBlock が
        // 既に持っているので写さない(写すと、数え方の穴を塞ぐときに片方が取り残される)
        var body = ExtractBraceBlock(code, declaration.Index + declaration.Length);
        // 本文が読めないなら(式本体へ変わった・波かっこが閉じていない)、同じく落として人に判断させる
        Assert.True(body is not null,
            $"{methodName} の本文が切り出せない。書き方を変えたなら、この照合も同じ変更セットで直すこと。");

        // 引用符が残っていたら、この単純な数え方では正しく切り出せていない可能性がある。
        // 文字列・文字リテラルの中の波かっこ('{' や $"...{x}..." の対応しない片方)は
        // 深さの計算を狂わせ、本文が姉妹メソッドまで伸びて「隣の門番」で検査が成立しうる
        // ——静かに広がるより、落として人に判断させる(リテラルを足すならこの検査も一緒に直す)
        Assert.True(body!.IndexOfAny(['"', '\'']) < 0,
            $"{methodName} の本文に文字列・文字リテラルがある。波かっこを数えるこの切り出しは"
            + "リテラル内の中かっこを区別しないので、リテラルを足すならこの照合も同じ変更セットで直すこと。");

        // コメントを落とした本文を返す
        return body;
    }

    // 「採用しなかったことを画面へ伝える」旗を、ビューが実際に読んでいることを確かめる。
    // コントローラ級のテストは ViewModel までしか見ないので、@if のブロックごと消しても
    // 全件緑のまま通る(実測)。そうなると DepartmentFilterIgnored は誰も読まない
    // 書き込み専用のプロパティになり、利用者は黙って全件を見せられる ——
    // SearchFilter の表が「してはいけない」と書いている状態そのもの。
    // 選択肢の配線を Razor のソースで見張っているのと同じ理由・同じやり方で塞ぐ。
    //
    // 旗は現在 2 つあり(発生部署・原因分類)、どちらも同じ壊れ方をする。
    // 片方だけを見る形にしない —— 実測でも、原因分類の注意書きを足す前の版は
    // 部署の旗だけを見ていたので、新しい旗が誰にも読まれない書き込み専用のプロパティに
    // なっても全件緑のままだった。一覧は手書きせず IgnoredFilterFlags から導く
    [Theory]
    [MemberData(nameof(IgnoredFilterFlags))]
    public void IncidentsIndexView_RendersTheIgnoredFilterNotice(string flag)
    {
        // 一覧ビューの Razor ソースを読む(ビルド出力にはコピーされない)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        // Razor のコメントは落としてから見る(コメントで満たせないようにする)
        var source = RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);

        // 旗で表示を出し分けている。
        // 「名前がどこかに出てくるか」では足りない —— この旗は絞り込みパネルを開くかどうかの
        // 判定(anyFilter)からも参照しているので、注意書きのブロックを丸ごと消しても
        // その 1 行が条件を満たしてしまう(実測で全件緑のまま通った)。
        // 出し分けの構文そのものを探して、注意書きが実際に描画されることを確かめる。
        // 空白の有無や比較の書き方に依存しない形で探す。`@if (Model.X)` の完全一致で書くと、
        // `@if(Model.X)` のように同じ働きの正しい書き方を落としてしまい、
        // 次の人が動いているマークアップを「直し」に行く検出網になる
        var header = Regex.Match(source, $@"@if\s*\(\s*Model\.{flag}\b");
        Assert.True(header.Success,
            $"Views/Incidents/Index.cshtml が Model.{flag} で注意書きを出し分けていない。");

        // 出し分けているだけでなく、そのブロックに中身があることまで見る。
        // ヘッダだけを見ると、本文を空にする変異が素通りする
        var blockBody = ExtractBraceBlock(source, header.Index);
        Assert.True(blockBody != null,
            $"Views/Incidents/Index.cshtml の @if (Model.{flag}) に本体が無い。");
        Assert.Contains("alert", blockBody!, StringComparison.Ordinal);
        Assert.Contains("適用していません", blockBody!, StringComparison.Ordinal);
    }

    // 名前を「識別子として」照合する(部分文字列だと Model.Department が
    // Model.DepartmentOptions に一致して素通りする)。判定の正本は RazorSource で、
    // 登録・編集フォーム側の走査と共有している
    private static bool ContainsIdentifier(string text, string identifier) =>
        RazorSource.ContainsIdentifier(text, identifier);

    // 注意書きが案内する先（絞り込みパネル）が実際に開くこと、そして
    // 「フィルター適用中」の判定には混ざらないことを、両方まとめて固定する。
    //
    // この 2 つは同じ旗を使うが役割が逆で、片方へ寄せるとどちらかが必ず壊れる:
    //   - パネルの開閉に入れないと、「下の絞り込みから選び直してください」と書いてある
    //     のにパネルは閉じたまま。送った値は画面のどこにも無いので手掛かりが消える。
    //   - anyFilter（バッジと 0 件時の文言）に入れると、「適用していません」の横で
    //     バッジが「フィルター適用中」と言い、1 件も無い環境では効いていないフィルターを
    //     「クリアしてください」と促す。
    // どちらの差し戻しも実測で全件緑のまま通ったので、ソースの形で固定する。
    // 注意書きの検査と同じく、旗を 1 つずつ見る(片方だけの検査にすると新しい旗が素通りする)
    [Theory]
    [MemberData(nameof(IgnoredFilterFlags))]
    public void IncidentsIndexView_OpensTheFilterPanelForAnIgnoredValue_ButDoesNotCallItActive(string flag)
    {
        // 一覧ビューの Razor ソースを読む(Razor のコメントは落としてから見る)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);

        // パネルの開閉を決める式を取り出す
        var panel = Regex.Match(source, @"var\s+showFilterPanel\s*=(?<expr>[^;]*);");
        Assert.True(panel.Success, "showFilterPanel の判定が見つからない。");
        // 「絞り込みが効いているか」を決める式を取り出す
        var active = Regex.Match(source, @"var\s+anyFilter\s*=(?<expr>[^;]*);");
        Assert.True(active.Success, "anyFilter の判定が見つからない。");

        // パネルは開く
        Assert.True(ContainsIdentifier(panel.Groups["expr"].Value, $"Model.{flag}"),
            $"採用しなかった値があるときも絞り込みパネルを開くこと(showFilterPanel に Model.{flag} を含める)。"
            + "開かないと、注意書きが案内する「下の絞り込みから選び直す」先が閉じたままになる。");
        // ただし「適用中」ではない
        Assert.False(ContainsIdentifier(active.Groups["expr"].Value, $"Model.{flag}"),
            $"anyFilter に Model.{flag} を混ぜないこと。"
            + "混ぜると「適用していません」の注意書きの横に「フィルター適用中」バッジが出て、"
            + "0 件のときは効いていないフィルターの「クリア」を促してしまう。");

        // 判定の「定義」だけでなく「使われ方」も見る。
        // anyFilter の定義を正しく保ったまま、バッジや 0 件時の文言の側を
        // showFilterPanel へ差し替えれば同じ矛盾が戻る（実測で全件緑のまま通った）。
        //
        // anyFilter の読み手は現在 3 つある: showFilterPanel の定義、「フィルター適用中」
        // バッジ、0 件時の文言。このうち<b>「絞り込みが効いている」と主張する 2 つ</b>を
        // ここで固定する（showFilterPanel は「開くかどうか」なので対象外）。
        // <b>この列挙は自動では追随しない</b> ——「絞り込み中だけ出す」表示を新しく足す人は、
        // それを anyFilter で出し分けたうえでここへ 1 件足すこと。
        // showFilterPanel で出し分けると、注意書きの横で「絞り込み中」と主張する
        // 表示がまた増える
        var badge = Regex.Match(source, @"@if\s*\(\s*(?<flag>\w+)\s*\)\s*\{[^}]*フィルター適用中");
        Assert.True(badge.Success, "「フィルター適用中」バッジの出し分けが見つからない。");
        Assert.Equal("anyFilter", badge.Groups["flag"].Value);

        var emptyState = Regex.Match(source, @"if\s*\(\s*(?<flag>\w+)\s*\)\s*\{[^}]*一致するインシデントはありません");
        Assert.True(emptyState.Success, "0 件時の文言の出し分けが見つからない。");
        Assert.Equal("anyFilter", emptyState.Groups["flag"].Value);
    }

    /// <summary>
    /// <paramref name="from"/> 以降にある最初の <c>{ ... }</c> の中身を取り出す。
    /// 見つからなければ <c>null</c>。
    /// </summary>
    /// <remarks>
    /// <c>@if</c> の本体を切り出して「条件だけでなく中身も見る」ために使う。
    /// 条件の有無だけを見ると、本体を空にする変異が素通りする。
    /// </remarks>
    private static string? ExtractBraceBlock(string source, int from)
    {
        // 本体の開始となる波括弧を探す
        var open = source.IndexOf('{', from);
        if (open < 0) return null;

        // 入れ子を数えながら対応する閉じ波括弧を探す
        var depth = 0;
        for (var i = open; i < source.Length; i++)
        {
            if (source[i] == '{') depth++;
            else if (source[i] == '}')
            {
                depth--;
                // 深さが 0 に戻った位置が本体の終わり
                if (depth == 0) return source[(open + 1)..i];
            }
        }
        // 閉じ波括弧が無ければ解析できない
        return null;
    }

    /// <summary>
    /// ブロック内の <b>すべての</b> <c>foreach</c> の本体(<c>{ ... }</c> の中身)を取り出す。
    /// </summary>
    /// <remarks>
    /// selected の検査をループ本体へ限るために使う。ブロック全体を対象にすると、
    /// ループの外にある静的な <c>&lt;option&gt;</c> の selected で条件を満たせてしまう。
    /// 最初の 1 つに限ると、2 つ目のループが丸ごと検査から外れる。
    /// </remarks>
    private static List<string> ExtractLoopBodies(string block)
    {
        // 見つかった本体をためる
        var bodies = new List<string>();
        // 走査の開始位置
        var cursor = 0;

        while (true)
        {
            // 次の foreach の位置を探す。数える側(RazorSource.CountForeach)と同じ入口を通す
            // ——素の部分文字列検索にすると、走査対象に foreach を含む識別子
            // (class="js-foreach-host" 等)があったときだけ件数が食い違い、
            // 下の「本体を取り出せていない」という門番が実在しない問題で落ちる
            var keyword = RazorSource.NextForeachKeyword(block, cursor);
            if (keyword < 0) break;
            // 見つからない形でも無限ループにしないよう、次はこの先から探す
            cursor = keyword + RazorSource.ForeachKeywordLength;
            // その後ろにある最初の波括弧が本体の開始
            var open = block.IndexOf('{', keyword);
            if (open < 0) continue;

            // 入れ子を数えながら対応する閉じ波括弧を探す
            var depth = 0;
            for (var i = open; i < block.Length; i++)
            {
                if (block[i] == '{') depth++;
                else if (block[i] == '}')
                {
                    depth--;
                    // 深さが 0 に戻った位置が本体の終わり
                    if (depth == 0)
                    {
                        bodies.Add(block[(open + 1)..i]);
                        // 次の探索は本体の中から続ける。入れ子のループ(<optgroup> での
                        // グルーピングなど)も 1 件として数えるため —— 本体の外へ飛ばすと、
                        // 数だけ見ている loopCount や ExtractForeachSources とずれて、
                        // 正しいマークアップなのに「本体を取り出せていない」と落ちる
                        cursor = open + 1;
                        break;
                    }
                }
            }
        }

        // 見つかったすべての本体を返す
        return bodies;
    }

    /// <summary>
    /// ブロック内の <b>すべての</b> HTML 属性 <c>name="&lt;ここ&gt;"</c> の「ここ」を取り出す。
    /// </summary>
    /// <remarks>
    /// ブロック全体に対する部分文字列検査の代わりに使う。期待する名前が別の名前の
    /// <b>前置詞</b>になっている場合(<c>Model.Department</c> と <c>Model.DepartmentOptions</c>)、
    /// 「どこかに出てくるか」では別の行が条件を満たして検査が空振りするため。
    /// </remarks>
    private static List<string> ExtractAttributeValues(string block, string attributeName)
    {
        // 見つかった値をためる
        var values = new List<string>();
        // 属性名と等号・引用符までを目印にする
        var marker = $"{attributeName}=\"";
        for (var i = block.IndexOf(marker, StringComparison.Ordinal); i >= 0;
             i = block.IndexOf(marker, i + 1, StringComparison.Ordinal))
        {
            // 直前が属性名の区切り(空白かタグの開始)でなければ別の属性の一部。
            // これを見ないと selected="..." が aria-selected="..." や data-selected="..." に
            // 引っかかり、本物の selected が消えていても検査が通ってしまう
            // (§7 で aria-selected を足すのは十分ありうる)
            var before = i == 0 ? '<' : block[i - 1];
            if (!char.IsWhiteSpace(before) && before != '<') continue;
            // 値の開始位置(引用符の次)
            var valueStart = i + marker.Length;
            // 閉じ引用符を探す(Razor の式に生の " は現れない)
            var valueEnd = block.IndexOf('"', valueStart);
            // 閉じ引用符が無ければこの 1 件は解析できない
            if (valueEnd < 0) continue;
            // 引用符の中身を積む
            values.Add(block[valueStart..valueEnd]);
        }
        // 見つかったすべての値を返す
        return values;
    }

    // foreach が「何を」回しているかを取り出す。括弧を数える理由と、解析できないループを
    // 読み飛ばす性質(呼び出し側で件数を照合する必要がある)は RazorSource の解説が正本。
    // 登録・編集フォーム側の走査と共有している
    private static List<string> ExtractForeachSources(string block) =>
        RazorSource.ExtractForeachSources(block);
}
