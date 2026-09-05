// アクションの引数を走査するために使う(BindingFlags)
using System.Reflection;
// required 修飾子が残す [RequiredMember] を読むために使う
using System.Runtime.CompilerServices;
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
// 集計 JSON の中身を読む共有ヘルパー
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
// SelectListItem(選択肢リストの要素型)を判定に使う
using Microsoft.AspNetCore.Mvc.Rendering;
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
/// <c>Controllers.Internal.DepartmentFilterResolver</c> の解説に書いてある
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

    // --- /Incidents: 型として読めない絞り込み値(issue #198) --------------------------

    // 「型として読めなかった」状態を作って一覧を引く。
    //
    // 実運用では MVC のモデルバインドが ?severity=abc のような値を引数へ変換できず、
    // 引数を null にしたうえで ModelState へエラーを積む。テストはコントローラの
    // メソッドを直接呼ぶのでモデルバインドを通らないため、その結果を手で再現する:
    // 引数は null、ModelState にはその引数名でエラー。キーが引数名になるのは
    // 単純型の引数に対するモデルバインドの規則で、本体側も nameof で同じ名前を渡している
    private async Task<IncidentListViewModel> IndexWithUnreadableValueAsync(string parameterName)
    {
        // ModelState は ControllerContext と一緒に作られるので、先にコントローラを組み立てる
        var controller = NewIncidentsController();
        // 「値は届いたが、その型として読めなかった」ことを表すエラーを積む
        // (第 2 引数は MVC が入れる既定メッセージ相当。文面は判定に使われない)
        controller.ModelState.AddModelError(parameterName, "値の形式が正しくありません。");
        // 絞り込みの引数はすべて null(モデルバインドが失敗した後の状態)
        var result = await controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す
        return Assert.IsType<IncidentListViewModel>(result!.Model);
    }

    // 「読めない値を受け取ったら注意書きを出す」対象の引数を、本体とは<b>独立な手がかり</b>から導く。
    //
    // 手がかりはアクションの署名: <c>string?</c> はどんな入力でも束縛できるので
    // 「読めなかった」という状態が存在せず、<b>読めずに null へ化けうるのは Nullable&lt;T&gt; だけ</b>。
    // つまり Index が受ける Nullable の引数が、この手当てが要る入力の実際の一覧になる。
    //
    // なぜ書き並べないのか。 本体側は見張る引数名を nameof で並べて渡しており、
    // 6 つ目の型付き絞り込みを足した人がそこへ渡し忘れると、その引数だけが黙って
    // 元の壊れ方(注意書きも出ないまま全件が返る)に戻る。ここを [InlineData] の手書きに
    // すると同じ人が同じように行を足し忘れるので、検出網ごと素通りする ——
    // この repo が AuditedEntities / LengthGovernedEntityTypes / IgnoredFilterFlags で
    // 繰り返し避けている「写しを持つ」形そのもの。署名から導けば、引数を足した時点で
    // 自動でケースに入る。
    //
    // <b>拾うのは「URL 上の名前」で、C# の引数名ではない。</b> モデルバインドが ModelState の
    // キーに使うのは URL 上の名前で、本体側が渡している nameof は<b>その 2 つが一致している
    // 今だけ</b>正しい。引数名で照合すると本体とまったく同じ手がかりを共有することになり、
    // <c>[FromQuery(Name = "cause")] int? causeCategoryId</c> のような別名を付けた瞬間に
    // 本体は "causeCategoryId" を見張り MVC は "cause" にエラーを積む、という食い違いが
    // <b>両側そろって同じ名前を使うせいで検出できない</b>(＝注意書きが黙って消えるのに全件緑)。
    // URL 上の名前で拾えば、別名を付けた時点でこの Theory が "cause" を渡して落ちる。
    // 判定は ?department= の照合と同じ QueryStringName に集約してある(§6 DRY)
    //
    // 1 つも拾えなければ落とす(fail-closed)。引数の型をすべて string? へ変えるような
    // 改修で「対象ゼロ＝全件緑」になり、検出網が黙って死ぬのを防ぐ
    public static TheoryData<string> NullableFilterParameters()
    {
        // Index の引数のうち Nullable<T>(値として読めなければ null に化けるもの)だけを、
        // モデルバインドが ModelState のキーに使う「URL 上の名前」で拾う
        var names = typeof(IncidentsController)
            .GetMethod(nameof(IncidentsController.Index))!
            .GetParameters()
            .Where(p => Nullable.GetUnderlyingType(p.ParameterType) != null)
            .Select(p => QueryStringName(p)!)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 0 件は「対象が無くなった」より「引数の型か導出が変わった」可能性が高い
        Assert.True(names.Count > 0,
            $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)} に Nullable の引数が 1 つも無い。"
            + "引数の型を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、読めない値の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var name in names) data.Add(name);
        return data;
    }

    // 型として読めない絞り込み値でも、黙って落とさず注意書きを出すこと(issue #198)。
    //
    // 直っていなかった頃の再現手順: /Incidents?causeCategoryId=abc を開くと
    // モデルバインドが失敗して causeCategoryId は null になり、解決処理は「未指定」と
    // 判断して Ignored: false を返す ——注意書きも「フィルター適用中」バッジも出ないまま
    // 全件が返る。?causeCategoryId=0(実在しない id)なら注意書きが出るのに、綴りが
    // 数値でないと消える、という一貫性の欠如そのもの。
    //
    // 引数ごとに掛けるのは、本体側が nameof を並べて渡す形だから ——
    // まとめて 1 件だけ見る検査にすると、5 つのうち 1 つを渡し忘れても緑のまま通る
    [Theory]
    [MemberData(nameof(NullableFilterParameters))]
    public async Task IncidentsIndex_ReportsAFilterValueThatCannotBeRead(string parameterName)
    {
        // 一覧に出る行を 1 件用意する(注意書きが「0 件だから出た」のではないことを示すため)
        await SeedIncidentAsync("ICU");

        // その引数だけが「読めなかった」状態で一覧を引く
        var vm = await IndexWithUnreadableValueAsync(parameterName);

        // 受け取ったのに採用しなかったことを画面へ伝えている
        Assert.True(vm.MalformedFilterIgnored,
            $"?{parameterName}=<読めない値> を受け取ったのに注意書きが出ない。"
            + $"MalformedFilterValueResolver へ {parameterName} を渡し忘れていないか、"
            + "あるいは [FromQuery(Name = ...)] で URL 上の名前を変えたのに本体が nameof の"
            + "引数名を渡したままになっていないか確認すること"
            + "(ModelState のキーになるのは URL 上の名前で、C# の引数名ではない)。");

        // 絞り込みは掛かっていない(全件が返る)。これは「読めない値では絞り込めない」以上
        // 避けられないので、注意書きはまさにこの状態を伝えるためにある
        Assert.Single(vm.Incidents);
    }

    // 逆に、正しく読めた値では注意書きを出さないこと。
    //
    // <b>ModelState にエントリがあること自体を条件にしてはいけない。</b>
    // モデルバインドは<b>成功した引数にもエントリを作る</b>(束縛した値を記録するため)ので、
    // キーの存在で判定すると<b>正しい値を送るたびに注意書きが出る</b>(誤検知)。
    // 出っぱなしの警告は読み飛ばされるようになり、本物の注意書きまで効かなくなる。
    //
    // <b>この誤検知はコントローラを直接呼ぶだけでは再現しない</b>(モデルバインドを通らないので
    // ModelState が空のまま)。実測でも、判定を「エントリの有無」へ差し替える変異は
    // 他の検査をすべて素通りして<b>全件緑のまま通った</b>。そこで
    // <c>SetModelValue</c> で「束縛に成功した引数」の状態(エラーの無いエントリ)を作る ——
    // これは MVC が成功時に行うのと同じ記録の仕方
    [Theory]
    [MemberData(nameof(NullableFilterParameters))]
    public async Task IncidentsIndex_DoesNotReportAnything_WhenTheFilterValueWasReadable(string parameterName)
    {
        // 一覧に出る行を 1 件用意する
        await SeedIncidentAsync("ICU");

        // ModelState は ControllerContext と一緒に作られるので、先にコントローラを組み立てる
        var controller = NewIncidentsController();
        // 「値が届いて、束縛にも成功した」状態を作る(エラーの無いエントリ)
        controller.ModelState.SetModelValue(parameterName, "1", "1");
        // 絞り込みの値そのものはこのテストの関心ではない(見るのは注意書きを出さないことだけ)
        var result = await controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = Assert.IsType<IncidentListViewModel>(result!.Model);

        // 読めなかった値は無いので注意書きは出ない
        Assert.False(vm.MalformedFilterIgnored,
            $"?{parameterName}=<読める値> で注意書きが出ている。"
            + "MalformedFilterValueResolver が「エントリの有無」ではなく"
            + "「エラーの有無」を見ているか確認すること。");
    }

    // 実際に読める値を渡したときも注意書きが出ず、絞り込み自体は効くこと。
    // 上の Theory が ModelState の作り方を模した検査なのに対し、こちらは
    // 引数として本物の値が入ってきた通常の経路を通す(模した状態が実態とずれていないかの裏取り)
    [Fact]
    public async Task IncidentsIndex_DoesNotReportAnything_WhenEveryFilterValueIsReadable()
    {
        // 一覧に出る行を 1 件用意する
        var incident = await SeedIncidentAsync("ICU");

        // すべての型付き絞り込みへ、実際に読める値を渡して一覧を引く
        var result = await NewIncidentsController().Index(
            null, null, incident.IncidentType, incident.Severity,
            TestFixtures.Today.AddDays(-1), TestFixtures.Today.AddDays(1), null, null, 1) as ViewResult;
        var vm = Assert.IsType<IncidentListViewModel>(result!.Model);

        // 読めない値は 1 つも無かったので注意書きは出ない
        Assert.False(vm.MalformedFilterIgnored);
        // 絞り込みは実際に効いている(値が素通りしていないことの裏取り)
        Assert.Single(vm.Incidents);
    }

    // 未指定(そもそも値が届いていない)でも注意書きを出さないこと。
    //
    // ?severity= のような空の入力は null 許容型へ null として問題なく束縛され
    // ModelState にエラーを積まないので、ここは「エラーの有無」を見る判定が
    // 空入力を誤って拾わないことの確認になる
    [Fact]
    public async Task IncidentsIndex_DoesNotReportAnything_WhenNoFilterValueWasSent()
    {
        // 一覧に出る行を 1 件用意する
        await SeedIncidentAsync("ICU");

        // 絞り込みを一切指定せずに一覧を引く
        var vm = await IndexIncidentsAsync(null);

        // 受け取っていないものは「採用しなかった」ではない
        Assert.False(vm.MalformedFilterIgnored);
    }

    // --- /Incidents: enum の定義に無い絞り込み値(issue #208) ------------------------

    // 「読めるが定義に無い」enum の絞り込み対象を、本体とは<b>独立な手がかり</b>から導く。
    //
    // 手がかりはアクションの署名: <c>Enum.IsDefined</c> から外れうるのは
    // <b>Nullable&lt;TEnum&gt; の引数だけ</b>(string? はどんな値でも束縛でき、int? / DateTime? に
    // 「定義」という概念が無い)。つまり Index が受ける Nullable の enum 引数が、
    // この手当てが要る入力の実際の一覧になる。
    //
    // なぜ書き並べないのか。 本体側は enum の引数 1 つずつに解決処理を呼ぶ形なので、
    // 3 つ目の enum 絞り込みを足した人が通し忘れると、その引数だけが黙って元の壊れ方
    // (絞り込みが掛かって 0 件・select は「（全て）」・再送信で無言解除)に戻る。
    // ここを [InlineData] の手書きにすると同じ人が同じように行を足し忘れるので、
    // 検出網ごと素通りする —— NullableFilterParameters と同じ理由・同じやり方で導出にする。
    //
    // <b>手がかりを「読めない値」の Theory と分けている</b>のは、再現のさせ方が違うため。
    // ?severity=99 は ModelState にエラーを積まないので、あちらの作り方(エラーを手で積む)
    // では再現しない ——こちらは実際に未定義の enum 値を引数へ渡す必要がある。
    //
    // 1 つも拾えなければ落とす(fail-closed)。enum の引数を int? へ変えるような改修で
    // 「対象ゼロ＝全件緑」になり、検出網が黙って死ぬのを防ぐ
    public static TheoryData<string> EnumFilterParameters()
    {
        // Index の引数のうち Nullable<TEnum> だけを、C# の引数名で拾う
        // (この Theory は引数の位置へ値を差し込むので、URL 上の名前ではなく引数名で照合する)
        var names = EnumFilterParameterInfos()
            .Select(p => p.Name!)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 0 件は「対象が無くなった」より「引数の型か導出が変わった」可能性が高い
        Assert.True(names.Count > 0,
            $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)} に Nullable の enum 引数が 1 つも無い。"
            + "引数の型を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、定義に無い enum 値の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var name in names) data.Add(name);
        return data;
    }

    // Index が受ける Nullable<TEnum> の引数。
    // 上の導出(Theory のケース)と、下の呼び出しヘルパ(引数の位置決め)が同じここを読む ——
    // 写しを持つと、条件を直したときに片方だけ取り残される(§6 DRY)
    private static List<ParameterInfo> EnumFilterParameterInfos() =>
        typeof(IncidentsController)
            .GetMethod(nameof(IncidentsController.Index))!
            .GetParameters()
            .Where(p => Nullable.GetUnderlyingType(p.ParameterType)?.IsEnum == true)
            .ToList();

    // 指定した enum 型の「定義に無い値」を 1 つ作る。
    //
    // 定数を書かない(99 など)のは、将来その値が enum へ足されたときに検査が
    // <b>「定義にある値」を渡す無害なテストへ黙って化ける</b>から ——
    // 実際に定義されている値をすべて見て、そこから外れる値を導く。
    // (実際 IncidentTypeKind.Other は 99 として定義済みで、?incidentType=99 は
    //  「その他」で正しく絞り込まれる。定数を書いていたらこの検査は空振りしていた)
    //
    // <b>探す範囲は基になる整数型の範囲に限る。</b> 「列挙は有限なので必ず見つかる」は
    // 成り立たない —— 例えば byte を基とする enum で 256 個すべてが定義済みなら、
    // 候補 256 は Enum.ToObject が切り詰めて 0(定義済みの値)を返す。
    // 黙って定義済みの値を渡すと、この後の Assert が「解決処理へ通し忘れていないか」という
    // <b>見当違いの案内</b>で落ちるので、飽和している場合はその事実を名指しして落とす
    private static object UndefinedValueFor(Type enumType)
    {
        // 基になる整数型(byte / int / long など)を調べる
        var underlying = Enum.GetUnderlyingType(enumType);
        // 定義済みの値を long で集める。ulong を基とする enum は long へ収まらない値を
        // 持ちうるので、その場合はここで落として人に判断させる(黙って例外にしない)
        Assert.True(underlying != typeof(ulong),
            $"{enumType.Name} は ulong を基とする enum で、この探索は long で候補を数える。"
            + "基の型を変えたなら、この導出も同じ変更セットで直すこと。");
        var defined = Enum.GetValues(enumType).Cast<object>()
            .Select(v => Convert.ToInt64(v))
            .ToHashSet();

        // 探索の範囲は基の型が表せる範囲(切り詰めで定義済みの値へ化けない範囲)。
        // 負の側も見るのは、符号付きの基の型では非負だけを探して尽きても
        // まだ未定義の値が残っており、「作れない」と言うのが事実に反するため
        var max = Convert.ToInt64(underlying.GetField("MaxValue")!.GetValue(null));
        var min = Convert.ToInt64(underlying.GetField("MinValue")!.GetValue(null));
        // 0 から順に、定義に無い最初の整数を探す(先に非負を見るのは、
        // ?severity=99 のような「URL に書かれやすい値」に近い候補を選ぶため)
        for (long candidate = 0; candidate <= max; candidate++)
        {
            // 定義済みならこの候補は使えない
            if (defined.Contains(candidate)) continue;
            // 定義に無い値が見つかったので、その enum 型の値へ変換して返す
            return Enum.ToObject(enumType, candidate);
        }
        // 非負が尽きたら負の側を見る(符号無しの基の型なら min は 0 なのでこのループは回らない)
        for (long candidate = -1; candidate >= min; candidate--)
        {
            // 定義済みならこの候補は使えない
            if (defined.Contains(candidate)) continue;
            // 定義に無い値が見つかったので、その enum 型の値へ変換して返す
            return Enum.ToObject(enumType, candidate);
        }

        // 表せる値がすべて定義済み。この検査は成立しないので、理由を名指しして落とす
        Assert.Fail($"{enumType.Name} は基の型({underlying.Name})が表せる値をすべて定義しており、"
            + "「定義に無い値」を作れない。この検査は成立しないので、"
            + "enum の定義かこの導出のどちらを直すか人が決めること。");
        // Assert.Fail は必ず例外を投げるのでここへは到達しない(コンパイラのための return)
        return null!;
    }

    // 指定した enum 引数にだけ値を入れて一覧を引く。
    //
    // 「定義に無い値」を渡す検査と「定義にある値」を渡す検査が同じ呼び出し方をするので、
    // 値の作り方だけを引数(valueFor)で受け取って本体は共有する ——
    // 写すと、Index の署名の扱い(引数の埋め方)を直したときに片方だけ取り残され、
    // <b>コンパイルも通り緑のまま別の引数へ値を差し込む</b>テストになる(§6 DRY)。
    //
    // 引数の位置を反射で決めるのも同じ理由 —— 位置を手で書くと、Index の引数の並びを
    // 変えた人がここを直し忘れた瞬間に、何も検査していないテストへ黙って化ける
    private async Task<IncidentListViewModel> IndexWithEnumArgAsync(
        string parameterName, Func<Type, object> valueFor)
    {
        // 対象の引数が導出の一覧に載っていること(名前を取り違えたまま
        // 「どの引数にも値が入らない」テストになるのを防ぐ)
        var enumParameters = EnumFilterParameterInfos();
        Assert.True(enumParameters.Any(p => p.Name == parameterName),
            $"{parameterName} は Index の Nullable<TEnum> 引数ではない。"
            + "引数名か導出を変えたなら、この呼び出しも同じ変更セットで直すこと。");

        // Index の引数をすべて既定値(null / page は 1)で埋めた配列を作る
        var method = typeof(IncidentsController).GetMethod(nameof(IncidentsController.Index))!;
        var parameters = method.GetParameters();
        var args = new object?[parameters.Length];
        for (var i = 0; i < parameters.Length; i++)
        {
            // 対象の引数にだけ、呼び出し側が決めた作り方で値を入れる
            if (parameters[i].Name == parameterName)
                args[i] = valueFor(Nullable.GetUnderlyingType(parameters[i].ParameterType)!);
            // 値型(page: int)は既定値を、参照型・Nullable は null を入れる。
            // 既定値を持たない値型はその型の既定値を作る —— 1 のような整数リテラルを
            // 置くと、int 以外の値型引数(Guid / DateTime / bool など)を足した瞬間に
            // Invoke が「Int32 は変換できない」で落ち、enum の方式とは無関係な
            // 見当違いのエラーで両 Theory の全ケースが赤くなる
            else if (parameters[i].ParameterType.IsValueType
                     && Nullable.GetUnderlyingType(parameters[i].ParameterType) == null)
                args[i] = parameters[i].HasDefaultValue
                    ? parameters[i].DefaultValue
                    : Activator.CreateInstance(parameters[i].ParameterType);
            else
                args[i] = null;
        }

        // 反射でアクションを呼ぶ(戻り値は Task<IActionResult>)
        var controller = NewIncidentsController();
        var result = await (Task<IActionResult>)method.Invoke(controller, args)!;
        // 一覧ビューのモデルとして取り出す
        var view = Assert.IsType<ViewResult>(result);
        return Assert.IsType<IncidentListViewModel>(view.Model);
    }

    // enum として束縛できても定義に無い値なら、絞り込みを掛けず画面へも返さないこと(issue #208)。
    //
    // 直っていなかった頃の再現手順: /Incidents?severity=99 を開くと
    // severity.HasValue == true なので Where(i => i.Severity == (IncidentSeverity)99) が
    // <b>実際に掛かって 0 件</b>になる。MalformedFilterIgnored は false(束縛は成功している)
    // なので画面は「フィルター適用中」バッジ＋「条件に一致するインシデントはありません」を出す。
    // ところが重症度の <select> には一致する <option> が無いので「重症度（全て）」の位置に戻り、
    // その絞り込みパネルで「検索」を押すと severity="" が送られて<b>絞り込みが黙って解除される</b>。
    //
    // 引数ごとに掛けるのは、本体側が enum の引数 1 つずつに解決処理を呼ぶ形だから ——
    // まとめて 1 件だけ見る検査にすると、片方を通し忘れても緑のまま通る
    [Theory]
    [MemberData(nameof(EnumFilterParameters))]
    public async Task IncidentsIndex_DropsAnEnumFilterValueOutsideItsDefinition(string parameterName)
    {
        // 一覧に出る行を 1 件用意する(「絞り込みが掛かって 0 件」との違いを見るため)
        await SeedIncidentAsync("ICU");

        // その引数だけに「定義に無い enum 値」を入れて一覧を引く
        var vm = await IndexWithEnumArgAsync(parameterName, UndefinedValueFor);

        // 絞り込みは掛かっていない(0 件にならない)。ここが直っていないと 0 件になる
        Assert.Single(vm.Incidents);
        // 受け取ったのに採用しなかったことを画面へ伝えている
        Assert.True(vm.UnlistedEnumFilterIgnored,
            $"?{parameterName}=<定義に無い値> を受け取ったのに注意書きが出ない。"
            + $"UnlistedEnumFilterResolver へ {parameterName} を通し忘れていないか確認すること。");
        // 画面へも値を返していない(返すとページャのリンクがその値を運び、
        // <select> には一致する <option> が無いまま「絞り込み中」バッジだけが出る)
        Assert.Null(ReadFilterValue(vm, parameterName));
    }

    // 逆に、定義にある値では絞り込みが効き、注意書きも出ないこと。
    // 片方(採用しない側)しか試していないと、「enum の絞り込みを丸ごと無効化する」変異
    // ——常に Effective = null を返す——が全件緑のまま通る
    [Theory]
    [MemberData(nameof(EnumFilterParameters))]
    public async Task IncidentsIndex_KeepsAnEnumFilterValueInsideItsDefinition(string parameterName)
    {
        // 一覧に出る行を 1 件用意する(SeedIncidentAsync が使う値で絞り込む)
        var incident = await SeedIncidentAsync("ICU");

        // 保存した行が実際に持っている値(＝定義にある値)で絞り込む
        var vm = await IndexWithEnumArgAsync(
            parameterName, enumType => ReadIncidentValue(incident, enumType));

        // 絞り込みは成立し、その 1 件が返る
        Assert.Single(vm.Incidents);
        // 定義にある値なので注意書きは出ない
        Assert.False(vm.UnlistedEnumFilterIgnored,
            $"?{parameterName}=<定義にある値> で注意書きが出ている。"
            + "UnlistedEnumFilterResolver が Enum.IsDefined ではなく別の判定になっていないか確認すること。");
        // 画面へも値が返り、<select> が現在値を指せる(これが無いと再送信で絞り込みが解除される)
        Assert.NotNull(ReadFilterValue(vm, parameterName));
    }

    // enum の絞り込みを一切指定しなければ、注意書きは出ないこと。
    // 「受け取っていない」を「採用しなかった」と数えると、絞り込みを一度も使っていない
    // 利用者の画面に出っぱなしの警告が並び、本物の注意書きまで読み飛ばされる
    [Fact]
    public async Task IncidentsIndex_DoesNotReportAnUnlistedEnum_WhenNoEnumFilterWasSent()
    {
        // 一覧に出る行を 1 件用意する
        await SeedIncidentAsync("ICU");

        // 絞り込みを一切指定せずに一覧を引く
        var vm = await IndexIncidentsAsync(null);

        // 受け取っていないものは「採用しなかった」ではない
        Assert.False(vm.UnlistedEnumFilterIgnored);
    }

    // 保存済みインシデントから、指定した enum 型のプロパティの値を取り出す。
    //
    // プロパティ名を書かず<b>型で</b>引くのは、引数名(incidentType)とエンティティの
    // プロパティ名(IncidentType)の対応を写しで持たないため —— 3 つ目の enum 絞り込みを
    // 足した人が対応表を直し忘れると、このテストだけが黙って別の値を渡すようになる。
    // 同じ enum 型のプロパティが 2 つ以上あるなら対応が一意に決まらないので落とす(fail-closed)
    private static object ReadIncidentValue(Incident incident, Type enumType)
    {
        // その enum 型を持つプロパティを探す
        var matches = typeof(Incident)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == enumType)
            .ToList();
        // ちょうど 1 つでなければ、型だけでは対応が決まらない
        Assert.True(matches.Count == 1,
            $"{nameof(Incident)} に {enumType.Name} 型のプロパティが {matches.Count} 個ある。"
            + "型で引く前提が崩れているので、この照合も同じ変更セットで直すこと。");
        // その値を返す
        return matches[0].GetValue(incident)!;
    }

    // ViewModel が画面へ返している絞り込み値を、引数名から取り出す。
    //
    // 対応は「引数名の先頭を大文字にしたプロパティ」で引く(incidentType -> IncidentType)。
    // 見つからなければ落とす —— 命名が揃わなくなったときに黙って null を返すと、
    // 「画面へ返していない」という Assert が常に成立して検査が無力化される(fail-closed)
    private static object? ReadFilterValue(IncidentListViewModel vm, string parameterName)
    {
        // 引数名の先頭を大文字にした名前で ViewModel のプロパティを引く
        var propertyName = char.ToUpperInvariant(parameterName[0]) + parameterName[1..];
        var property = typeof(IncidentListViewModel).GetProperty(propertyName);
        Assert.True(property != null,
            $"{nameof(IncidentListViewModel)} に {propertyName} が無い。"
            + "引数名とプロパティ名の対応が崩れたなら、この照合も同じ変更セットで直すこと。");
        // 画面へ返している値を返す
        return property!.GetValue(vm);
    }

    // --- /Analytics: /Incidents と同じ「実データにあれば補完、無ければ採用しない」 ------

    // 方式表(SearchFilter の解説)に載っている「?department= を受ける」アクションの一覧。
    //
    // これが「表に何が載っているか」の唯一の写しで、下の網羅ガードが
    // <b>判定とは独立な手がかり</b>(URL の契約＝アクションの引数)と突き合わせる。
    // 手で書くのは、表そのものが文章で機械には読めないため —— 代わりに
    // 「表に載っていない画面が ?department= を受けている」ことは機械で落とせる
    private static readonly (Type Controller, string Action)[] DepartmentFilterScreens =
    {
        // 一覧画面。選択肢(ドロップダウン)を持つので補完まで含めて上の各テストが見る
        (typeof(IncidentsController), nameof(IncidentsController.Index)),
        // 集計 JSON。選択肢は持たないが、採用の判定は一覧とまったく同じ(issue #204 課題 4)
        (typeof(AnalyticsController), nameof(AnalyticsController.MonthlyTrend)),
        (typeof(AnalyticsController), nameof(AnalyticsController.ByCause)),
        (typeof(AnalyticsController), nameof(AnalyticsController.BySeverity)),
    };

    // 方式表の一覧から /Analytics の分だけを取り出して [Theory] のケースにする。
    //
    // 手書きの [InlineData] にしないのは、表へ 4 つ目の集計エンドポイントを足した人が
    // 行を足し忘れた瞬間に、そのエンドポイントだけが挙動の検査から黙って外れるため。
    // 表へ足せば自動でケースに入り、呼び出し方を書いていなければ
    // InvokeAnalyticsAsync が例外で落ちて「配線が要る」ことを知らせる(fail-closed)
    public static TheoryData<string> AnalyticsDepartmentActions()
    {
        // 表のうち /Analytics のものだけを拾う
        var actions = DepartmentFilterScreens
            .Where(s => s.Controller == typeof(AnalyticsController))
            .Select(s => s.Action)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 0 件は「エンドポイントが無くなった」より「表から落ちた」可能性が高い(fail-closed)
        Assert.True(actions.Count > 0,
            $"{nameof(DepartmentFilterScreens)} に {nameof(AnalyticsController)} の項目が 1 つも無い。"
            + "表から外したなら、この導出も同じ変更セットで直すこと。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var action in actions) data.Add(action);
        return data;
    }

    // 方式表の一覧に載っている /Analytics のアクションを名前で呼び分ける。
    // 知らない名前が来たら落とす —— 表へ足しただけで検査が素通りするのを防ぐ(fail-closed)
    private static Task<IActionResult> InvokeAnalyticsAsync(
        AnalyticsController controller, string action, string? department) => action switch
        {
            // 期間の絞り込みは既定(未指定)にして、部署だけを動かす
            nameof(AnalyticsController.MonthlyTrend) => controller.MonthlyTrend(null, null, department),
            nameof(AnalyticsController.ByCause) => controller.ByCause(null, null, department),
            nameof(AnalyticsController.BySeverity) => controller.BySeverity(null, null, department),
            _ => throw new InvalidOperationException(
                $"{action} の呼び出し方がこのテストに無い。"
                + $"{nameof(DepartmentFilterScreens)} へ足したなら、ここへも呼び出しを足すこと。")
        };

    // /Analytics を扱うコントローラを用意する。
    // 時計を固定するのは、MonthlyTrend が「直近 12 ヶ月」で窓を切るため ——
    // 実時刻だと、シードに使う固定日(TestFixtures.Today)がいつか窓の外へ出て
    // 「ある日を境に落ちるようになる」テストになる(issue #199 と同じ壊れ方)
    private AnalyticsController NewAnalyticsController()
    {
        // シードと同じ日を「今日」として扱う時計を渡す
        var controller = new AnalyticsController(_db, new FixedClock(TestFixtures.Today));
        // この画面は Admin / RiskManager 限定。実在確認の部署スコープにも User が要る
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        return controller;
    }

    // 集計 3 エンドポイントすべてが数える 1 件を用意する
    // (インシデント本体＋そのなぜなぜ分析。ByCause は分析テーブルを起点に数えるため)
    private async Task SeedAnalyticsRowAsync(string department)
    {
        // 集計対象になるインシデントを 1 件作る
        var incident = await SeedIncidentAsync(department);
        // ByCause が数えられるよう、原因分類付きの分析をぶら下げる
        _db.CauseAnalyses.Add(new CauseAnalysis
        {
            IncidentId = incident.Id,
            // 部署ごとに別の分類にして、集計がまとまらないようにする
            CauseCategory = new CauseCategory { Name = $"原因（{department}）", DisplayOrder = 1 },
            Why1 = "なぜ1"
        });
        await _db.SaveChangesAsync();
    }

    // 集計 JSON の data 配列の合計(件数)を取り出す
    private static int TotalCount(JsonDocument doc) =>
        doc.RootElement.GetProperty("data").EnumerateArray().Sum(d => d.GetInt32());

    // 集計 JSON の「採用しなかった」旗を取り出す
    private static bool DepartmentFilterIgnored(JsonDocument doc) =>
        doc.RootElement.GetProperty("departmentFilterIgnored").GetBoolean();

    // 許可リストから外れた過去の部署名でも、実データにあれば絞り込みは効く。
    // 一覧画面と同じ扱い —— 部署名を入れ替えたあとも過去の集計へ到達できる必要がある
    [Theory]
    [MemberData(nameof(AnalyticsDepartmentActions))]
    public async Task Analytics_RetiredDepartmentThatStillExists_IsApplied(string action)
    {
        // 過去の部署名を持つ行と、現行の部署名を持つ行を 1 件ずつ用意する
        await SeedAnalyticsRowAsync(RetiredDepartment);
        await SeedAnalyticsRowAsync("ICU");

        // 古いブックマーク相当のリクエスト
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsAsync(NewAnalyticsController(), action, RetiredDepartment));

        // 絞り込みが効いて 1 件だけになる(全件の 2 件ではない)
        Assert.Equal(1, TotalCount(doc));
        // 採用しているので旗は立てない
        Assert.False(DepartmentFilterIgnored(doc));
    }

    // 実データのどこにも無い部署名は採用しない。
    //
    // issue #204 課題 4 の再現手順そのもの。以前は値をそのまま Where へ渡していたため
    // 「全 0 のグラフ」を注意書き無しで返しており、「この部署にはインシデントが 0 件だった」と
    // 読めてしまった(実際は「そんな部署は無い」)。方式を揃えると全件が返るので、
    // 今度は「絞り込んだつもりの全件」と読まれないよう旗で知らせる
    [Theory]
    [MemberData(nameof(AnalyticsDepartmentActions))]
    public async Task Analytics_UnknownDepartment_IsNotAppliedAndIsFlagged(string action)
    {
        // 現行の部署名を持つ行だけを用意する
        await SeedAnalyticsRowAsync("ICU");

        // 実在しない部署名で絞り込もうとする
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsAsync(NewAnalyticsController(), action, UnknownDepartment));

        // 絞り込みは掛からない(0 件ではなく全件が返る)
        Assert.Equal(1, TotalCount(doc));
        // 黙って落とさず、採用しなかったことを JSON で伝える
        Assert.True(DepartmentFilterIgnored(doc));
    }

    // 許可リストに載っている部署は、そのまま採用する(旗も立てない)
    [Theory]
    [MemberData(nameof(AnalyticsDepartmentActions))]
    public async Task Analytics_ListedDepartment_IsApplied(string action)
    {
        // 許可リストの先頭にある部署を使う(値そのものを書き写さない)
        var listed = Incident.Departments[0];
        // その部署の行と、別部署の行を 1 件ずつ用意する
        await SeedAnalyticsRowAsync(listed);
        await SeedAnalyticsRowAsync(RetiredDepartment);

        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsAsync(NewAnalyticsController(), action, listed));

        // 絞り込みが効いて 1 件だけになる
        Assert.Equal(1, TotalCount(doc));
        Assert.False(DepartmentFilterIgnored(doc));
    }

    // 入力そのものが無い(または空白のみの)ときは「採用しなかった」ではない。
    // ここを区別しないと、部署を指定していない普通の集計でも旗が立ち続け、
    // 旗を読む側(将来この画面に絞り込み UI を足す人)が読まなくなる
    [Theory]
    [MemberData(nameof(AnalyticsDepartmentActions))]
    public async Task Analytics_WhenNoDepartmentWasRequested_NoFlagIsRaised(string action)
    {
        // 集計対象を 1 件用意する
        await SeedAnalyticsRowAsync("ICU");

        // 空白のみ(＝絞り込み無し)で呼ぶ
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsAsync(NewAnalyticsController(), action, "   "));

        // 全件が返り、旗も立たない
        Assert.Equal(1, TotalCount(doc));
        Assert.False(DepartmentFilterIgnored(doc));
    }

    // 方式表が「絞り込み入力の唯一の真実の源」を名乗る以上、
    // <b>表に載っていない画面が ?department= を受けている</b>こと自体が穴になる。
    //
    // 実際 issue #204 課題 4 の時点で /Analytics がその状態だった: 表は
    // /Incidents /PreventiveMeasures /AuditLogs の 3 画面しか列挙しておらず、
    // このファイルの検査も表に載っている画面にしか掛からないので、
    // 集計画面は<b>表からも検出網からも同時に外れていた</b>。
    //
    // 手がかりは URL の契約(アクションが受け取る引数名)で、表そのものとは別の宣言箇所。
    // 同じ手がかりでガードを書くと、表が狭まったときにガードも一緒に狭まって
    // 「取りこぼしゼロ＝緑」で無力化される(この repo が
    //  LengthGovernedTypes_CoverEveryOwnedDbSet で避けているのと同じ形)
    //
    // <b>残っている境界。</b> 手がかりにするのは「URL 上の名前」なので、
    // <c>[FromQuery(Name = &quot;department&quot;)]</c> による別名までは追えるが、
    // <b>絞り込み条件をまとめた ViewModel を丸ごとバインドする</b>書き方
    // (<c>Index(IncidentFilter filter)</c> のような形)は追えない ——その型の
    // <c>Department</c> プロパティが同じ <c>?department=</c> を受けるのに、
    // アクションの引数としては現れないため。現在そういう書き方をしている画面は無いが、
    // <b>最初に足す人がこの照合を広げること</b>(広げないと、その画面だけが
    // 表からも検出網からも同時に外れる ——この検査が塞いだのと同じ状態に戻る)
    [Fact]
    public void PolicyTable_CoversEveryActionThatAcceptsADepartmentFilter()
    {
        // アプリ本体のアセンブリから、MVC のコントローラをすべて拾う
        var controllers = WebControllers();
        // 1 つも拾えないなら手がかりが死んでいる(「見るべき対象ゼロ＝緑」を避ける)
        Assert.True(controllers.Count > 0, "コントローラが 1 つも見つからない。");

        // 「?department= を受ける」アクションを、URL 上の名前と型で拾う
        var accepting = controllers
            .SelectMany(t => ActionMethods(t)
                .Where(m => m.GetParameters().Any(param =>
                    QueryStringName(param) == "department" && param.ParameterType == typeof(string)))
                .Select(m => (Controller: t, Action: m.Name)))
            .Distinct()
            .OrderBy(x => x.Controller.Name, StringComparer.Ordinal)
            .ThenBy(x => x.Action, StringComparer.Ordinal)
            .ToList();

        // 手がかりが 1 件も読めないなら、引数名を変えたか拾い方が壊れている
        Assert.True(accepting.Count > 0,
            "?department= を受けるアクションが 1 つも見つからない。"
            + "引数名を変えたなら、この照合も同じ変更セットで直すこと。");

        // 表の側も同じ並びに揃えてから突き合わせる
        var listed = DepartmentFilterScreens
            .OrderBy(x => x.Controller.Name, StringComparer.Ordinal)
            .ThenBy(x => x.Action, StringComparer.Ordinal)
            .ToList();

        // 2 つの宣言箇所が一致していること。ずれていれば、表に載せずに ?department= を
        // 受け始めた画面があるか、逆に受けなくなった画面が表に残っている
        Assert.Equal(listed, accepting);
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
        // 対象ドロップダウンのブロックだけを(Razor のコメントを落として)切り出す。
        // 切り出しの手順は 3 つの検査で共通なので RazorSource が持つ(§6 DRY)
        var selectBlock = RazorSource.ExtractSelectBlock(
            File.ReadAllText(viewPath), $"<select name=\"{selectName}\"", $"{viewFolder}/Index.cshtml");

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
    // 覆っているのは /Incidents の分だけ(この導出も、照合も、下の 2 つの Razor 走査も、
    // IncidentListViewModel / IncidentsController.cs / Views/Incidents/Index.cshtml を
    // 名指ししている)。「旗を足せば必ず検査に入る」のはこの画面の中の話。
    //
    // 2 画面目(/PreventiveMeasures)は旗を持つようになったが、この導出には載らない ——
    // あちらは ViewModel を持たず ViewBag で渡すので、「ViewModel の *Ignored という
    // bool プロパティ」という命名規約では原理的に拾えない。そのため同じ 3 つの入り口を
    // 画面ごとに用意してある(MeasuresIgnoredFilterFlags / MeasuresIndexView_* )。
    // <b>「無条件補完だから旗を持たない」ではない</b> —— あの画面は担当部署(自由記述＝補完)と
    // 対策ステータス(閉じた enum ＝採用しない)の 2 方式を併用しており、以前ここに
    // 「/PreventiveMeasures は無条件補完で採用しない枝が無い」と書いていたのは<b>誤り</b>で、
    // その思い込みのぶん ?status=99 が長くどの検査にも掛からずに残っていた。
    //
    // 3 画面目が旗を持ったときも同じく入り口を用意すること。enum の絞り込みについては
    // EnumFilterScreens_CoverEveryActionThatAcceptsAnEnumFilter が
    // 「用意し忘れ」自体をアプリ全体の署名から拾って落とす
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

    // ドロップダウンの選択肢プロパティの命名規約。下の導出はこの接尾辞で拾う
    private const string OptionsPropertySuffix = "Options";

    // 「選択肢プロパティを required にする」検査の対象を機械的に導く。
    //
    // 条件は 2 つ: (a) 自分たちのアセンブリで *Options を宣言している型、
    // (b) MVC のアクション引数として<b>使われない</b>型。
    //
    // (b) が要る理由。 モデルバインドされる型に required を付けると、
    // <Nullable>enable</Nullable> の下で MVC が非 null 許容の参照型へ [Required] を自動で足し、
    // フォームが送らない選択肢が必ず検証エラーになって<b>その画面の POST が全部落ちる</b>
    // (実測は IncidentCreateEditViewModel.DepartmentOptions のコメントにある)。
    // 通すには [BindNever] / [ValidateNever] が要り、それは別の規約 ——
    // そちらは FormViewModelBindingMetadataTests が受け持つ。ここで一律に required を
    // 要求すると<b>実行不能な指示</b>になり、いずれ検査ごと緩められる。
    //
    // 型を書き並べないのは旗(IgnoredFilterFlags)と同じ理由。手書きにすると、
    // 2 つ目の一覧画面を足した人が行を足し忘れた瞬間にその画面だけが黙って外れる
    // ——実際この導出を IncidentListViewModel の決め打ちにしていた版では、
    // AuditLogListViewModel の 2 つ(と詳細画面の 1 つ)が同じ = new() の穴を持ったまま
    // 検査の外にあった。
    //
    // 1 つも拾えなければ落とす(fail-closed)。命名規約や導出ごと変えると
    // 「対象ゼロ＝全件緑」で検出網が黙って死ぬため
    public static TheoryData<string, string> FilterOptionProperties()
    {
        // 対象の (型, プロパティ名) をすべて拾う
        var properties = GovernedOptionProperties();

        // 0 件は「選択肢が無くなった」より「命名規約か導出が変わった」可能性が高い
        Assert.True(properties.Count > 0,
            $"*{OptionsPropertySuffix} という名前のプロパティを持つ ViewModel が 1 つも見つからない。"
            + "命名規約か導出を変えたなら、この検査も同じ変更セットで直すこと。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string, string>();
        foreach (var (type, property) in properties) data.Add(type.FullName!, property);
        return data;
    }

    // 検査対象の (型, プロパティ名) を上の 2 条件で導く
    private static List<(Type Type, string Property)> GovernedOptionProperties()
    {
        // モデルバインドされる型(＝アクションの引数に現れる型)は対象外にする
        var modelBound = WebControllers()
            .SelectMany(ActionMethods)
            .SelectMany(m => m.GetParameters())
            .Select(param => param.ParameterType)
            .ToHashSet();

        // 自分たちのアセンブリで *Options を宣言している型を拾い、モデルバインドされる型を除く。
        // DeclaredOnly にするのは、基底(フレームワーク側)が持つ同名のプロパティを数えないため
        // ——実際 ApplicationUserClaimsPrincipalFactory は Identity の基底から
        // IdentityOptions 型の Options を継いでおり、名前だけで拾うと
        // 「required にしろ」という実行不能な指示が出る(正しいコードを咎める検出網になる)
        return typeof(IncidentListViewModel).Assembly
            .GetTypes()
            .Where(t => t.IsClass && !modelBound.Contains(t))
            .SelectMany(t => t
                .GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(p => p.Name.EndsWith(OptionsPropertySuffix, StringComparison.Ordinal))
                .Where(p => IsDropdownOptionList(p.PropertyType))
                .Select(p => (Type: t, Property: p.Name)))
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(x => x.Type.FullName, StringComparer.Ordinal)
            .ThenBy(x => x.Property, StringComparer.Ordinal)
            .ToList();
    }

    // 「ドロップダウンへ並べる選択肢のリスト」かどうかを型で判定する。
    //
    // 名前(*Options)だけで拾うと、画面の選択肢とは無関係な設定オブジェクト
    // (Identity の IdentityOptions など)まで対象に入る。<select> へ渡すのは
    // 表示用の文字列リストか SelectListItem のリストのどちらかなので、そこで切る
    // ——3 つ目の要素型が出てきたらここへ足す(足さないとその選択肢が黙って検査から外れる)
    private static bool IsDropdownOptionList(Type propertyType) =>
        propertyType == typeof(List<string>) || propertyType == typeof(List<SelectListItem>);

    // 選択肢プロパティはすべて required にする(＝既定値を持たせない)。
    //
    // 空リストの既定値を持たせると、その ViewModel を組み立てる経路が増えたときに
    // 設定漏れが<b>コンパイルも通りテストも緑のまま</b>素通りし、そのドロップダウンが
    // 「(全て)」だけになって選択肢が画面から消える ——例外もテストの失敗も出ないので
    // 気付く手掛かりが無い。理由の正本は IncidentListViewModel.DepartmentOptions のコメント。
    //
    // 片方だけ required だと、対で作られるもう片方が同じ穴を持ったまま残る
    // (実際 issue #204 課題 3 がその状態だった: DepartmentOptions は required、
    //  CauseCategoryOptions は = new() の既定値付き)
    [Theory]
    [MemberData(nameof(FilterOptionProperties))]
    public void FilterOptionProperties_AreRequiredSoTheyCannotBeForgotten(string typeName, string propertyName)
    {
        // 導出元と同じアセンブリから型を引き直す
        var type = typeof(IncidentListViewModel).Assembly.GetType(typeName);
        Assert.True(type != null, $"{typeName} が見つからない。");
        // 対象のプロパティを取り出す
        var property = type!.GetProperty(propertyName);
        Assert.True(property != null, $"{typeName}.{propertyName} が見つからない。");

        // C# の required 修飾子は [RequiredMember] としてメタデータに残るので、それで判定する
        var isRequired = property!.GetCustomAttributes(typeof(RequiredMemberAttribute), inherit: true).Length > 0;
        Assert.True(isRequired,
            $"{typeName}.{propertyName} を required にすること。"
            + "既定値を持たせると、組み立て経路が増えたときに設定漏れが"
            + "コンパイルも通りテストも緑のまま素通りし、そのドロップダウンから選択肢が消える。");
    }

    // 発生部署の 2 つの解決メソッドが、DB から読んだ綴りを採用する前に
    // SearchFilter.HasValue の門番へ通していることをソースで見張る(issue #202)。
    //
    // なぜランタイムのテストで固定できないのか。DepartmentFilterResolver.ResolveAsync が
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
    //
    // 置き場所も引数に取る。絞り込み側は /Incidents と /Analytics が共有するようになって
    // Controllers/Internal へ移ったが(issue #204 課題 4)、保存側はフォーム固有なので
    // コントローラに残っている ——ファイル名を決め打ちにすると、片方を動かしたときに
    // 「宣言が見つからない」で落ちて、直す人が門番そのものを消す方へ倒れかねない
    [Theory]
    // 一覧・集計の絞り込み側(採用しないと絞り込みが解除される)
    [InlineData("Controllers/Internal/DepartmentFilterResolver.cs", "ResolveAsync")]
    // 登録・編集の保存側(採用しないと保存された発生部署が書き換わる)
    [InlineData("Controllers/IncidentsController.cs", "ResolveDepartmentSaveSelection")]
    public void DepartmentResolvers_GateTheAdoptedValueOnHasValue(string relativePath, string methodName)
    {
        // 対象のソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var sourcePath = Path.Combine(RepositoryPaths.WebProject, relativePath.Replace('/', Path.DirectorySeparatorChar));
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(sourcePath), $"解決メソッドのソースが見つからない: {sourcePath}");
        var source = File.ReadAllText(sourcePath);

        // 対象メソッドの本文だけを切り出す(ファイル全体を見ると、他のメソッドにある
        // 同じ形の判定を数えてしまい、片方を外しても気付けない)
        var body = ExtractMethodBody(source, methodName, relativePath);

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
    private static string ExtractMethodBody(string source, string methodName, string relativePath)
    {
        // 先にコメントを落とす。これで波かっこの数え方もコメント内の中かっこに乱されない
        var code = CSharpComment.Replace(source, string.Empty);

        // メソッド宣言の位置を探す(呼び出しではなく宣言を狙うため、名前の直後が引数リストで
        // かつ行頭からインデントだけが先行する形に限る)
        var declaration = Regex.Match(code, $@"^[ \t]+(?:private|public|internal).*\b{Regex.Escape(methodName)}\s*\(", RegexOptions.Multiline);
        // 宣言が読めないなら、書き方が変わって手がかりが死んでいる。
        // 「違反ゼロ＝緑」にせず落として、書き方かこの検査のどちらを直すか人に決めさせる
        Assert.True(declaration.Success,
            $"{relativePath} に {methodName} の宣言が見つからない。"
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
        // 何が適用されなかったのかを言い切る見出しは呼び出し側にある(旗ごとに文面が違う)
        Assert.Contains("適用していません", blockBody!, StringComparison.Ordinal);

        // 枠(警告の見た目・アイコン・role="alert")は共有パーシャルが持つので、
        // ブロックがそのパーシャルを実際に呼んでいることを見て、続きはパーシャル側で確かめる。
        //
        // なぜ追いかけるのか。 以前この検査はブロック本体に "alert" があることだけを見ていた。
        // 3 件目の注意書きを足すにあたって枠を _FilterIgnoredNotice へ切り出した(§6 DRY /
        // 枠には §7 の配慮が入っており、3 か所へ書き写すと直すときに 1 つ取り残される)が、
        // 「本体に alert という語があるか」のままだと、パーシャルの呼び出しごと消して
        // 見出しの文字列だけを残す変異が素通りする ——注意書きの枠が消えて文字が地の文に
        // 落ちるので、警告として見えなくなる。マークアップの置き場所を変えても
        // 「注意書きが実際に描画されるか」を見続けられるよう、呼び出し先まで追う
        var partialCall = Regex.Match(blockBody!, @"<partial\s+name\s*=\s*""(?<name>[^""]+)""");
        Assert.True(partialCall.Success,
            $"Views/Incidents/Index.cshtml の @if (Model.{flag}) が注意書きのパーシャルを呼んでいない。"
            + "枠のマークアップを直接書くか、この照合を同じ変更セットで直すこと。");

        // 呼んでいるパーシャルの中身を読む(ビルド出力にはコピーされないので絶対パスで開く)。
        // 置き場所を Views/Incidents/ 決め打ちにしない —— Razor 自身は
        // /Views/{コントローラ名}/ と /Views/Shared/ の順に探すので、決め打ちにすると
        // 実行時には正しく解決されるパーシャルをテストだけが「見つからない」と言う
        // (実際 2 画面目が注意書きを持ったとき Views/Shared/ へ移してここが落ちた)
        var partialSource = ReadPartial("Incidents", partialCall.Groups["name"].Value);

        // 警告として見えること(§7 は色だけに意味を持たせないので、role と文言の両方を見る)
        Assert.Contains("alert", partialSource, StringComparison.Ordinal);
        // 呼び出し側が渡す文面が両方とも実際に描画されること。
        // 片方しか出さないと、見出しだけ・説明だけの注意書きになる
        // (説明が落ちると「なぜ適用されなかったか」も「どう選び直すか」も画面から消える)
        Assert.Contains($"@Model.{nameof(FilterIgnoredNotice.Heading)}", partialSource, StringComparison.Ordinal);
        Assert.Contains($"@Model.{nameof(FilterIgnoredNotice.Detail)}", partialSource, StringComparison.Ordinal);

        // 呼び出し側が空文字を渡していないこと。パーシャルが両方を描画していても、
        // 渡す文面が空なら画面には枠しか出ない
        var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
        Assert.True(notice.Success,
            $"Views/Incidents/Index.cshtml の @if (Model.{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
        // 引数として渡している文字列リテラルのうち、空でないものを数える
        var literals = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
            .Select(m => m.Groups["text"].Value)
            .Where(text => text.Trim().Length > 0)
            .ToList();
        Assert.True(literals.Count >= 2,
            $"@if (Model.{flag}) の {nameof(FilterIgnoredNotice)} に、見出しと説明の両方の文面が要る。");
    }

    // 名前を「識別子として」照合する(部分文字列だと Model.Department が
    // Model.DepartmentOptions に一致して素通りする)。判定の正本は RazorSource で、
    // 登録・編集フォーム側の走査と共有している
    private static bool ContainsIdentifier(string text, string identifier) =>
        RazorSource.ContainsIdentifier(text, identifier);

    // 旗ごとの注意書きの<b>見出しが互いに違う</b>こと。
    //
    // なぜ要るのか(実測)。 旗は同時に立ちうる(?severity=99&dateFrom=abc で
    // MalformedFilterIgnored と UnlistedEnumFilterIgnored が両方立つ)。見出しが同じだと
    // ほぼ同一の警告が 2 つ並び、利用者からは<b>二重描画の不具合に見える</b>。
    // 実際 issue #208 の対応で新しい注意書きを足したとき、malformed 側と同じ
    // 「一部の絞り込みは適用していません。」を書いてしまい、
    // <b>全件緑のまま通った</b>（人のレビューでしか気付けなかった）。
    //
    // 上の per-flag の検査は「見出しと説明が空でないこと」までしか見ないので、
    // 衝突は原理的に見えない —— 旗をまたいで比べる必要があるため独立した [Fact] にする。
    // 5 つ目の旗を足した人が既存の文面を写して使うと、ここで落ちる
    [Fact]
    public void IncidentsIndexView_GivesEachIgnoredFilterNoticeItsOwnHeading()
    {
        // 一覧ビューの Razor ソースを読む(Razor のコメントは落としてから見る)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);

        // 旗ごとに、その @if ブロックが組み立てる FilterIgnoredNotice の「見出し」を集める。
        // 見出しは第 1 引数なので、ブロック内の最初の空でない文字列リテラルを取る
        var headings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var flag in DeclaredIgnoredFilterFlags())
        {
            // その旗で出し分けているブロックを切り出す(per-flag の検査と同じ探し方)
            var header = Regex.Match(source, $@"@if\s*\(\s*Model\.{flag}\b");
            Assert.True(header.Success, $"Model.{flag} で出し分けている注意書きが無い。");
            var blockBody = ExtractBraceBlock(source, header.Index);
            Assert.True(blockBody != null, $"@if (Model.{flag}) に本体が無い。");

            // FilterIgnoredNotice の組み立て位置から先の、最初の空でない文字列リテラルが見出し
            var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
            Assert.True(notice.Success, $"@if (Model.{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
            var heading = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
                .Select(m => m.Groups["text"].Value)
                .FirstOrDefault(text => text.Trim().Length > 0);
            Assert.True(heading != null, $"@if (Model.{flag}) の注意書きに見出しの文面が無い。");

            // 同じ見出しを既に別の旗が使っていないこと
            Assert.False(headings.TryGetValue(heading!, out var owner),
                $"Model.{flag} の注意書きの見出しが Model.{owner} と同じ(「{heading}」)。"
                + "2 つの旗は同時に立ちうるので、同じ見出しだとほぼ同一の警告が 2 つ並び、"
                + "二重描画の不具合に見える。旗ごとに違う見出しを付けること。");
            headings[heading!] = flag;
        }

        // 旗を 1 つも拾えないなら手がかりが死んでいる(fail-closed)
        Assert.True(headings.Count > 0, "注意書きの見出しを 1 つも拾えなかった。");
    }

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
    /// アプリ本体のアセンブリにある MVC のコントローラをすべて返す。
    /// </summary>
    /// <remarks>
    /// 「?department= を受けるアクション」の照合と、「モデルバインドされる型」の判定
    /// (選択肢プロパティの required 検査)が同じ走査を必要とする。写しを持つと、
    /// 片方だけ拾い方を直したときにもう片方が古い基準のまま緑になる(§6 DRY)。
    /// </remarks>
    private static List<Type> WebControllers() =>
        typeof(IncidentsController).Assembly
            .GetTypes()
            .Where(t => t.IsClass && !t.IsAbstract && typeof(Controller).IsAssignableFrom(t))
            .ToList();

    /// <summary>
    /// 指定したコントローラが<b>自分で宣言している</b>アクションメソッドを返す。
    /// </summary>
    /// <remarks>
    /// <c>DeclaredOnly</c> にするのは基底(<see cref="Controller"/>)の公開メソッドを数えないため。
    /// プロパティのアクセサ(<c>IsSpecialName</c>)と <c>[NonAction]</c> も除く。
    /// </remarks>
    private static IEnumerable<MethodInfo> ActionMethods(Type controller) =>
        controller
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName)
            .Where(m => m.GetCustomAttributes(typeof(NonActionAttribute), inherit: true).Length == 0);

    /// <summary>
    /// アクションの引数が<b>クエリ文字列上で</b>名乗る名前を返す。
    /// </summary>
    /// <remarks>
    /// <c>[FromQuery(Name = "…")]</c> が付いていればその名前、無ければ C# の引数名。
    /// C# の識別子だけを見ると、別名を付けた引数が同じ <c>?department=</c> を受けているのに
    /// 照合から外れる(<c>Index([FromQuery(Name = "department")] string? departmentName)</c>)。
    /// </remarks>
    private static string? QueryStringName(ParameterInfo parameter) =>
        parameter.GetCustomAttribute<FromQueryAttribute>()?.Name ?? parameter.Name;

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

    // --- 共有: パーシャルの置き場所は Razor と同じ順で探す --------------------------

    // 呼ばれているパーシャルのソースを読む。
    //
    // <b>Razor の解決順をそのまま真似る</b>のが要点 —— Razor は
    // /Views/{コントローラ名}/ を見てから /Views/Shared/ を見るので、テスト側だけが
    // 片方を決め打ちにすると 2 つの嘘が生まれる: (a) Shared に置いた共有パーシャルを
    // 「見つからない」と言って<b>正しいコードを咎める</b>、(b) 逆に Shared だけを見ると
    // 画面固有のパーシャルを見落とす。どちらの向きの嘘もいずれ検査ごと緩められる。
    //
    // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
    private static string ReadPartial(string viewFolder, string partialName)
    {
        // Razor と同じ順(画面固有 → 共有)で候補を並べる
        var candidates = new[]
        {
            Path.Combine(RepositoryPaths.Views, viewFolder, $"{partialName}.cshtml"),
            Path.Combine(RepositoryPaths.Views, SharedViewFolder, $"{partialName}.cshtml"),
        };
        // 先に見つかったほうを採る(Razor の解決結果と一致する)
        var found = candidates.FirstOrDefault(File.Exists);
        // どちらにも無ければ、実行時にも解決できないので落とす
        Assert.True(found != null,
            $"パーシャル {partialName} が {viewFolder} にも {SharedViewFolder} にも見つからない"
            + "(Razor が探すのはこの 2 か所だけ)。");
        // Razor のコメントは落としてから返す(コメントで検査を満たせないようにする)
        return RazorComment.Replace(File.ReadAllText(found!), string.Empty);
    }

    // Razor が共有パーシャルを探すフォルダ名
    private const string SharedViewFolder = "Shared";

    // --- /PreventiveMeasures: 受け取ったのに採用しなかった絞り込み(issue #207 / #208) ---

    // カンバン画面のコントローラを、部署スコープを持つ利用者で組み立てる。
    // 既定は Admin(全部署が見える)で、部署スコープ側の挙動を見たいときだけ差し替える
    private PreventiveMeasuresController NewMeasuresController(ClaimsPrincipal? user = null)
    {
        // 依存は本物の InMemory DbContext を使う(Mock より InMemory を優先する repo の方針)
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        // 実行ロールを載せる(指定が無ければ全部署が見える Admin)
        UserContextHelper.AttachUser(controller, user ?? UserContextHelper.Admin());
        // 組み立てたコントローラを返す
        return controller;
    }

    // カンバンに 1 件だけ対策を積む。どの検査も「絞り込みが効いたら消える 1 件」があれば足りる
    private async Task SeedSingleMeasureAsync()
    {
        // 対策はインシデントにぶら下がるので、親のインシデントごと作る
        var incident = new Incident
        {
            Department = "ICU",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "テスト",
            ReporterName = "報告者",
            OccurredAt = DateTime.Now
        };
        // 計画中の対策を 1 件ぶら下げる(?status=Planned で拾える状態にしておく)
        incident.PreventiveMeasures.Add(new PreventiveMeasure
        {
            Incident = incident,
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = "ICU",
            DueDate = DateTime.Today.AddDays(30),
            Status = MeasureStatus.Planned,
            Priority = 2
        });
        // 親ごと保存する
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
    }

    // カンバンを引いて ViewResult を返す(引数の既定値をここに 1 か所だけ置く)
    private async Task<ViewResult> MeasuresIndexAsync(
        PreventiveMeasuresController controller, MeasureStatus? status = null)
        => Assert.IsType<ViewResult>(await controller.Index(status, null, null, null, null));

    // 定義に無い enum 値(?status=99)は採用しない ——絞り込みを掛けず、画面へも返さない。
    //
    // 素通しにすると何が起きるか(実測): 絞り込みは<b>実際に掛かって盤面が空</b>になり、
    // <select> には一致する <option> が無いので「ステータス（全て）」の位置に戻る。
    // その状態でフォームを再送信すると status= が送られて<b>絞り込みが黙って解除される</b>
    // ——SearchFilter の表が守ろうとしている不変条件(「絞り込みに使った値は必ず選択肢にある」)
    // がそのまま破れている状態(issue #192 の症状)。
    //
    // 値は決め打ちの 99 ではなく MeasureStatus の定義から導く ——将来 99 が定義へ足されると、
    // 決め打ちの検査は「定義にある値」を渡す無害なテストへ黙って化ける
    [Fact]
    public async Task MeasuresIndex_DropsAnEnumFilterValueOutsideItsDefinition()
    {
        // 絞り込みが掛かれば消える 1 件を積む
        await SeedSingleMeasureAsync();
        // 定義に無い MeasureStatus の値を作って渡す
        var undefined = (MeasureStatus)UndefinedValueFor(typeof(MeasureStatus));
        var result = await MeasuresIndexAsync(NewMeasuresController(), undefined);

        // 絞り込みを掛けていないので、積んだ 1 件はそのまま残る
        var rows = Assert.IsAssignableFrom<IEnumerable<PreventiveMeasure>>(result.Model);
        Assert.Single(rows);
        // 採用しなかった値は画面へ返さない(返すと <select> だけが「（全て）」を指す食い違いになる)
        Assert.Null(result.ViewData["FilterStatus"]);
        // 受け取ったのに採用しなかったことは伝える(黙って全件を見せない)
        Assert.Equal(true, result.ViewData["UnlistedEnumFilterIgnored"]);
        // 「絞り込みが効いている」とは言わない ——効いていないフィルターの
        // 「クリア」を促す 0 件時の文言が出てしまうため
        Assert.Equal(false, result.ViewData["HasActiveFilter"]);
    }

    // 定義にある値はこれまでどおり絞り込みに使い、注意書きも出さない。
    // 上の検査だけだと「enum の絞り込みを丸ごと無効にする」変異が素通りする
    [Fact]
    public async Task MeasuresIndex_KeepsAnEnumFilterValueInsideItsDefinition()
    {
        // 計画中の 1 件を積む
        await SeedSingleMeasureAsync();
        // 定義にある値(完了)で絞る ——積んだ 1 件は計画中なので消えるはず
        var result = await MeasuresIndexAsync(NewMeasuresController(), MeasureStatus.Completed);

        // 絞り込みが実際に効いていること
        var rows = Assert.IsAssignableFrom<IEnumerable<PreventiveMeasure>>(result.Model);
        Assert.Empty(rows);
        // 採用した値は画面へ返す(<select> が実際に絞り込んだ値を指す)
        Assert.Equal(MeasureStatus.Completed, result.ViewData["FilterStatus"]);
        // 採用したので注意書きは出さない
        Assert.Equal(false, result.ViewData["UnlistedEnumFilterIgnored"]);
        // 絞り込みは効いている(0 件時に「条件に一致しません」と案内してよい)
        Assert.Equal(true, result.ViewData["HasActiveFilter"]);
    }

    // 型として読めなかった値(?dateFrom=abc など)も「受け取った」と数えて伝える。
    //
    // 見なければ「そもそも指定が無かった」と同じ扱いになり、絞り込んだつもりの利用者に
    // カンバン全件が返る(issue #207)。対象は Index が受ける Nullable の引数から導く
    // ——手書きにすると、6 つ目の型付き絞り込みを足した人が行を足し忘れた瞬間に
    // その引数だけが黙って元の壊れ方に戻る
    [Theory]
    [MemberData(nameof(MeasuresNullableFilterParameters))]
    public async Task MeasuresIndex_ReportsAFilterValueThatCannotBeRead(string parameterName)
    {
        // 絞り込みが掛かれば消える 1 件を積む
        await SeedSingleMeasureAsync();
        var controller = NewMeasuresController();
        // モデルバインドが「値は届いたが読めなかった」ときに積むエラーを再現する
        controller.ModelState.AddModelError(parameterName, "変換できません");
        var result = await MeasuresIndexAsync(controller);

        // 読めなかっただけなので絞り込みは掛からない(1 件はそのまま残る)
        var rows = Assert.IsAssignableFrom<IEnumerable<PreventiveMeasure>>(result.Model);
        Assert.Single(rows);
        // 受け取ったのに採用しなかったことを伝える
        Assert.Equal(true, result.ViewData["MalformedFilterIgnored"]);
    }

    // 何も送っていないときは、どちらの注意書きも出さない。
    // 未指定で出すと、絞り込みを一度も使っていない利用者の画面に出っぱなしの警告が並び、
    // 本物の注意書きまで読み飛ばされる
    [Fact]
    public async Task MeasuresIndex_ReportsNothing_WhenNoFilterValueWasSent()
    {
        // 1 件だけ積んで、素の一覧を引く
        await SeedSingleMeasureAsync();
        var result = await MeasuresIndexAsync(NewMeasuresController());

        // どちらの旗も立たない
        Assert.Equal(false, result.ViewData["MalformedFilterIgnored"]);
        Assert.Equal(false, result.ViewData["UnlistedEnumFilterIgnored"]);
        // 絞り込みも掛かっていない
        Assert.Equal(false, result.ViewData["HasActiveFilter"]);
        Assert.Null(result.ViewData["FilterStatus"]);
    }

    // カンバンの Index が受ける Nullable の引数(＝読めずに null へ化けうる入力)を導く。
    // 導出の理由と fail-closed にする理由は /Incidents 側の NullableFilterParameters が正本
    public static TheoryData<string> MeasuresNullableFilterParameters()
    {
        // Nullable<T> の引数だけを C# の引数名で拾う(モデルバインドのキーは引数名そのもの)
        var names = typeof(PreventiveMeasuresController)
            .GetMethod(nameof(PreventiveMeasuresController.Index))!
            .GetParameters()
            .Where(p => Nullable.GetUnderlyingType(p.ParameterType) != null)
            .Select(p => p.Name!)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 1 つも拾えないのは「引数が無くなった」より「型か導出が変わった」可能性が高い
        Assert.True(names.Count > 0,
            $"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.Index)} に "
            + "Nullable の引数が 1 つも無い。引数の型を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、読めない値の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var name in names) data.Add(name);
        return data;
    }

    // --- /PreventiveMeasures: 旗をビューが実際に読んでいるか ------------------------

    // カンバンが立てる旗を、コントローラのソースから導く。
    //
    // この画面は ViewModel を持たず ViewBag で渡すので、/Incidents のように
    // 「ViewModel の *Ignored という bool プロパティ」という命名規約では拾えない。
    // 代わりに「… = ….Ignored」という代入の形を手がかりにする ——旗は必ず解決関数が返す
    // Ignored から写されるので、この代入が旗の実際の一覧になる。
    //
    // 1 つも拾えなければ落とす(fail-closed)。書き方を変えると
    // 「対象ゼロ＝全件緑」で下の Razor 走査が黙って死ぬため
    public static TheoryData<string> MeasuresIgnoredFilterFlags()
    {
        // コントローラのソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var flags = MeasuresIgnoredFilterFlagNames();

        // 0 件は「旗が無くなった」より「書き方が変わった」可能性が高い
        Assert.True(flags.Count > 0,
            $"{nameof(PreventiveMeasuresController)} に「… = ….Ignored」の代入が 1 つも見つからない。"
            + "書き方を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、旗ごとに掛かるはずの Razor の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var flag in flags) data.Add(flag);
        return data;
    }

    // 上の導出の本体。Theory のケース作りと下の見出し照合が同じここを読む(§6 DRY)
    private static List<string> MeasuresIgnoredFilterFlagNames()
    {
        // コントローラのソースを開く
        var controllerPath = Path.Combine(
            RepositoryPaths.WebProject, "Controllers", $"{nameof(PreventiveMeasuresController)}.cs");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(controllerPath), $"コントローラのソースが見つからない: {controllerPath}");
        // コメントを落としてから走査する(説明コメントが幽霊の旗として拾われるのを防ぐ)
        var source = CSharpComment.Replace(File.ReadAllText(controllerPath), string.Empty);

        // 「<旗> = <解決結果>.Ignored」の代入をすべて拾う(ViewBag. の前置きは \w+ に入らない)
        return Regex.Matches(source, @"(?<flag>\w+)\s*=\s*\w+\.Ignored\b")
            .Select(m => m.Groups["flag"].Value)
            .Distinct(StringComparer.Ordinal)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
    }

    // 旗をカンバンのビューが実際に読んでいることを確かめる。
    //
    // コントローラ級の検査は ViewBag までしか見ないので、@if のブロックごと消しても
    // 全件緑のまま通る。そうなると旗は誰も読まない書き込み専用の値になり、
    // 利用者は黙って全件(または空の盤面)を見せられる ——/Incidents 側とまったく同じ理由で、
    // 同じやり方(Razor のソースを見る)で塞ぐ
    [Theory]
    [MemberData(nameof(MeasuresIgnoredFilterFlags))]
    public void MeasuresIndexView_RendersTheIgnoredFilterNotice(string flag)
    {
        // カンバンビューの本文を読む(Razor のコメントは落としてから見る)
        var source = ReadMeasuresIndexSource();

        // 旗で表示を出し分けていること。空白や比較の書き方に依存しない形で探す
        // (@if(ViewBag.X == true) のような同じ働きの正しい書き方を落とさないため)
        var header = Regex.Match(source, $@"@if\s*\(\s*ViewBag\.{flag}\b");
        Assert.True(header.Success,
            $"Views/PreventiveMeasures/Index.cshtml が ViewBag.{flag} で注意書きを出し分けていない。");

        // 出し分けているだけでなく、そのブロックに中身があることまで見る
        var blockBody = ExtractBraceBlock(source, header.Index);
        Assert.True(blockBody != null,
            $"Views/PreventiveMeasures/Index.cshtml の @if (ViewBag.{flag}) に本体が無い。");
        // 何が適用されなかったのかを言い切る見出しがあること
        Assert.Contains("適用していません", blockBody!, StringComparison.Ordinal);

        // 枠は共有パーシャルが持つので、実際に呼んでいることを見て続きはパーシャル側で確かめる
        var partialCall = Regex.Match(blockBody!, @"<partial\s+name\s*=\s*""(?<name>[^""]+)""");
        Assert.True(partialCall.Success,
            $"Views/PreventiveMeasures/Index.cshtml の @if (ViewBag.{flag}) が"
            + "注意書きのパーシャルを呼んでいない。");

        // パーシャルは Razor と同じ順で探す(この画面のものは Views/Shared/ にある)
        var partialSource = ReadPartial("PreventiveMeasures", partialCall.Groups["name"].Value);
        // 警告として見えること(§7 は色だけに意味を持たせないので role と文言の両方を見る)
        Assert.Contains("alert", partialSource, StringComparison.Ordinal);
        // 呼び出し側が渡す文面が両方とも描画されること
        Assert.Contains($"@Model.{nameof(FilterIgnoredNotice.Heading)}", partialSource, StringComparison.Ordinal);
        Assert.Contains($"@Model.{nameof(FilterIgnoredNotice.Detail)}", partialSource, StringComparison.Ordinal);

        // 呼び出し側が空文字を渡していないこと(パーシャルが描画しても文面が空なら枠しか出ない)
        var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
        Assert.True(notice.Success,
            $"@if (ViewBag.{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
        // 見出しと説明の 2 つの文面が入っていること
        var literals = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
            .Select(m => m.Groups["text"].Value)
            .Where(text => text.Trim().Length > 0)
            .ToList();
        Assert.True(literals.Count >= 2,
            $"@if (ViewBag.{flag}) の {nameof(FilterIgnoredNotice)} に、見出しと説明の両方の文面が要る。");
    }

    // 旗ごとの見出しが互いに違うこと。
    // 2 つの旗は同時に立ちうる(?status=99&dateFrom=abc)ので、見出しが同じだと
    // ほぼ同一の警告が 2 つ並び、利用者からは二重描画の不具合に見える
    // (/Incidents 側で実際にこの取り違えが起き、人のレビューでしか気付けなかった)
    [Fact]
    public void MeasuresIndexView_GivesEachIgnoredFilterNoticeItsOwnHeading()
    {
        // カンバンビューの本文を読む
        var source = ReadMeasuresIndexSource();
        // 見出し → その見出しを使っている旗、の対応を作りながら重複を見る
        var headings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var flag in MeasuresIgnoredFilterFlagNames())
        {
            // その旗で出し分けているブロックを切り出す(per-flag の検査と同じ探し方)
            var header = Regex.Match(source, $@"@if\s*\(\s*ViewBag\.{flag}\b");
            Assert.True(header.Success, $"ViewBag.{flag} で出し分けている注意書きが無い。");
            var blockBody = ExtractBraceBlock(source, header.Index);
            Assert.True(blockBody != null, $"@if (ViewBag.{flag}) に本体が無い。");

            // 見出しは FilterIgnoredNotice の第 1 引数(＝最初の空でない文字列リテラル)
            var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
            Assert.True(notice.Success, $"@if (ViewBag.{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
            var heading = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
                .Select(m => m.Groups["text"].Value)
                .FirstOrDefault(text => text.Trim().Length > 0);
            Assert.True(heading != null, $"@if (ViewBag.{flag}) の注意書きに見出しの文面が無い。");

            // 同じ見出しを別の旗が既に使っていないこと
            Assert.False(headings.TryGetValue(heading!, out var owner),
                $"ViewBag.{flag} の注意書きの見出しが ViewBag.{owner} と同じ(「{heading}」)。"
                + "2 つの旗は同時に立ちうるので、旗ごとに違う見出しを付けること。");
            headings[heading!] = flag;
        }

        // 旗を 1 つも拾えないなら手がかりが死んでいる(fail-closed)
        Assert.True(headings.Count > 0, "注意書きの見出しを 1 つも拾えなかった。");
    }

    // カンバンビューの Razor ソース(コメントを落としたもの)。3 つの走査が同じここを読む
    private static string ReadMeasuresIndexSource()
    {
        // ビルド出力にはコピーされないので絶対パスで開く
        var viewPath = Path.Combine(RepositoryPaths.Views, "PreventiveMeasures", "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"カンバンビューが見つからない: {viewPath}");
        // Razor のコメントは落としてから返す(コメントで検査を満たせないようにする)
        return RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);
    }

    // --- 画面をまたぐ網羅ガード: enum の絞り込みを持つ画面を取りこぼさない ------------

    // 「定義に無い enum 値を採用しない」手当てが要る画面を<b>アプリ全体から</b>導き、
    // 上の behavioural な検査が実際にその全部を覆っていることを照合する。
    //
    // <b>なぜ要るのか(この検査が生まれた経緯)。</b> 手当てはもともと /Incidents にしか無く、
    // それを見張る Theory も typeof(IncidentsController) を名指ししていた。そのため
    // /PreventiveMeasures の ?status=99 は<b>同じ壊れ方をしたまま、どの検査にも掛からず</b>
    // 残っていた(SearchFilter の解説が「残っている境界」として書いていたとおり)。
    // 画面を名指しする検査だけを積んでも、名指ししなかった画面は増えるほど増える。
    //
    // <b>手がかりはアクションの署名</b>: Enum.IsDefined から外れうるのは Nullable&lt;TEnum&gt; の
    // 引数だけ(string? はどんな値でも束縛でき、int? / DateTime? に「定義」という概念が無い)。
    // これはコントローラの実装とは独立した宣言箇所なので、手当てを入れ忘れた画面が
    // <b>ここに現れる</b>。3 画面目が enum の絞り込みを持った時点でこの検査が落ち、
    // 「解決処理へ通す」と「behavioural な検査を足す」の両方を促す。
    //
    // 覆っている画面は下の表に書く。表を手で書くのはここだけで、<b>比べる相手は導出</b>
    // なので、表だけを増やしても導出に無ければ落ちる(逆も同じ)
    [Fact]
    public void EnumFilterScreens_CoverEveryActionThatAcceptsAnEnumFilter()
    {
        // アプリ全体から「Nullable<TEnum> の引数を受けるアクション」を拾う
        var actual = EnumFilterParametersInTheApp();

        // 1 つも拾えないのは「enum の絞り込みが無くなった」より「導出が壊れた」可能性が高い。
        // 「対象ゼロ＝緑」にせず落として、導出かアクションのどちらを直すか人に決めさせる
        Assert.True(actual.Count > 0,
            "Nullable<TEnum> の引数を受けるアクションが 1 つも見つからない。"
            + "導出を変えたなら、この照合も同じ変更セットで直すこと"
            + "(直さないと、定義に無い enum 値の検査が対象ゼロで全件緑になる)。");

        // 覆っていると宣言している画面の一覧(このテストクラスの behavioural な検査が
        // 実際に 1 つずつ確かめているもの)。表に足すだけでは意味が無く、
        // 対応する検査を足すこととセットで初めて意味を持つ
        var covered = new[]
        {
            // MeasuresIndex_DropsAnEnumFilterValueOutsideItsDefinition が確かめる
            $"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.Index)}.status",
            // IncidentsIndex_DropsAnEnumFilterValueOutsideItsDefinition が確かめる
            $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.incidentType",
            $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.severity",
        }
            // 並びを固定してから比べる(宣言順のゆれで落ちないようにする)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 2 つの宣言箇所が一致していること。ずれていれば、手当ての無い画面が増えたか、
        // 逆に無くなった画面が表に残っている
        Assert.Equal(covered, actual);
    }

    // アプリ全体のコントローラから「Nullable<TEnum> のアクション引数」を
    // "<コントローラ名>.<アクション名>.<引数名>" の形で拾う。
    //
    // アクションの選び方を「Index」などの名前に依存させないのは、別名の一覧画面が
    // 増えたときに黙って外れないため。public なインスタンスメソッドのうち
    // コントローラ基底が持つものを除いた＝自分たちが書いたアクション、で切る
    private static List<string> EnumFilterParametersInTheApp() =>
        // 自分たちのアセンブリのコントローラをすべて見る(名前空間の切り直しで外れない)
        typeof(IncidentsController).Assembly.GetTypes()
            .Where(t => typeof(Controller).IsAssignableFrom(t) && !t.IsAbstract)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                // プロパティのゲッターなど、アクションでないものを除く
                .Where(m => !m.IsSpecialName)
                .SelectMany(m => m.GetParameters()
                    // 定義から外れうるのは Nullable<TEnum> の引数だけ
                    .Where(p => Nullable.GetUnderlyingType(p.ParameterType)?.IsEnum == true)
                    .Select(p => $"{t.Name}.{m.Name}.{p.Name}")))
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
}
