// 引数の型が「文字列から変換できるか」を調べるために使う(TypeDescriptor)
using System.ComponentModel;
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
    // 「読めなかった」という状態が存在しない。逆に<b>読めなければ黙って別の値へ化ける</b>のは
    // (a) <c>Nullable&lt;T&gt;</c>(null へ化ける)と (b) 非 null 許容の値型＋既定値
    // (既定値へ化ける)の 2 つで、どちらも失敗の事実は ModelState にしか残らない。
    // つまり Index が受けるその 2 種類の引数が、この手当てが要る入力の実際の一覧になる。
    //
    // <b>(b) を勘定に入れていなかったのが issue #211。</b> 以前ここは
    // <c>Nullable.GetUnderlyingType(...) != null</c> だけで導出していたため、
    // <c>int page = 1</c> は<b>この Theory のケースに入りようがなかった</b> ——
    // 穴が、それを見張るはずの検出網からも同時に外れていた。次に同じ形の引数
    // (<c>bool overdueOnly = false</c> など)を足す人が同じ穴を作らないよう、
    // 導出は「化ける先が null か既定値か」を問わず両方を拾う。
    // 意図的に対象外にする引数は下の MalformedFilterExemptions に理由付きで登録する
    // ——「渡すか、除外するか」を必ず一度は決めさせる形にしてある。
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
    public static TheoryData<string> UnreadableProneParameters() =>
        // 導出そのものは画面をまたいで共有する(下の UnreadableProneTheoryData が正本)
        UnreadableProneTheoryData(IncidentsIndexMethod);

    /// <summary>
    /// アクションの署名から「読めなければ黙って別の値へ化ける」引数を導き、
    /// 意図的な除外を引いたうえで <c>[MemberData]</c> のケースにする。
    /// </summary>
    /// <remarks>
    /// <para><b>画面をまたいで共有する(§6 DRY)。</b> 以前この手順は
    /// <c>/Incidents</c> 用と <c>/PreventiveMeasures</c> 用に写してあり、しかも
    /// <b>除外表を引いていたのは前者だけ</b>だった。3 画面目(<c>/AuditLogs</c>)は
    /// <c>page</c> を受けるので除外を引かないと「ページ番号にも注意書きを出せ」という
    /// 直しようの無い要求になり、写しのまま増やすと除外の扱いが画面ごとにばらける。
    /// 手順を 1 か所に集めれば、どの画面でも同じ規則が掛かる。</para>
    ///
    /// <para><b>0 件を 2 段階で見るのは意図的。</b> 除外を引く前と後で別々に落とすと、
    /// 「引数が変わった」のか「除外表が全部を覆った」のかを取り違えた案内にならない
    /// (前者を直しに行っても、原因の除外表は手つかずのまま残る)。</para>
    /// </remarks>
    /// <param name="action">対象のアクション(一覧の <c>Index</c> など)。</param>
    private static TheoryData<string> UnreadableProneTheoryData(MethodInfo action)
    {
        // 引数のうち「読めなければ黙って別の値へ化ける」ものを、モデルバインドが
        // ModelState のキーに使う「URL 上の名前」で拾う
        var derived = UnreadableProneQueryNames(action).ToList();

        // 除外の前に 0 件かどうかを見る(理由は上の解説)
        Assert.True(derived.Count > 0,
            $"{action.DeclaringType?.Name}.{action.Name} に"
            + "「読めなければ別の値へ化ける」引数が 1 つも無い。"
            + "引数の型を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、読めない値の検査が対象ゼロで全件緑になる)。");

        // 意図的な除外を取り除く
        var names = derived.Where(name => !MalformedFilterExemptions.ContainsKey(name)).ToList();

        // 除外で全部消えた場合は、原因が除外表であることを名指しして落とす
        // (対象ゼロで全件緑になるのは上と同じなので、こちらも fail-closed にする)
        Assert.True(names.Count > 0,
            $"{nameof(MalformedFilterExemptions)} が {action.DeclaringType?.Name}.{action.Name} の"
            + $"引数をすべて覆っている({string.Join(", ", derived)})。除外を足したのなら、"
            + "手当てが要る引数まで巻き込んでいないか確認すること。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var name in names) data.Add(name);
        return data;
    }

    // 上の導出が見る IncidentsController.Index。除外表の検査も同じものを見る
    // (別々に引き直すと、対象のアクションを変えたときに片方だけ取り残される)
    private static MethodInfo IncidentsIndexMethod =>
        typeof(IncidentsController).GetMethod(nameof(IncidentsController.Index))!;

    // 上の導出が見る AuditLogsController.Index(監査ログ一覧)
    private static MethodInfo AuditLogsIndexMethod =>
        typeof(AuditLogsController).GetMethod(nameof(AuditLogsController.Index))!;

    // <b>「読めない値」の手当てを入れてあるアクションの一覧。</b>
    //
    // 除外表に掛かる 2 つの検査(キーが実在するか / Nullable を隠していないか)は
    // <b>この一覧すべて</b>を見る。以前は /Incidents だけを見ていたので、たとえば
    // /AuditLogs にしか無い引数を除外表へ登録しても「実在しない」と誤判定されず、
    // 逆に /AuditLogs の Nullable 引数は「隠せない」の門番をすり抜けた。
    // <b>除外表は URL 上の名前をキーにする(画面ごとに分けない)ので、掛ける範囲も
    // 除外表を引く側とそろえる必要がある</b> ——引く側が 1 つでも多いと、その画面にしか
    // 無い引数を表へ 1 行足すだけで黙らせられる。
    //
    // /Analytics のアクションも載せる。あの画面は ViewModel も page も持たないが、
    // ケースの導出で同じ除外表を引く以上、門番の対象からだけ外すと上の穴になる
    private static IReadOnlyList<MethodInfo> MalformedFilterGuardedActions =>
        new[] { IncidentsIndexMethod, MeasuresIndexMethod, AuditLogsIndexMethod }
            .Concat(AnalyticsActionsWithUnreadableProneParameters())
            .ToList();

    // <b>「読めない値」の手当てから意図的に外している引数</b>(URL 上の名前 → 外す理由)。
    //
    // この表が除外の唯一の真実の源で、導出も下の 3 つの検査も同じここを読む
    // (写しを持つと、どちらへ足しても片方が取り残される ——この repo が
    //  LengthGovernanceExclusions で繰り返し避けている形)。
    //
    // <b>残っている境界: 表そのものは人が判断するエスケープハッチ。</b>
    // 「絞り込みか、そうでないか」は署名からは判定できない(値をクエリの絞り込みに
    // 使っているかどうかは本体の実装の話で、独立な手がかりにならない)。したがって
    // 本物の絞り込みをもっともらしい理由付きでここへ登録すれば、その引数は黙って
    // 検出網から外れる。<b>この表にエントリが増える差分は、理由の妥当性をレビューで
    // 必ず確認すること</b>(LengthGovernanceExclusions と同じ扱い)。
    // せめて濫用の幅は狭めてあり、Nullable&lt;T&gt; の引数は登録できない(下の検査)。
    private static readonly IReadOnlyDictionary<string, string> MalformedFilterExemptions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["page"] =
                "ページ番号は絞り込みではない。?page=abc(読めない)も ?page=99999(範囲外)も "
                + "Index が Math.Clamp で最寄りの有効なページへ丸める同じ扱いで、着地した"
                + "ページはページャが実際に表示している ——絞り込みの注意書きが要るのは"
                + "「送ったのに効いていない」状態が画面から見えなくなるからで、ページングには"
                + "その食い違いが無い。文面(「絞り込みは適用していません」)も合わず、出せば"
                + "絞り込みパネルまで開いて事実と違う案内になる(issue #211。正本は "
                + "MalformedFilterValueResolver の解説)。",
        };

    // 除外表のキーが、いまも実在する「読めなければ化ける」引数を指していること。
    //
    // 引数を消した・改名した・型を string? へ変えたときにエントリだけが残ると、
    // 表は「何を外しているのか分からない飾り」になり、次に同じ名前の引数を足した人が
    // 気付かないまま検出網の外へ置かれる
    [Fact]
    public void MalformedFilterExemptions_AreAllStillReal()
    {
        // 現時点で導出が拾う「読めなければ化ける」引数の URL 上の名前(手当て済みの全画面ぶん)
        var actual = MalformedFilterGuardedActions
            .SelectMany(UnreadableProneQueryNames)
            .ToHashSet(StringComparer.Ordinal);

        // 表のキーのうち、その一覧に無いもの(＝もう実在しない引数)を集める
        var stale = MalformedFilterExemptions.Keys.Where(name => !actual.Contains(name)).ToList();

        // 1 つでもあれば落とす
        Assert.True(stale.Count == 0,
            $"{nameof(MalformedFilterExemptions)} に実在しない引数が残っている: {string.Join(", ", stale)}。"
            + "手当て済みの画面のどの Index からも、その名前の「読めなければ化ける」引数が"
            + "見つからない。引数を消した・改名した・型を変えたなら、"
            + "同じ変更セットでこの表からも消すこと。");
    }

    // 除外の理由が空・空白でないこと。
    //
    // 値を誰も読まないと、理由を "   " にするだけで検出網を黙らせられる
    // (LengthGovernanceExclusions_AllHaveAReason と同じ手当て)
    [Fact]
    public void MalformedFilterExemptions_AllHaveAReason()
    {
        // 理由が空・空白のみのエントリを集める
        var blank = MalformedFilterExemptions
            .Where(pair => string.IsNullOrWhiteSpace(pair.Value))
            .Select(pair => pair.Key)
            .ToList();

        // 1 つでもあれば落とす
        Assert.True(blank.Count == 0,
            $"{nameof(MalformedFilterExemptions)} の理由が空: {string.Join(", ", blank)}。"
            + "「なぜ手当ての対象外でよいのか」を書くこと(理由を書けないなら、"
            + "それは除外してよい引数ではない)。");
    }

    // 除外できるのは「既定値へ化ける」引数だけで、Nullable<T> は登録できないこと。
    //
    // Nullable の引数が読めずに null になると、画面は「そもそも指定が無かった」のと
    // 区別が付かない ——これは issue #198 が塞いだ壊れ方そのもので、除外してよい
    // 理由が原理的に存在しない。エスケープハッチをこの形へ広げないよう門番を置く
    // (置かないと、severity を 1 行足すだけで注意書きを黙らせられる)
    [Fact]
    public void MalformedFilterExemptions_CannotHideANullableFilter()
    {
        // 手当て済みの全画面の Index が受ける Nullable<T> 引数を URL 上の名前で拾う。
        // 1 画面だけを見ると、他の画面にしか無い Nullable の絞り込みを
        // 表へ 1 行足すだけで黙らせられる(除外表は画面ごとに分かれていないため)
        var nullableNames = MalformedFilterGuardedActions
            .SelectMany(action => action.GetParameters())
            .Where(p => Nullable.GetUnderlyingType(p.ParameterType) != null)
            .Select(p => QueryStringName(p)!)
            .ToHashSet(StringComparer.Ordinal);

        // 表がその中のどれかを外していないか調べる
        var hidden = MalformedFilterExemptions.Keys.Where(nullableNames.Contains).ToList();

        // 1 つでもあれば落とす
        Assert.True(hidden.Count == 0,
            $"{nameof(MalformedFilterExemptions)} が Nullable の絞り込みを外している: "
            + $"{string.Join(", ", hidden)}。読めずに null へ化ける引数は「未指定」と"
            + "区別が付かないので(issue #198)、除外ではなく "
            + "MalformedFilterValueResolver へ渡して手当てすること。");
    }

    // アクションの引数のうち<b>読めなければ黙って別の値へ化けるもの</b>を、モデルバインドが
    // ModelState のキーに使う「URL 上の名前」で拾う。/Incidents と /PreventiveMeasures の
    // 導出が共有する(判定を書き写すと、片方だけ直したときにもう片方の検出網が静かに緩む)
    private static IEnumerable<string> UnreadableProneQueryNames(MethodInfo action) =>
        action.GetParameters()
            .Where(IsUnreadableProne)
            .Select(p => QueryStringName(p)!)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal);

    // その引数が「値として読めなかったとき、黙って別の値へ化ける」形かどうか。
    //
    // 条件は 2 つ。
    //
    // (1) <b>値型であること。</b> 化ける先は Nullable&lt;T&gt; なら null、それ以外の値型なら
    //     default(T) だが、どちらも失敗の事実は ModelState にしか残らないので手当ての条件は
    //     同じ。参照型(string? など)はどんな入力でも束縛でき、「読めなかった」という状態が
    //     存在しないので当たらない。
    //     <b>既定値の有無で絞らない。</b> 既定値の無い bool overdueOnly も束縛に失敗すれば
    //     default(bool) に化けるので、手当てが要る条件はまったく同じ ——
    //     HasDefaultValue を条件に足すと、既定値を書かなかった引数だけが黙って
    //     検出網から外れる(issue #211 とまったく同じ穴を、より狭い形で作り直すことになる)。
    //
    // (2) <b>クエリ文字列から文字として束縛される型であること。</b> 判定は
    //     「TypeConverter が string から変換できるか」で、これは MVC の SimpleTypeModelBinder が
    //     効く範囲そのもの。専用のバインダを持つ値型(CancellationToken など)を巻き込まないために要る
    //     ——巻き込むと、Index に CancellationToken ct = default を足しただけで Theory が
    //     「注意書きを出せ」と要求し、しかも変換エラーが積まれないので<b>直しようが無い</b>。
    //     残る道は「絞り込みでない引数を解決処理へ渡す」か「除外表を広げる」の 2 つだけで、
    //     どちらも設計を壊す(実行不能な指示を出す検出網は、いずれ緩められる)。
    //     実測: int / bool / DateTime / enum / Guid とそれぞれの Nullable は変換でき、
    //     CancellationToken はできない
    private static bool IsUnreadableProne(ParameterInfo parameter) =>
        parameter.ParameterType.IsValueType
        && TypeDescriptor.GetConverter(parameter.ParameterType).CanConvertFrom(typeof(string));

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
    [MemberData(nameof(UnreadableProneParameters))]
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
    [MemberData(nameof(UnreadableProneParameters))]
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
    // ?severity= のような<b>空の</b>入力は null 許容型へ null として問題なく束縛され
    // ModelState にエラーを積まないので、ここは「エラーの有無」を見る判定が
    // 空入力を誤って拾わないことの確認になる
    // (空でない未定義値 ?severity=99 の側は既定では逆にエラーが積まれる。issue #215)
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
    // 検出網ごと素通りする —— UnreadableProneParameters と同じ理由・同じやり方で導出にする。
    //
    // <b>手がかりを「読めない値」の Theory と分けている</b>のは、再現のさせ方が違うため ——
    // こちらは実際に未定義の enum 値を引数へ渡す必要があり、あちらの作り方
    // (ModelState へエラーを手で積む)では代用できない。
    // <b>「?severity=99 は ModelState にエラーを積まないから」ではない</b> ——
    // 既定ではむしろ積む(SearchFilter の訂正の段落を参照。issue #215)。
    // なおこの Theory はアクションを直接呼ぶので、モデルバインドを一度も通らない。
    // <b>この検査から「モデルバインドがどう振る舞うか」を結論づけないこと。</b>
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
        var controller = new AnalyticsController(_db, TestFixtures.Clock);
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

    // --- /Analytics: 型として読めない絞り込み値(issue #207) --------------------------

    // 集計 JSON の「読めなかったので採用しなかった」旗を取り出す
    private static bool MalformedFilterIgnored(JsonDocument doc) =>
        doc.RootElement.GetProperty("malformedFilterIgnored").GetBoolean();

    // 手当てが要る (アクション, 引数) の組を、本体とは<b>独立な手がかり</b>(署名)から導く。
    //
    // <b>アクションも引数も書き並べない。</b> 本体側は集計エンドポイントごとに
    // 解決処理を呼び、見張る引数名を nameof で並べて渡す形なので、
    // 6 つ目のエンドポイントを足した人や、既存のエンドポイントへ 3 つ目の期間指定を
    // 足した人が渡し忘れると、<b>そこだけが黙って元の壊れ方に戻る</b>。
    // [InlineData] の手書きにすると同じ人が同じように行を足し忘れるので、
    // 署名から導いて「足した時点で自動でケースに入る」形にする。
    //
    // 1 つも拾えなければ落とす(fail-closed)。署名の書き方を変えると
    // 「対象ゼロ＝全件緑」で検出網が黙って死ぬため
    public static TheoryData<string, string> AnalyticsUnreadableProneParameters()
    {
        // /Analytics のアクションのうち「読めなければ化ける」引数を受けるものを拾う。
        // <b>除外表(MalformedFilterExemptions)は一覧画面と同じく引く。</b> 引かないと、
        // /Analytics へ page のような「絞り込みではない」引数を足した瞬間に
        // 「読めないページ番号にも旗を立てろ」という直しようの無い要求になり、
        // 逃げ道は「絞り込みでない引数を解決処理へ渡す」か「除外表を広げる」しか無くなる
        // (この repo が繰り返し避けている形。除外表は URL 上の名前をキーにするので、
        //  画面ごとに効いたり効かなかったりする状態を作らない)
        var cases = AnalyticsActionsWithUnreadableProneParameters()
            .SelectMany(action => UnreadableProneQueryNames(action)
                .Where(name => !MalformedFilterExemptions.ContainsKey(name))
                .Select(name => (Action: action.Name, Parameter: name)))
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(c => c.Action, StringComparer.Ordinal)
            .ThenBy(c => c.Parameter, StringComparer.Ordinal)
            .ToList();

        // 0 件は「引数が無くなった」より「署名か導出が変わった」可能性が高い
        Assert.True(cases.Count > 0,
            $"{nameof(AnalyticsController)} に「読めなければ別の値へ化ける」引数を受ける"
            + "アクションが 1 つも無い。署名を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、読めない値の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string, string>();
        foreach (var (action, parameter) in cases) data.Add(action, parameter);
        return data;
    }

    // /Analytics のアクションのうち「読めなければ化ける」引数を受けるものを署名から拾う。
    // Theory のケース作りと下の網羅ガードが同じここを読む(§6 DRY)
    private static List<MethodInfo> AnalyticsActionsWithUnreadableProneParameters() =>
        typeof(AnalyticsController)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            // プロパティのゲッターなど、アクションでないものを除く
            .Where(m => !m.IsSpecialName && m.DeclaringType == typeof(AnalyticsController))
            // 「読めなければ化ける」引数を 1 つでも受けるものだけ
            .Where(m => m.GetParameters().Any(IsUnreadableProne))
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(m => m.Name, StringComparer.Ordinal)
            .ToList();

    // 導出で拾ったアクションを名前で呼び分ける(期間・部署はすべて未指定で呼ぶ)。
    // 知らない名前が来たら落とす —— エンドポイントを足しただけで検査が素通りするのを防ぐ
    // (fail-closed。?department= 側の InvokeAnalyticsAsync と同じ扱い)
    private static Task<IActionResult> InvokeAnalyticsWithoutFiltersAsync(
        AnalyticsController controller, string action) => action switch
        {
            nameof(AnalyticsController.MonthlyTrend) => controller.MonthlyTrend(null, null, null),
            nameof(AnalyticsController.ByCause) => controller.ByCause(null, null, null),
            nameof(AnalyticsController.ByDepartment) => controller.ByDepartment(null, null),
            nameof(AnalyticsController.BySeverity) => controller.BySeverity(null, null, null),
            nameof(AnalyticsController.ByIncidentType) => controller.ByIncidentType(null, null),
            _ => throw new InvalidOperationException(
                $"{action} の呼び出し方がこのテストに無い。"
                + "「読めなければ化ける」引数を受けるアクションを足したなら、ここへも呼び出しを足すこと。")
        };

    // 型として読めない絞り込み値でも、黙って落とさず JSON で伝えること(issue #207)。
    //
    // 直っていなかった頃の再現手順: /Analytics/MonthlyTrend?dateFrom=abc を引くと
    // モデルバインドが失敗して dateFrom は null になり、期間の Where を飛ばすだけなので
    // <b>期間を絞ったかのような全期間のグラフ</b>が旗も無しで返る。医療インシデントの
    // 集計画面で「その期間は 0 件だった」と「期間の指定が読めなかった」を区別できないのは
    // 誤読が重い ——一覧・カンバンで注意書きを出しているのとまったく同じ理由。
    //
    // 伝え先が JSON なのはこの画面に注意書きを出す場所が無いためで、
    // 既存の departmentFilterIgnored と同じ扱い(キーの追加は形状契約を壊さない)
    [Theory]
    [MemberData(nameof(AnalyticsUnreadableProneParameters))]
    public async Task Analytics_ReportsAFilterValueThatCannotBeRead(string action, string parameterName)
    {
        // 集計対象を 1 件用意する(旗が「0 件だから立った」のではないことを示すため)
        await SeedAnalyticsRowAsync("ICU");

        // ModelState は ControllerContext と一緒に作られるので、先にコントローラを組み立てる
        var controller = NewAnalyticsController();
        // モデルバインドが「値は届いたが読めなかった」ときに積むエラーを再現する
        controller.ModelState.AddModelError(parameterName, "値の形式が正しくありません。");
        // 絞り込みの引数はすべて null(モデルバインドが失敗した後の状態)で集計を引く
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsWithoutFiltersAsync(controller, action));

        // 受け取ったのに採用しなかったことを JSON で伝えている
        Assert.True(MalformedFilterIgnored(doc),
            $"{action}?{parameterName}=<読めない値> を受け取ったのに旗が立たない。"
            + $"MalformedFilterValueResolver へ {parameterName} を渡し忘れていないか確認すること。");

        // 絞り込みは掛かっていない(全件が返る)。旗はまさにこの状態を伝えるためにある
        Assert.Equal(1, TotalCount(doc));
    }

    // 逆に、正しく読めた値では旗を立てないこと。
    //
    // <b>ModelState にエントリがあること自体を条件にしてはいけない。</b>
    // モデルバインドは成功した引数にもエントリを作る(束縛した値を記録するため)ので、
    // キーの存在で判定すると<b>正しい値を送るたびに旗が立つ</b>(誤検知)。
    // この誤検知はコントローラを直接呼ぶだけでは再現しない(モデルバインドを通らないので
    // ModelState が空のまま)ため、SetModelValue で「束縛に成功した引数」の状態を作る
    [Theory]
    [MemberData(nameof(AnalyticsUnreadableProneParameters))]
    public async Task Analytics_ReportsNothing_WhenTheFilterValueWasReadable(string action, string parameterName)
    {
        // 集計対象を 1 件用意する
        await SeedAnalyticsRowAsync("ICU");

        // 「値が届いて、束縛にも成功した」状態を作る(エラーの無いエントリ)
        var controller = NewAnalyticsController();
        controller.ModelState.SetModelValue(parameterName, "1", "1");
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsWithoutFiltersAsync(controller, action));

        // 読めなかった値は無いので旗は立たない
        Assert.False(MalformedFilterIgnored(doc),
            $"{action}?{parameterName}=<読める値> で旗が立っている。"
            + "MalformedFilterValueResolver が「エントリの有無」ではなく"
            + "「エラーの有無」を見ているか確認すること。");
    }

    // <b>そもそも値が届いていない</b>ときも旗を立てないこと。
    //
    // 上の検査とは別に要る ——あちらは「エントリはあるがエラーが無い」状態を見るので、
    // 解決処理の「エントリが無ければ未指定」の枝(TryGetValue の門番)は一度も通らない。
    // その枝を「エントリが無ければ採用しなかった扱い」へ変えると、期間を指定していない
    // <b>普通の集計要求すべてで旗が立つ</b>のに、上の Theory は緑のまま通る。
    // 旗が出っぱなしになると、読む側(この JSON を使う画面・外部スクリプト)が読まなくなる。
    //
    // アクションごとに掛けるのは、1 つの代表だけを見る形にすると
    // 新しいエンドポイントがこの経路の検査から黙って外れるため
    [Theory]
    [MemberData(nameof(AnalyticsActionsWithDateRangeFilters))]
    public async Task Analytics_ReportsNothing_WhenNoFilterValueWasSent(string action)
    {
        // 集計対象を 1 件用意する
        await SeedAnalyticsRowAsync("ICU");

        // 絞り込みを一切指定せずに集計を引く(ModelState は空のまま)
        using var doc = JsonResultReader.ToJsonDocument(
            await InvokeAnalyticsWithoutFiltersAsync(NewAnalyticsController(), action));

        // 受け取っていないものは「採用しなかった」ではない
        Assert.False(MalformedFilterIgnored(doc),
            $"{action} を絞り込み無しで引いたのに旗が立っている。"
            + "MalformedFilterValueResolver が「エントリが無い＝未指定」を"
            + "正しく素通ししているか確認すること。");
        // 集計そのものは普通に返る
        Assert.Equal(1, TotalCount(doc));
    }

    // 上の検査のケース(アクション名だけ)。引数ごとの Theory と同じ導出から作るので、
    // エンドポイントを足せば両方に自動で入る
    public static TheoryData<string> AnalyticsActionsWithDateRangeFilters()
    {
        // 「読めなければ化ける」引数を受けるアクションの名前を並べる
        var actions = AnalyticsActionsWithUnreadableProneParameters()
            .Select(m => m.Name)
            .ToList();

        // 0 件は「エンドポイントが無くなった」より「導出が壊れた」可能性が高い(fail-closed)
        Assert.True(actions.Count > 0,
            $"{nameof(AnalyticsController)} に「読めなければ別の値へ化ける」引数を受ける"
            + "アクションが 1 つも無い。導出を変えたなら、この照合も同じ変更セットで直すこと。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var action in actions) data.Add(action);
        return data;
    }

    // --- 画面をまたぐ網羅ガード: 期間の絞り込みを持つ画面を取りこぼさない ------------

    // 「読めない期間指定を伝える」手当てが要るアクションを<b>アプリ全体から</b>導き、
    // 実際にその全部が覆われていることを照合する。
    //
    // <b>なぜ要るのか(この検査が生まれた経緯)。</b> 手当てはもともと /Incidents にしか無く、
    // それを見張る検査も画面を名指ししていた。そのため /AuditLogs?dateFrom=abc と
    // /Analytics/MonthlyTrend?dateFrom=abc は<b>同じ壊れ方をしたまま、どの検査にも掛からず</b>
    // 残っていた(SearchFilter の解説が「残っている境界」として書いていたとおり。issue #207)。
    // 画面を名指しする検査だけを積んでも、名指ししなかった画面は増えるほど増える。
    //
    // <b>手がかりは DateTime? の引数</b>: このアプリで期間の絞り込みはすべてこの型で受ける。
    // アクションの署名はコントローラの実装とは独立した宣言箇所なので、手当てを入れ忘れた
    // 画面が<b>ここに現れる</b>。4 画面目が期間の絞り込みを持った時点でこの検査が落ち、
    // 「解決処理へ通す」と「behavioural な検査を足す」の両方を促す。
    //
    // <b>「読めなければ化ける引数すべて」まで広げないのは意図的。</b> それだと
    // Details(long id) / Delete(int id) のような<b>ルートのキー</b>まで巻き込む ——
    // あちらは読めなければ 404 / 400 になって画面から見えるので、絞り込みの
    // 「送ったのに効いていないことが見えない」問題が存在しない。実行不能な要求を出す
    // 検出網はいずれ緩められるので、手がかりは「このアプリで絞り込みにしか使われない型」に絞る。
    // <b>この境界は他の型の絞り込みを足す人が広げる</b>(int? の範囲指定など)。
    [Fact]
    public void MalformedFilterScreens_CoverEveryActionThatAcceptsADateRangeFilter()
    {
        // アプリ全体から「DateTime? の引数を受けるアクション」を拾う
        var actual = DateRangeActionParametersInTheApp();

        // 1 つも拾えないのは「期間の絞り込みが無くなった」より「導出が壊れた」可能性が高い。
        // 「対象ゼロ＝緑」にせず落として、導出かアクションのどちらを直すか人に決めさせる
        Assert.True(actual.Count > 0,
            "DateTime? の引数を受けるアクションが 1 つも見つからない。"
            + "導出を変えたなら、この照合も同じ変更セットで直すこと"
            + "(直さないと、読めない期間指定の検査が対象ゼロで全件緑になる)。");

        // 「どの引数が、どの検査で覆われているか」の表。
        //
        // 覆い方は伝え先によって 3 通りあるが、<b>どれでもよい代わりに「どれでもない」は許さない</b>。
        //   - ViewModel … 画面の注意書き(/Incidents ・ /AuditLogs)。
        //     *Index_ReportsAFilterValueThatCannotBeRead が確かめる。
        //   - ViewBag …… 画面の注意書き(/PreventiveMeasures。ViewModel を持たない画面)。
        //     MeasuresIndex_ReportsAFilterValueThatCannotBeRead が確かめる。
        //   - Json ……… 集計 JSON のキー(/Analytics。注意書きを出す場所が無い画面)。
        //     Analytics_ReportsAFilterValueThatCannotBeRead が確かめる。
        //
        // 表を手で書くのはここだけで、<b>比べる相手は導出</b>なので、
        // 表だけを増やしても導出に無ければ落ちる(逆も同じ)
        var guarded = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [$"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.dateFrom"] = "ViewModel",
            [$"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.dateTo"] = "ViewModel",
            [$"{nameof(AuditLogsController)}.{nameof(AuditLogsController.Index)}.dateFrom"] = "ViewModel",
            [$"{nameof(AuditLogsController)}.{nameof(AuditLogsController.Index)}.dateTo"] = "ViewModel",
            [$"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.Index)}.dateFrom"] = "ViewBag",
            [$"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.Index)}.dateTo"] = "ViewBag",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.MonthlyTrend)}.dateFrom"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.MonthlyTrend)}.dateTo"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByCause)}.dateFrom"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByCause)}.dateTo"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByDepartment)}.dateFrom"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByDepartment)}.dateTo"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.BySeverity)}.dateFrom"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.BySeverity)}.dateTo"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByIncidentType)}.dateFrom"] = "Json",
            [$"{nameof(AnalyticsController)}.{nameof(AnalyticsController.ByIncidentType)}.dateTo"] = "Json",
        };

        // 2 つの宣言箇所が一致していること。ずれていれば、手当てを決めていない期間の絞り込みが
        // 増えたか、逆に無くなった引数が表に残っている
        Assert.Equal(
            guarded.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList(),
            actual);

        // <b>伝え先の値も見る。</b> キーだけを突き合わせると、値は誰にも読まれない飾りになり、
        // 「どの引数を、どの伝え先で覆っているか」の唯一の真実の源を名乗る表が黙って腐る
        // (実在しない伝え先や空文字を書いても全件緑のまま通る)。値を既知の 3 つに限ると、
        // <b>行を足す人は伝え先を選ばされる</b> ——選べない引数(たとえば絞り込みでない
        // POST の DateTime?)はそもそもこの表に載せる対象ではない、と気付く入り口になる
        // (LengthGovernanceExclusions_AllHaveAReason と同じ手当て。あちらは理由が
        //  "   " でも通ってしまった実測があり、値を読まない表は必ずそうなる)
        var unknown = guarded
            .Where(pair => !MalformedFilterDeliveries.Contains(pair.Value))
            .Select(pair => $"{pair.Key} = 「{pair.Value}」")
            .ToList();
        Assert.True(unknown.Count == 0,
            $"表の伝え先が既知のどれでもない: {string.Join(" / ", unknown)}。"
            + $"使える伝え先は {string.Join(" / ", MalformedFilterDeliveries)} の 3 つで、"
            + "それぞれに対応する behavioural な検査がある。新しい伝え先を作ったのなら、"
            + "その検査と一緒にここへ足すこと(選べないなら、それはこの表に載せる引数ではない)。");
    }

    // 「読めなかったことをどう伝えるか」の選択肢。表の値はこの 3 つに限る。
    // 文字列を表と検査の 2 か所へ直書きすると、片方だけ増やしたときに検査が黙って緩む(§6)
    private static readonly IReadOnlySet<string> MalformedFilterDeliveries =
        new HashSet<string>(StringComparer.Ordinal) { "ViewModel", "ViewBag", "Json" };

    // アプリ全体のコントローラから「DateTime? のアクション引数」を
    // "<コントローラ名>.<アクション名>.<引数名>" の形で拾う。
    //
    // コントローラの選び方・DeclaredOnly で絞らない理由は
    // EnumActionParametersInTheApp と同じ(そちらの解説が正本)。
    // 走査の形をそろえてあるのは、片方だけ拾い方を直したときに
    // もう片方の検出網が黙って狭くなるのを避けるため
    private static List<string> DateRangeActionParametersInTheApp()
    {
        // 自分たちのアセンブリ(名前空間の切り直しで外れない)
        var ownAssembly = typeof(IncidentsController).Assembly;
        // そのアセンブリのコントローラをすべて見る
        return ownAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                // プロパティのゲッターなど、アクションでないものを除く
                .Where(m => !m.IsSpecialName)
                // 宣言元が自分たちのアセンブリのものだけ(Controller/object の public メソッドを拾わない)
                .Where(m => m.DeclaringType?.Assembly == ownAssembly)
                .SelectMany(m => m.GetParameters()
                    // 期間の絞り込みは必ず DateTime? で受ける
                    .Where(p => p.ParameterType == typeof(DateTime?))
                    .Select(p => $"{t.Name}.{m.Name}.{p.Name}")))
            // 同じアクションが複数の型から見えても 1 件に畳む(自前の基底から継いだ場合)
            .Distinct(StringComparer.Ordinal)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
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
        // 「<ViewModel のプロパティ> = <解決結果>.Ignored」という代入を全部拾う。
        // ソースを開く手順も走査の規則も、カンバン側とまったく同じなので共有する
        // (IgnoredFilterFlagNamesIn が正本。写しを持つと、規則を直したときに片方が取り残される)
        var assigned = IgnoredFilterFlagNamesIn(nameof(IncidentsController));

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
    public void IncidentsIndexView_RendersTheIgnoredFilterNotice(string flag) =>
        // 走査そのものは 3 画面で共有する(下の AssertIgnoredFilterNoticeIsRendered が正本)
        AssertIgnoredFilterNoticeIsRendered("Incidents", ViewModelFlagAccessor, flag);

    /// <summary>
    /// 旗を <b>ビューが実際に読んでいる</b>ことを、Razor のソースから確かめる共有の走査。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ 3 画面で共有するのか(§6 DRY)。</b> 以前この走査は
    /// <c>/Incidents</c> 用と <c>/PreventiveMeasures</c> 用に丸ごと写してあった。
    /// 3 画面目(<c>/AuditLogs</c>)を足す時点で 3 つ目の写しになるので、実際に重複した
    /// この時点で共通化する。写しのまま増やすと、注意書きの見せ方を変えたとき
    /// (枠を別のパーシャルへ移す・文面の渡し方を変える 等)に 1 つが取り残され、
    /// <b>取り残された画面だけが検査の外へ出る</b> ——この repo が
    /// <c>IgnoredFilterFlagNamesIn</c> でも同じ理由で共通化している形。</para>
    ///
    /// <para><b>画面ごとに違うのは 2 つだけ</b>: ビューの置き場所と、旗の読み方
    /// (<c>Model.</c> か <c>ViewBag.</c> か)。それを引数で受ける。</para>
    /// </remarks>
    /// <param name="viewFolder">ビューの置き場所(<c>Views/&lt;ここ&gt;/Index.cshtml</c>)。</param>
    /// <param name="accessor">旗の読み方の前置き(<c>Model.</c> または <c>ViewBag.</c>)。</param>
    /// <param name="flag">確かめる旗の名前。</param>
    private static void AssertIgnoredFilterNoticeIsRendered(string viewFolder, string accessor, string flag)
    {
        // 一覧ビューの Razor ソースを読む(コメントは落としてある)
        var source = ReadIndexViewSource(viewFolder);

        // 旗で表示を出し分けている。
        // 「名前がどこかに出てくるか」では足りない —— この旗は絞り込みパネルを開くかどうかの
        // 判定(anyFilter)からも参照しているので、注意書きのブロックを丸ごと消しても
        // その 1 行が条件を満たしてしまう(実測で全件緑のまま通った)。
        // 出し分けの構文そのものを探して、注意書きが実際に描画されることを確かめる。
        // 空白の有無や比較の書き方に依存しない形で探す。`@if (Model.X)` の完全一致で書くと、
        // `@if(Model.X)` のように同じ働きの正しい書き方を落としてしまい、
        // 次の人が動いているマークアップを「直し」に行く検出網になる
        var header = Regex.Match(source, $@"@if\s*\(\s*{Regex.Escape(accessor)}{flag}\b");
        Assert.True(header.Success,
            $"Views/{viewFolder}/Index.cshtml が {accessor}{flag} で注意書きを出し分けていない。");

        // 出し分けているだけでなく、そのブロックに中身があることまで見る。
        // ヘッダだけを見ると、本文を空にする変異が素通りする
        var blockBody = ExtractBraceBlock(source, header.Index);
        Assert.True(blockBody != null,
            $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{flag}) に本体が無い。");
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
            $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{flag}) が注意書きのパーシャルを呼んでいない。"
            + "枠のマークアップを直接書くか、この照合を同じ変更セットで直すこと。");

        // 呼んでいるパーシャルの中身を読む(ビルド出力にはコピーされないので絶対パスで開く)。
        // 置き場所をその画面のフォルダ決め打ちにしない —— Razor 自身は
        // /Views/{コントローラ名}/ と /Views/Shared/ の順に探すので、決め打ちにすると
        // 実行時には正しく解決されるパーシャルをテストだけが「見つからない」と言う
        // (実際 2 画面目が注意書きを持ったとき Views/Shared/ へ移してここが落ちた)
        var partialSource = ReadPartial(viewFolder, partialCall.Groups["name"].Value);

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
            $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
        // 引数として渡している文字列リテラルのうち、空でないものを数える
        var literals = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
            .Select(m => m.Groups["text"].Value)
            .Where(text => text.Trim().Length > 0)
            .ToList();
        Assert.True(literals.Count >= 2,
            $"@if ({accessor}{flag}) の {nameof(FilterIgnoredNotice)} に、見出しと説明の両方の文面が要る。");
    }

    // 注意書きを出す画面と、その画面での旗の読み方。
    // 下の「画面をまたいで文面をそろえる」検査が全画面を見るために要る
    // ——1 画面でも書き漏らすと、その画面だけが照合から外れて文面が割れる
    private static readonly (string ViewFolder, string Accessor)[] IgnoredFilterNoticeScreens =
    {
        ("Incidents", ViewModelFlagAccessor),
        ("PreventiveMeasures", ViewBagFlagAccessor),
        ("AuditLogs", ViewModelFlagAccessor),
    };

    // 同じ理由の注意書きは、画面をまたいで<b>一字一句そろっている</b>こと。
    //
    // <b>なぜ検査で縛るのか。</b> 「同じ理由で採用しなかったのに画面ごとに言い回しが違うと、
    // 利用者は別の出来事だと受け取る」は各ビューのコメントが要求しているだけで、
    // 守られているかを見る仕組みが無かった ——1 画面の説明文だけを書き換えても
    // 全件緑のまま通る(per-flag の検査は「適用していません」を含むことと
    // 「空でない文面が 2 つある」ことしか見ない)。これは §6 が禁じる
    // 「同じ文言を各所へ直書きする」形そのものだった。
    //
    // <b>照合の仕方。</b> 対応表を手で持たない ——旗の名前は画面ごとに違いうる
    // (/AuditLogs は許可リストなので UnlistedFilterIgnored、/Incidents は enum なので
    //  UnlistedEnumFilterIgnored)ので、名前で突き合わせると対応表が必要になり、
    // その表が古くなる。代わりに<b>文面そのもの</b>を手がかりにする:
    // 見出しが同じなら説明も同じ、説明が同じなら見出しも同じ、を求める。
    // これで「片方の画面だけ言い換える」変更は必ずどちらかの向きで落ちる。
    [Fact]
    public void IgnoredFilterNotices_UseTheSameWordingAcrossScreens()
    {
        // 画面をまたいで (見出し, 説明) の組をすべて集める
        var notices = IgnoredFilterNoticeScreens
            .SelectMany(screen => IgnoredFilterNoticeTexts(screen.ViewFolder, screen.Accessor))
            .ToList();

        // 1 つも拾えなければ手がかりが死んでいる(fail-closed)
        Assert.True(notices.Count > 0, "注意書きの文面を 1 つも拾えなかった。");

        // 見出しが同じなら説明も同じであること
        foreach (var group in notices.GroupBy(n => n.Heading, StringComparer.Ordinal))
        {
            // その見出しで使われている説明の種類
            var details = group.Select(n => n.Detail).Distinct(StringComparer.Ordinal).ToList();
            Assert.True(details.Count == 1,
                $"見出し「{group.Key}」の説明文が画面ごとに違う"
                + $"({string.Join(" / ", group.Select(n => n.Screen))})。"
                + "同じ理由で採用しなかったのに言い回しが違うと、利用者は別の出来事だと受け取る。"
                + "文面を変えるときは、その見出しを使っている画面すべてを同じ変更セットで直すこと。");
        }

        // 説明が同じなら見出しも同じであること(逆向きの取り違えを塞ぐ)
        foreach (var group in notices.GroupBy(n => n.Detail, StringComparer.Ordinal))
        {
            // その説明で使われている見出しの種類
            var headings = group.Select(n => n.Heading).Distinct(StringComparer.Ordinal).ToList();
            Assert.True(headings.Count == 1,
                $"同じ説明文に別の見出しが付いている: {string.Join(" / ", headings)}"
                + $"({string.Join(" / ", group.Select(n => n.Screen))})。");
        }
    }

    // 1 画面のビューから、注意書きの (見出し, 説明) を旗ごとに取り出す。
    // 切り出し方は per-flag の検査と同じ(FilterIgnoredNotice の第 1・第 2 引数)
    private static List<(string Screen, string Heading, string Detail)> IgnoredFilterNoticeTexts(
        string viewFolder, string accessor)
    {
        // ビューの Razor ソースを読む(コメントは落としてある)
        var source = ReadIndexViewSource(viewFolder);
        // 旗で出し分けているブロックをすべて拾う
        var texts = new List<(string, string, string)>();
        foreach (Match header in Regex.Matches(source, $@"@if\s*\(\s*{Regex.Escape(accessor)}(?<flag>\w*FilterIgnored)\b"))
        {
            // そのブロックの本体を切り出す
            var blockBody = ExtractBraceBlock(source, header.Index);
            Assert.True(blockBody != null,
                $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{header.Groups["flag"].Value}) に本体が無い。");
            // FilterIgnoredNotice の組み立て位置を探す
            var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
            Assert.True(notice.Success,
                $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{header.Groups["flag"].Value}) が "
                + $"{nameof(FilterIgnoredNotice)} を組み立てていない。");
            // 空でない文字列リテラルを順に取る。先頭が見出し、残りを連結したものが説明
            // (説明は行をまたいで `+` で連結して書かれている)
            var literals = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
                .Select(m => m.Groups["text"].Value)
                .Where(text => text.Trim().Length > 0)
                .ToList();
            Assert.True(literals.Count >= 2,
                $"Views/{viewFolder}/Index.cshtml の @if ({accessor}{header.Groups["flag"].Value}) の"
                + $"{nameof(FilterIgnoredNotice)} に、見出しと説明の両方の文面が要る。");
            texts.Add((viewFolder, literals[0], string.Concat(literals.Skip(1))));
        }

        // その画面から 1 つも拾えないなら、走査が書き方の変更に追随できていない(fail-closed)
        Assert.True(texts.Count > 0,
            $"Views/{viewFolder}/Index.cshtml から注意書きの文面を 1 つも拾えなかった。");
        return texts;
    }

    // 旗の読み方の前置き。ViewModel を持つ画面(/Incidents ・ /AuditLogs)は Model. で、
    // ViewBag で渡す画面(/PreventiveMeasures)は ViewBag. で読む。
    // 文字列を各所へ直書きすると、読み方を変えたときに一部だけが取り残される(§6)
    private const string ViewModelFlagAccessor = "Model.";
    private const string ViewBagFlagAccessor = "ViewBag.";

    /// <summary>
    /// 一覧ビューの Razor ソース(コメントを落としたもの)を読む。
    /// </summary>
    /// <remarks>
    /// 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす。
    /// Razor のコメントを先に落とすのは、コメントで検査を満たしたり破ったりできないようにするため。
    /// </remarks>
    private static string ReadIndexViewSource(string viewFolder)
    {
        // ビルド出力にはコピーされないので絶対パスで開く
        var viewPath = Path.Combine(RepositoryPaths.Views, viewFolder, "Index.cshtml");
        // 見つからなければ落とす(対象ゼロで全件緑になるのを避ける)
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        // Razor のコメントは落としてから返す
        return RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);
    }

    /// <summary>
    /// 旗ごとの注意書きの<b>見出しが互いに違う</b>ことを確かめる共有の走査。
    /// </summary>
    /// <remarks>
    /// 旗は同時に立ちうる(<c>?severity=99&amp;dateFrom=abc</c>)ので、見出しが同じだと
    /// ほぼ同一の警告が 2 つ並び、利用者からは<b>二重描画の不具合に見える</b>。
    /// 実際 issue #208 の対応でこの取り違えが起き、全件緑のまま通った
    /// (人のレビューでしか気付けなかった)。
    /// per-flag の検査は「見出しと説明が空でないこと」までしか見ないので、
    /// 衝突は旗をまたいで比べないと原理的に見えない。
    /// <para>走査を 3 画面で共有する理由は
    /// <see cref="AssertIgnoredFilterNoticeIsRendered"/> と同じ(§6 DRY)。</para>
    /// </remarks>
    private static void AssertIgnoredFilterNoticeHeadingsAreDistinct(
        string viewFolder, string accessor, IEnumerable<string> flags)
    {
        // 一覧ビューの Razor ソースを読む
        var source = ReadIndexViewSource(viewFolder);
        // 見出し → その見出しを使っている旗、の対応を作りながら重複を見る
        var headings = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var flag in flags)
        {
            // その旗で出し分けているブロックを切り出す(per-flag の検査と同じ探し方)
            var header = Regex.Match(source, $@"@if\s*\(\s*{Regex.Escape(accessor)}{flag}\b");
            Assert.True(header.Success, $"{accessor}{flag} で出し分けている注意書きが無い。");
            var blockBody = ExtractBraceBlock(source, header.Index);
            Assert.True(blockBody != null, $"@if ({accessor}{flag}) に本体が無い。");

            // 見出しは FilterIgnoredNotice の第 1 引数(＝最初の空でない文字列リテラル)
            var notice = Regex.Match(blockBody!, $@"new\s+{nameof(FilterIgnoredNotice)}\s*\(");
            Assert.True(notice.Success, $"@if ({accessor}{flag}) が {nameof(FilterIgnoredNotice)} を組み立てていない。");
            var heading = Regex.Matches(blockBody![notice.Index..], @"""(?<text>[^""]*)""")
                .Select(m => m.Groups["text"].Value)
                .FirstOrDefault(text => text.Trim().Length > 0);
            Assert.True(heading != null, $"@if ({accessor}{flag}) の注意書きに見出しの文面が無い。");

            // 同じ見出しを既に別の旗が使っていないこと
            Assert.False(headings.TryGetValue(heading!, out var owner),
                $"{accessor}{flag} の注意書きの見出しが {accessor}{owner} と同じ(「{heading}」)。"
                + "2 つの旗は同時に立ちうるので、同じ見出しだとほぼ同一の警告が 2 つ並び、"
                + "二重描画の不具合に見える。旗ごとに違う見出しを付けること。");
            headings[heading!] = flag;
        }

        // 旗を 1 つも拾えないなら手がかりが死んでいる(fail-closed)
        Assert.True(headings.Count > 0, "注意書きの見出しを 1 つも拾えなかった。");
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
    public void IncidentsIndexView_GivesEachIgnoredFilterNoticeItsOwnHeading() =>
        // 走査そのものは 3 画面で共有する(AssertIgnoredFilterNoticeHeadingsAreDistinct が正本)
        AssertIgnoredFilterNoticeHeadingsAreDistinct(
            "Incidents", ViewModelFlagAccessor, DeclaredIgnoredFilterFlags());

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
    [MemberData(nameof(MeasuresUnreadableProneParameters))]
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

    // カンバンの Index が受ける「読めなければ黙って別の値へ化ける」引数を導く。
    // 導出の理由と fail-closed にする理由は /Incidents 側の UnreadableProneParameters が正本。
    //
    // 判定(UnreadableProneQueryNames)は /Incidents と共有する。以前ここは Nullable だけを
    // C# の引数名で拾っており、あちらと 2 点ずれていた ——(1) 非 null 許容の値型＋既定値を
    // 拾えない(issue #211 と同じ穴)、(2) [FromQuery(Name = ...)] で別名を付けると本体は
    // 引数名を見張り MVC は別名にエラーを積む食い違いが検出できない。写しを持つ限り
    // 片方だけ直されて、もう片方の検出網が静かに緩む(§6 DRY)。
    //
    // 除外表を持たないのは、この画面に外している引数が 1 つも無いため
    // (先回りで用意すると、実在しない事情のための分岐を増やすことになる。§6)
    public static TheoryData<string> MeasuresUnreadableProneParameters() =>
        // 導出そのものは画面をまたいで共有する(UnreadableProneTheoryData が正本)
        UnreadableProneTheoryData(MeasuresIndexMethod);

    // 上の導出が見るアクション。1 か所に置くのは、対象のアクションを変えたときに
    // 導出と除外表の検査で片方だけ取り残されるのを防ぐため(/Incidents 側と同じ扱い)
    private static MethodInfo MeasuresIndexMethod =>
        typeof(PreventiveMeasuresController).GetMethod(nameof(PreventiveMeasuresController.Index))!;

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

    // 上の導出の本体。Theory のケース作りと下の見出し照合が同じここを読む(§6 DRY)。
    // 走査そのものは /Incidents 側と共有する(下の IgnoredFilterFlagNamesIn が正本)
    private static List<string> MeasuresIgnoredFilterFlagNames() =>
        IgnoredFilterFlagNamesIn(nameof(PreventiveMeasuresController));

    // コントローラのソースから「<旗> = <解決結果>.Ignored」という代入を拾い、旗の名前を返す。
    //
    // <b>2 画面で共有する(レビュー指摘で共通化)。</b> 以前は同じ正規表現・同じ
    // 「ソースを開く → コメントを落とす → 並びを固定する」の手順が /Incidents 用と
    // カンバン用に写してあった。3 つ目の解決処理が旗を別の名前(<c>.WasIgnored</c> など)で
    // 返すようになったとき片方だけ直すと、<b>直さなかった側は既存の旗を拾い続けるので
    // 「0 件なら落とす」門番が働かず</b>、新しい旗が誰にも読まれない書き込み専用の値になる。
    //
    // コメントを先に落とすのは、`// 例: SeverityFilterIgnored = severityFilter.Ignored` のような
    // 普通の説明コメント 1 行で<b>正しいコードのまま検査が落ちる</b>ため(実測)。
    // 正しいコードを咎める検出網はいずれ緩められるので、走査対象から外す
    private static List<string> IgnoredFilterFlagNamesIn(string controllerTypeName)
    {
        // コントローラのソースを開く(ビルド出力にはコピーされないので絶対パスで開く)
        var controllerPath = Path.Combine(
            RepositoryPaths.WebProject, "Controllers", $"{controllerTypeName}.cs");
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
    public void MeasuresIndexView_RendersTheIgnoredFilterNotice(string flag) =>
        // 走査そのものは 3 画面で共有する(AssertIgnoredFilterNoticeIsRendered が正本)。
        // この画面は ViewModel を持たず ViewBag で渡すので、読み方だけが違う
        AssertIgnoredFilterNoticeIsRendered("PreventiveMeasures", ViewBagFlagAccessor, flag);

    // 旗ごとの見出しが互いに違うこと。
    // 2 つの旗は同時に立ちうる(?status=99&dateFrom=abc)ので、見出しが同じだと
    // ほぼ同一の警告が 2 つ並び、利用者からは二重描画の不具合に見える
    // (/Incidents 側で実際にこの取り違えが起き、人のレビューでしか気付けなかった)
    [Fact]
    public void MeasuresIndexView_GivesEachIgnoredFilterNoticeItsOwnHeading() =>
        // 走査そのものは 3 画面で共有する(AssertIgnoredFilterNoticeHeadingsAreDistinct が正本)
        AssertIgnoredFilterNoticeHeadingsAreDistinct(
            "PreventiveMeasures", ViewBagFlagAccessor, MeasuresIgnoredFilterFlagNames());

    // --- /AuditLogs: 型として読めない絞り込み値(issue #207) --------------------------

    // 監査ログ画面の「読めなければ化ける」引数を、本体とは独立な手がかり(署名)から導く。
    // 導出そのものは画面をまたいで共有する(UnreadableProneTheoryData が正本)
    public static TheoryData<string> AuditLogsUnreadableProneParameters() =>
        UnreadableProneTheoryData(AuditLogsIndexMethod);

    // 監査ログ画面を組み立てる。この画面は Admin 専用なので Admin を載せる
    private AuditLogsController NewAuditLogsController()
    {
        // 依存は本物の InMemory DbContext を使う(Mock より InMemory を優先する repo の方針)
        var controller = new AuditLogsController(_db);
        // 実行ロールを載せる(監査ログは Admin 専用)
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 組み立てたコントローラを返す
        return controller;
    }

    // 監査ログを 1 行だけ積む。どの検査も「絞り込みが効いたら消える 1 件」があれば足りる。
    //
    // インターセプタ経由ではなく直接 Add するのは、この検査の関心が
    // 「絞り込みの受け取り方」だけで、行の出どころが結果に影響しないため
    // (InMemory ではインターセプタが書く行も同じテーブルに入る)
    private async Task SeedSingleAuditLogAsync()
    {
        // 一覧に出る行を 1 つ用意する
        _db.AuditLogs.Add(new AuditLog
        {
            // 監査対象の先頭(ドメインの順で最初＝インシデント)を使い、名前を書き写さない
            EntityName = AuditSaveChangesInterceptor.AuditedEntities[0],
            EntityKey = "1",
            // 語彙を書き写さず、本体が使っている許可リストの先頭から取る
            Operation = AuditLogsAllowLists["operation"][0],
            ChangedBy = "tester",
            ChangedAt = TestFixtures.Today,
            ChangesJson = "{}"
        });
        // 保存して一覧から読めるようにする
        await _db.SaveChangesAsync();
    }

    // /AuditLogs の一覧を引いて ViewModel を取り出す
    private async Task<AuditLogListViewModel> AuditLogsIndexAsync(AuditLogsController controller)
    {
        // 絞り込みは指定せずに一覧を引く(ModelState の状態だけを変えて呼び分ける)
        var result = await controller.Index(null, null, null, null, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<AuditLogListViewModel>(result!.Model);
    }

    // 型として読めない絞り込み値でも、黙って落とさず注意書きを出すこと(issue #207)。
    //
    // 直っていなかった頃の再現手順: /AuditLogs?dateFrom=abc を開くとモデルバインドが
    // 失敗して dateFrom は null になり、期間の Where を飛ばすだけなので
    // <b>監査ログ全件</b>が注意書きもバッジも無しで返る ——「その期間の証跡はこれで全部」と
    // 読めてしまうが、実際は「期間の指定が読めなかった」。規制対応の証跡画面で
    // この 2 つを区別できないのは誤読が重い。
    //
    // 引数ごとに掛けるのは、本体側が nameof を並べて渡す形だから ——
    // まとめて 1 件だけ見る検査にすると、2 つのうち 1 つを渡し忘れても緑のまま通る
    [Theory]
    [MemberData(nameof(AuditLogsUnreadableProneParameters))]
    public async Task AuditLogsIndex_ReportsAFilterValueThatCannotBeRead(string parameterName)
    {
        // 一覧に出る行を 1 件用意する(注意書きが「0 件だから出た」のではないことを示すため)
        await SeedSingleAuditLogAsync();

        // ModelState は ControllerContext と一緒に作られるので、先にコントローラを組み立てる
        var controller = NewAuditLogsController();
        // モデルバインドが「値は届いたが読めなかった」ときに積むエラーを再現する
        controller.ModelState.AddModelError(parameterName, "値の形式が正しくありません。");
        // 絞り込みの引数はすべて null(モデルバインドが失敗した後の状態)で一覧を引く
        var vm = await AuditLogsIndexAsync(controller);

        // 受け取ったのに採用しなかったことを画面へ伝えている
        Assert.True(vm.MalformedFilterIgnored,
            $"?{parameterName}=<読めない値> を受け取ったのに注意書きが出ない。"
            + $"MalformedFilterValueResolver へ {parameterName} を渡し忘れていないか、"
            + "あるいは [FromQuery(Name = ...)] で URL 上の名前を変えたのに本体が nameof の"
            + "引数名を渡したままになっていないか確認すること"
            + "(ModelState のキーになるのは URL 上の名前で、C# の引数名ではない)。");

        // 絞り込みは掛かっていない(全件が返る)。これは「読めない値では絞り込めない」以上
        // 避けられないので、注意書きはまさにこの状態を伝えるためにある
        Assert.Single(vm.Logs);

        // 許可リストの話ではないので、もう一方の旗は立てない。
        // <b>この対称の確認が要る</b> ——2 つの旗を OR で結んでしまう改修は、
        // 見出しの重複を見る検査(旗ごとに 1 つずつ切り出す)にも掛からず全件緑で通る。
        // 実際に立つと ?dateFrom=abc だけで注意書きが 2 つ並び、
        // 利用者にはどちらが自分の入力の話か分からない(二重描画の不具合に見える)
        Assert.False(vm.UnlistedFilterIgnored,
            "読めない値だけを送ったのに「選べる値ではない」の注意書きまで出ている。");
    }

    // 逆に、正しく読めた値では注意書きを出さないこと。
    // 「エントリの有無」で判定すると正しい値でも注意書きが出る(誤検知)ため、
    // 束縛に成功した状態(エラーの無いエントリ)を作って確かめる(/Incidents 側と同じ理由)
    [Theory]
    [MemberData(nameof(AuditLogsUnreadableProneParameters))]
    public async Task AuditLogsIndex_DoesNotReportAnything_WhenTheFilterValueWasReadable(string parameterName)
    {
        // 一覧に出る行を 1 件用意する
        await SeedSingleAuditLogAsync();

        // 「値が届いて、束縛にも成功した」状態を作る(エラーの無いエントリ)
        var controller = NewAuditLogsController();
        controller.ModelState.SetModelValue(parameterName, "1", "1");
        var vm = await AuditLogsIndexAsync(controller);

        // 読めなかった値は無いので注意書きは出ない
        Assert.False(vm.MalformedFilterIgnored,
            $"?{parameterName}=<読める値> で注意書きが出ている。"
            + "MalformedFilterValueResolver が「エントリの有無」ではなく"
            + "「エラーの有無」を見ているか確認すること。");
    }

    // 未指定(そもそも値が届いていない)でも注意書きを出さないこと。
    // 未指定で出すと、絞り込みを一度も使っていない利用者の画面に出っぱなしの警告が並び、
    // 本物の注意書きまで読み飛ばされる
    [Fact]
    public async Task AuditLogsIndex_ReportsNothing_WhenNoFilterValueWasSent()
    {
        // 一覧に出る行を 1 件用意する
        await SeedSingleAuditLogAsync();

        // 絞り込みを一切指定せずに一覧を引く
        var vm = await AuditLogsIndexAsync(NewAuditLogsController());

        // 受け取っていないものは「採用しなかった」ではない
        Assert.False(vm.MalformedFilterIgnored);
        // 絞り込みも掛かっていない
        Assert.Single(vm.Logs);
    }

    // --- /AuditLogs: 許可リストに無い絞り込み値(issue #220) --------------------------

    // 許可リストで閉じた絞り込み入力を、本体とは<b>独立な手がかり</b>から導く。
    //
    // <b>手がかりは画面の <select> の name。</b> この方式の不変条件は
    // 「絞り込みに使った値は必ず選択肢にある」(SearchFilter の表)なので、
    // 許可リストで閉じた絞り込みには<b>必ずドロップダウンがある</b>。
    // Razor は本体(コントローラ)とは別の宣言箇所なので、3 つ目の許可リスト絞り込みを
    // 足した人が解決処理を通し忘れると、<b>その name が導出には現れるのに
    // 下の対応表と ResolveListedValue のどちらにも無い</b>状態として現れる。
    //
    // 書き並べる形にしないのはこの repo が繰り返し避けている「写しを持つ」形だから
    // ——[InlineData] の手書きにすると、3 つ目を足した人が行を足し忘れた瞬間に
    // その入力だけが検出網から黙って外れる(実際、初版はその手書きだった)。
    //
    // <b>残っている境界</b>: 拾えるのは<b>ドロップダウンを持つ</b>許可リスト絞り込みだけ。
    // 選択肢を持たない入力欄(変更者・対象キー)は自由記述なので、そもそもこの方式の
    // 対象外(SearchFilter の「自由記述のテキスト絞り込みには 2 択が要らない」の段落)。
    // 逆に「閉じた語彙なのにドロップダウンを出さない」画面を作ると、この網からは外れる
    // ——その形を作るときは手がかりごと決め直すこと。
    public static TheoryData<string> AuditLogsListedFilterParameters()
    {
        // 画面のドロップダウンから、許可リストで閉じた絞り込みの名前を拾う
        var selectNames = AuditLogsFilterSelectNames();

        // 1 つも拾えなければ落とす(fail-closed)。ドロップダウンの書き方を変えると
        // 「対象ゼロ＝全件緑」で下の検査がまとめて死ぬため
        Assert.True(selectNames.Count > 0,
            "Views/AuditLogs/Index.cshtml に <select name=\"...\"> が 1 つも無い。"
            + "ドロップダウンの書き方を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、許可リストの絞り込みの検査が対象ゼロで全件緑になる)。");

        // 拾った名前と「許可リストの出どころ」の表が<b>双方向で</b>一致していること。
        //
        // <b>片方向(拾った名前 ⊆ 表)では足りない。</b> 導出が 1 つ取りこぼすと
        // その絞り込みは 3 つの検査から同時に、しかも黙って外れる ——痕跡はテスト件数の
        // 減少だけで、正当なリファクタと見分けが付かない(この repo が
        // LengthGovernedTypes_CoverEveryOwnedDbSet で同じ手当てをしている形)。
        // 表は人が手で書く別の宣言箇所なので、導出が狭まればここで食い違いとして現れる。
        // 絞り込みを本当に外すときは、表・画面・コントローラを同じ変更セットで直すことになる
        Assert.Equal(
            AuditLogsAllowLists.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList(),
            selectNames);

        // xUnit の [MemberData] が読める形へ詰めて返す。
        // 運ぶのは名前だけで、送る値(許可リストに載っている / 載っていない)は各検査が
        // AuditLogsAllowLists から引く ——ケースへ両方の値を載せると、
        // どちらか一方しか使わない検査に必ず捨てる引数ができる
        var data = new TheoryData<string>();
        foreach (var name in selectNames) data.Add(name);
        return data;
    }

    // 監査ログ画面の絞り込みドロップダウンの name を、Razor のソースから拾う。
    // Theory のケース作りと下の配線の照合が同じここを読む(§6 DRY)
    private static List<string> AuditLogsFilterSelectNames() =>
        // 属性の並び順に依存しない形で name を拾う。`<select name=... class=...>` の
        // 決め打ちにすると、<b>属性を並べ替えるだけ</b>でその絞り込みが導出から消え、
        // 3 つの検査が同時に対象を失う(実測で全件緑のまま通り、痕跡はテスト件数だけだった)
        Regex.Matches(ReadIndexViewSource("AuditLogs"), @"<select\b[^>]*?\bname\s*=\s*""(?<name>[^""]+)""")
            .Select(m => m.Groups["name"].Value)
            .Distinct(StringComparer.Ordinal)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

    // 絞り込みの名前 → その入力が取りうる値の許可リスト。
    //
    // <b>語彙は書き写さず、本体が使っているものをそのまま引く。</b>
    // エンティティ名は監査対象の一覧(唯一の真実の源)、操作種別はコントローラが持つ
    // private な配列をリフレクションで読む ——公開されていないからといって
    // "Added" 等を書き写すと、語彙を変えたときにこの検査だけが古い値で緑になり、
    // 落ちるのは無関係な検査(「載っている値なのに注意書きが出る」)になる。
    private static readonly IReadOnlyDictionary<string, string[]> AuditLogsAllowLists =
        new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            // どちらも「本体がその絞り込みに実際に使っている配列」を読む。
            // entityName を AuditedEntities から引き直さないのは、
            // AllowedEntityNames が将来そこから絞り込まれても(退役したエンティティを
            // ドロップダウンから隠す等)、この検査が古い語彙のまま
            // 「載っている値なのに注意書きが出る」という無関係な失敗を出さないため
            ["entityName"] = ReadPrivateAllowList(typeof(AuditLogsController), "AllowedEntityNames"),
            ["operation"] = ReadPrivateAllowList(typeof(AuditLogsController), "AllowedOperations"),
        };

    // コントローラが private static に持つ許可リストを読む。
    // 読めなければ落とす(fail-closed)——名前を変えたときに「空の許可リスト」で
    // 検査が通ってしまうのを防ぐ
    private static string[] ReadPrivateAllowList(Type controller, string fieldName)
    {
        // private static フィールドを名前で引く
        var field = controller.GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Static);
        // 見つからなければ、この検査が拠って立つ前提が崩れている
        Assert.True(field != null, $"{controller.Name}.{fieldName} が見つからない。"
            + "名前を変えたなら、この読み取りも同じ変更セットで直すこと。");
        // 中身を取り出す(型が変わっていれば IsType が落とす)
        var values = Assert.IsType<string[]>(field!.GetValue(null));
        // 空の許可リストでは「載っている値」の検査が作れない
        Assert.NotEmpty(values);
        return values;
    }

    // ドロップダウンを持つ絞り込みが、すべて解決処理を通っていること。
    //
    // 上の導出は「画面に <select> がある」ことしか見ないので、
    // <b>解決処理へ通し忘れた入力も導出には現れる</b>(そして「載っていない値でも
    // 注意書きが出ない」として behavioural な検査が落ちる)。ただしその失敗メッセージは
    // 症状しか言わないので、原因(配線漏れ)をコントローラのソースで名指しして落とす
    [Fact]
    public void AuditLogsListedFilters_AllGoThroughTheResolver()
    {
        // コントローラのソースを開く(ビルド出力にはコピーされないので絶対パスで開く)
        var controllerPath = Path.Combine(
            RepositoryPaths.WebProject, "Controllers", $"{nameof(AuditLogsController)}.cs");
        Assert.True(File.Exists(controllerPath), $"コントローラのソースが見つからない: {controllerPath}");
        // コメントを落としてから走査する(説明コメント中の呼び出し例を配線と取り違えない)
        var source = CSharpComment.Replace(File.ReadAllText(controllerPath), string.Empty);

        // ドロップダウンを持つ絞り込みのうち、ResolveListedValue へ渡されていないものを集める
        var unwired = AuditLogsFilterSelectNames()
            // 名前は Razor から拾った文字列なので、正規表現へ入れる前に必ずエスケープする
            // (`.` を含む name が任意の 1 文字と一致して、配線漏れを見逃すのを防ぐ)
            .Where(name => !Regex.IsMatch(source, $@"ResolveListedValue\s*\(\s*{Regex.Escape(name)}\b"))
            .ToList();

        // 1 つでもあれば落とす
        Assert.True(unwired.Count == 0,
            $"許可リストの絞り込みが解決処理を通っていない: {string.Join(", ", unwired)}。"
            + "ResolveListedValue へ通し、その Ignored を UnlistedFilterIgnored へ写すこと"
            + "(通さないと、許可リストに無い値で監査ログ全件が返るのに注意書きが出ない)。");
    }

    // どちらの許可リストにも載っていない値。実在する語彙と衝突しないことを
    // 下の門番が確かめるので、ここは 1 つの定数で足りる
    private const string UnlistedAuditValue = "Bogus";

    // 上の値が本当に「どの許可リストにも無い」ことを、許可リスト側から確かめる。
    //
    // 値を直書きしている以上、将来その綴りが実在の語彙になると
    // <b>検査が「採用される値」で採用されないことを求める</b>ことになり、
    // 落ちる理由が分からないテストになる(fail-closed で先に落とす)。
    // 比べる相手は本体が使っている許可リストそのもの ——ここで語彙を書き写すと、
    // 語彙を変えたときにこの門番だけが古い値で緑になる
    [Fact]
    public void UnlistedAuditValue_IsReallyOutsideEveryAllowList()
    {
        // 表に載っているすべての許可リストと突き合わせる
        foreach (var (name, allowed) in AuditLogsAllowLists)
            Assert.DoesNotContain(UnlistedAuditValue, allowed);

        // 表が空だと「見るべき対象ゼロ＝緑」になるので落とす(fail-closed)
        Assert.NotEmpty(AuditLogsAllowLists);
    }

    // 許可リストに無い絞り込み値でも、黙って落とさず注意書きを出すこと(issue #220)。
    //
    // 直っていなかった頃の再現手順: /AuditLogs?entityName=Bogus を開くと
    // 許可リスト照合で null に潰されて Where を飛ばすだけなので<b>監査ログ全件</b>が
    // 注意書きも無しで返る ——同じ画面が ?dateFrom=abc については注意書きを出すのに、
    // 綴りが許可リスト外だと黙る、という<b>同じ画面の中での一貫性の欠如</b>だった。
    // 利用者から見た結果は区別できない(どちらも絞り込んだつもりで全件が返る)
    [Theory]
    [MemberData(nameof(AuditLogsListedFilterParameters))]
    public async Task AuditLogsIndex_ReportsAFilterValueOutsideTheAllowList(string parameterName)
    {
        // 一覧に出る行を 1 件用意する(注意書きが「0 件だから出た」のではないことを示すため)
        await SeedSingleAuditLogAsync();

        // 許可リストに無い値だけを送って一覧を引く
        var vm = await AuditLogsIndexWithListedFilterAsync(parameterName, UnlistedAuditValue);

        // 受け取ったのに採用しなかったことを画面へ伝えている
        Assert.True(vm.UnlistedFilterIgnored,
            $"?{parameterName}={UnlistedAuditValue}(許可リストに無い値)を受け取ったのに注意書きが出ない。"
            + $"{parameterName} を ResolveListedValue へ通し、その Ignored を"
            + "UnlistedFilterIgnored へ写しているか確認すること。");

        // 絞り込みは掛かっていない(全件が返る)。注意書きはまさにこの状態を伝えるためにある
        Assert.Single(vm.Logs);

        // 採用しなかった値は画面へ戻さない ——戻すとドロップダウンは一致する <option> が
        // 無いので「(全て)」を指し、そのフォームを再送信した瞬間に絞り込みが解除される
        Assert.Null(AppliedListedFilterValue(vm, parameterName));

        // 読めなかったわけではないので、もう一方の旗は立てない
        // (2 つの文面が同時に出ると、利用者はどちらが自分の入力の話か分からない)
        Assert.False(vm.MalformedFilterIgnored,
            "許可リストに無いだけの値で「値として読み取れない」の注意書きまで出ている。");
    }

    // 逆に、許可リストに載っている値では注意書きを出さず、絞り込みも実際に効くこと。
    // これが無いと「常に true を返す」実装が上の Theory を素通りする
    [Theory]
    [MemberData(nameof(AuditLogsListedFilterParameters))]
    public async Task AuditLogsIndex_AppliesAFilterValueOnTheAllowList(string parameterName)
    {
        // 送る値は本体が使っている許可リストの先頭から取る(語彙をここへ書き写さない)
        var listed = AuditLogsAllowLists[parameterName][0];
        // 一致しない行に使う値も同じ許可リストの末尾から取る
        var other = AuditLogsAllowLists[parameterName][^1];
        // 語彙が 1 つに縮むと「一致しない行」を作れず、絞り込みが効いたかどうかを
        // 見分けられないまま緑になる(fail-closed で先に落とす)
        Assert.NotEqual(listed, other);

        // その値に一致する行と、一致しない行を 1 件ずつ用意する
        await SeedSingleAuditLogAsync();
        _db.AuditLogs.Add(new AuditLog
        {
            // 一致しない側。エンティティ名も操作種別も上の 1 件と別の値にする
            EntityName = AuditSaveChangesInterceptor.AuditedEntities[^1],
            EntityKey = "2",
            Operation = AuditLogsAllowLists["operation"][^1],
            ChangedBy = "tester",
            ChangedAt = TestFixtures.Today,
            ChangesJson = "{}"
        });
        await _db.SaveChangesAsync();

        // 許可リストに載っている値で絞り込む
        var vm = await AuditLogsIndexWithListedFilterAsync(parameterName, listed);

        // 採用しているので旗は立てない
        Assert.False(vm.UnlistedFilterIgnored,
            $"?{parameterName}={listed}(許可リストに載っている値)で注意書きが出ている。");
        // 絞り込みが実際に効いている(値が素通りしていないことの裏取り)
        Assert.Single(vm.Logs);
        // 採用した値は画面へ戻す(ドロップダウンの選択状態と一致させるため)
        Assert.Equal(listed, AppliedListedFilterValue(vm, parameterName));
    }

    // 未指定・空白のみは「採用しなかった」ではないこと。
    // ここを区別しないと、絞り込みを使っていない普通の一覧で警告が出続け、読まれなくなる
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AuditLogsIndex_ReportsNothing_WhenNoListedFilterWasSent(string? sent)
    {
        // 一覧に出る行を 1 件用意する
        await SeedSingleAuditLogAsync();

        // 空・空白のみ(＝絞り込み無し)で一覧を引く
        var vm = await AuditLogsIndexWithListedFilterAsync("entityName", sent);

        // 受け取っていないものは「採用しなかった」ではない
        Assert.False(vm.UnlistedFilterIgnored);
        // 絞り込みも掛かっていない
        Assert.Single(vm.Logs);
    }

    // 許可リストで閉じた絞り込みだけを指定して一覧を引く。
    // 引数の位置を各テストへ書き写すと、Index の署名が変わったときに直す場所が散る
    private async Task<AuditLogListViewModel> AuditLogsIndexWithListedFilterAsync(
        string parameterName, string? value)
    {
        // 知らない名前が来たら落とす(fail-closed)。3 つ目の絞り込みを足した人がここへ
        // 呼び出しを足し忘れると、実際には<b>何も送らない</b>リクエストになり、
        // 「注意書きが出ない」という<b>配線が正しくても出る失敗</b>になって、
        // 直すべき場所を指さないメッセージが残る
        Assert.True(parameterName is "entityName" or "operation",
            $"{parameterName} の送り方がこのテストに無い。絞り込みを足したなら、"
            + "ここへも送り方を足すこと(足さないと、値を送っていないのに"
            + "「注意書きが出ない」という誤った失敗になる)。");

        // 見張っている 2 つのうち、指定された側だけへ値を載せる
        var entityName = parameterName == "entityName" ? value : null;
        var operation = parameterName == "operation" ? value : null;
        // 他の絞り込みは指定せずに一覧を引く
        var result = await NewAuditLogsController()
            .Index(entityName, operation, null, null, null, null, 1) as ViewResult;
        // 一覧ビューのモデルとして取り出す(取れなければテストとして失敗させる)
        return Assert.IsType<AuditLogListViewModel>(result!.Model);
    }

    // 画面へ戻ってきた「採用した値」を、絞り込みの名前で引く。
    // 上の送り方と同じく、知らない名前は落とす(片方だけ足すと、送れているのに
    // 別の入力欄を見て「採用されていない」という誤った失敗になる)
    private static string? AppliedListedFilterValue(AuditLogListViewModel vm, string parameterName)
    {
        // 名前ごとに、その入力が画面へ戻す先を選ぶ
        if (parameterName == "entityName") return vm.EntityName;
        if (parameterName == "operation") return vm.Operation;
        // 知らない名前は fail-closed
        Assert.Fail($"{parameterName} が画面へ戻す先がこのテストに無い。"
            + "絞り込みを足したなら、ここへも戻り先を足すこと。");
        return null;
    }

    // --- /AuditLogs: 旗をビューが実際に読んでいるか --------------------------------

    // 監査ログ画面が立てる旗を、コントローラのソースから導く。
    //
    // この画面は ViewModel を持つが、導出は /PreventiveMeasures と同じ
    // 「… = ….Ignored」という代入の形を手がかりにする ——命名規約(*FilterIgnored)から
    // 導く形にすると、ViewModel を持つ画面ごとに同じ導出を写すことになる。
    // 代入の形なら 1 つの走査(IgnoredFilterFlagNamesIn)を画面名だけ変えて使い回せる。
    //
    // 1 つも拾えなければ落とす(fail-closed)。書き方を変えると
    // 「対象ゼロ＝全件緑」で下の Razor 走査が黙って死ぬため
    public static TheoryData<string> AuditLogsIgnoredFilterFlags()
    {
        // コントローラのソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var flags = AuditLogsIgnoredFilterFlagNames();

        // 0 件は「旗が無くなった」より「書き方が変わった」可能性が高い
        Assert.True(flags.Count > 0,
            $"{nameof(AuditLogsController)} に「… = ….Ignored」の代入が 1 つも見つからない。"
            + "書き方を変えたなら、この導出も同じ変更セットで直すこと"
            + "(直さないと、旗ごとに掛かるはずの Razor の検査が対象ゼロで全件緑になる)。");

        // xUnit の [MemberData] が読める形へ詰めて返す
        var data = new TheoryData<string>();
        foreach (var flag in flags) data.Add(flag);
        return data;
    }

    // 上の導出の本体。Theory のケース作りと見出しの照合が同じここを読む(§6 DRY)
    private static List<string> AuditLogsIgnoredFilterFlagNames() =>
        IgnoredFilterFlagNamesIn(nameof(AuditLogsController));

    // 旗を監査ログのビューが実際に読んでいることを確かめる。
    // コントローラ級の検査は ViewModel までしか見ないので、@if のブロックごと消しても
    // 全件緑のまま通る ——他の 2 画面とまったく同じ理由・同じやり方で塞ぐ
    [Theory]
    [MemberData(nameof(AuditLogsIgnoredFilterFlags))]
    public void AuditLogsIndexView_RendersTheIgnoredFilterNotice(string flag) =>
        // 走査そのものは 3 画面で共有する(AssertIgnoredFilterNoticeIsRendered が正本)
        AssertIgnoredFilterNoticeIsRendered("AuditLogs", ViewModelFlagAccessor, flag);

    // 旗ごとの見出しが互いに違うこと(理由は他の 2 画面と同じ)。
    // 現在この画面の旗は 1 つだが、2 つ目を足した人が既存の文面を写すとここで落ちる
    [Fact]
    public void AuditLogsIndexView_GivesEachIgnoredFilterNoticeItsOwnHeading() =>
        // 走査そのものは 3 画面で共有する(AssertIgnoredFilterNoticeHeadingsAreDistinct が正本)
        AssertIgnoredFilterNoticeHeadingsAreDistinct(
            "AuditLogs", ViewModelFlagAccessor, AuditLogsIgnoredFilterFlagNames());

    // 注意書きが案内する先(絞り込みパネル)が実際に開くこと、そして
    // 「フィルター適用中」の判定には混ざらないこと。
    //
    // 2 つの役割が逆であることと、片方へ寄せると必ずどちらかが壊れることは
    // IncidentsIndexView_OpensTheFilterPanelForAnIgnoredValue_ButDoesNotCallItActive の
    // 解説が正本。この画面でも同じ 2 つの判定(showFilterPanel / anyFilter)を持つので、
    // 同じ形で固定する
    [Theory]
    [MemberData(nameof(AuditLogsIgnoredFilterFlags))]
    public void AuditLogsIndexView_OpensTheFilterPanelForAnIgnoredValue_ButDoesNotCallItActive(string flag)
    {
        // 監査ログビューの Razor ソースを読む(コメントは落としてある)
        var source = ReadIndexViewSource("AuditLogs");

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
            + "混ぜると「適用していません」の注意書きの横に「フィルター適用中」バッジが出る。");

        // 判定の「定義」だけでなく「使われ方」も見る(理由は /Incidents 側の解説が正本)。
        // この画面で「絞り込みが効いている」と主張する表示は「フィルター適用中」バッジだけ
        var badge = Regex.Match(source, @"@if\s*\(\s*(?<flag>\w+)\s*\)\s*\{[^}]*フィルター適用中");
        Assert.True(badge.Success, "「フィルター適用中」バッジの出し分けが見つからない。");
        Assert.Equal("anyFilter", badge.Groups["flag"].Value);
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
    // 覆っている引数は下の表に書く。表を手で書くのはここだけで、<b>比べる相手は導出</b>
    // なので、表だけを増やしても導出に無ければ落ちる(逆も同じ)
    [Fact]
    public void EnumFilterScreens_CoverEveryActionThatAcceptsAnEnumFilter()
    {
        // アプリ全体から「enum の引数を受けるアクション」を拾う
        var actual = EnumActionParametersInTheApp();

        // 1 つも拾えないのは「enum の引数が無くなった」より「導出が壊れた」可能性が高い。
        // 「対象ゼロ＝緑」にせず落として、導出かアクションのどちらを直すか人に決めさせる
        Assert.True(actual.Count > 0,
            "enum の引数を受けるアクションが 1 つも見つからない。"
            + "導出を変えたなら、この照合も同じ変更セットで直すこと"
            + "(直さないと、定義に無い enum 値の検査が対象ゼロで全件緑になる)。");

        // 「どの引数を、どうやって守っているか」の表。
        //
        // <b>守り方は 2 種類あり、どちらでもよいが「どちらでもない」は許さない。</b>
        //   - Filter …… 絞り込みの入力。UnlistedEnumFilterResolver を通し、
        //     採用しなかったことを画面へ伝える(このクラスの behavioural な検査が確かめる)。
        //   - OwnGate … 保存を伴う POST。絞り込みと違って「採用しない」では済まず、
        //     未定義値を保存させないためアクション自身が Enum.IsDefined で弾く
        //     (通すとカンバンの振り分けもラベル表示も壊れる)。
        //
        // 2 種類を 1 つの表にまとめてあるのは、<b>取りこぼしを数え落とさない</b>ため。
        // 表を Filter だけにすると、非 null 許容の enum 引数は導出からも外さざるを得ず、
        // その瞬間に「守り方を何も決めていない enum 引数」が誰にも見えなくなる
        var guarded = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // 絞り込み: MeasuresIndex_DropsAnEnumFilterValueOutsideItsDefinition が確かめる
            [$"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.Index)}.status"] = "Filter",
            // 絞り込み: IncidentsIndex_DropsAnEnumFilterValueOutsideItsDefinition が確かめる
            [$"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.incidentType"] = "Filter",
            [$"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)}.severity"] = "Filter",
            // 保存: UpdateStatus 自身が Enum.IsDefined で弾く(未定義値を DB へ入れない)
            [$"{nameof(PreventiveMeasuresController)}.{nameof(PreventiveMeasuresController.UpdateStatus)}.status"] = "OwnGate",
        };

        // 2 つの宣言箇所が一致していること。ずれていれば、守り方を決めていない enum 引数が
        // 増えたか、逆に無くなった引数が表に残っている
        Assert.Equal(
            guarded.Keys.OrderBy(name => name, StringComparer.Ordinal).ToList(),
            actual);
    }

    // アプリ全体のコントローラから「enum のアクション引数」を
    // "<コントローラ名>.<アクション名>.<引数名>" の形で拾う。
    //
    // <b>null 許容かどうかで絞らない(レビュー指摘で修正)。</b> 以前ここは
    // Nullable&lt;TEnum&gt; だけを見て「Enum.IsDefined から外れうるのはそれだけ」と
    // 書いていたが、このリポジトリではその前提が既に成り立っていない ——
    // PreventiveMeasuresController.UpdateStatus は非 null 許容の MeasureStatus を受け、
    // まさに未定義値が届きうるので自前の Enum.IsDefined ゲートを持っている。
    // 絞ると、既定値付きの非 null 許容 enum 引数
    // (Index(MeasureStatus status = Planned, …) のような形。束縛に失敗すると
    //  黙って既定値へ落ちる)が検出網から丸ごと外れる。
    //
    // <b>コントローラの選び方は ControllerBase 基準</b>。Controller(ビューを返す基底)に
    // 絞ると [ApiController] : ControllerBase の JSON エンドポイントが見えない ——
    // SearchFilter の解説が「次に広げる画面」として名指ししている /Analytics が
    // まさに JSON 専用なので、その形は現実的に増えうる。
    //
    // <b>DeclaredOnly でも絞らない</b>。共通の基底コントローラへアクションを引き上げると、
    // 基底(abstract で除外)にも派生(そこでは宣言していない)にも現れず、
    // その画面がテスト件数すら変えずに消える —— CLAUDE.md が
    // LengthGovernedEntityTypes() について書いている「黙って狭まる」形そのもの。
    // 代わりに<b>宣言元が自分たちのアセンブリか</b>で切る(フレームワーク側の
    // public メソッドを拾わず、自前の基底から継いだアクションは拾う)
    private static List<string> EnumActionParametersInTheApp()
    {
        // 自分たちのアセンブリ(名前空間の切り直しで外れない)
        var ownAssembly = typeof(IncidentsController).Assembly;
        // そのアセンブリのコントローラをすべて見る
        return ownAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract)
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                // プロパティのゲッターなど、アクションでないものを除く
                .Where(m => !m.IsSpecialName)
                // 宣言元が自分たちのアセンブリのものだけ(Controller/object の public メソッドを拾わない)
                .Where(m => m.DeclaringType?.Assembly == ownAssembly)
                .SelectMany(m => m.GetParameters()
                    // null 許容かどうかを問わず、enum の引数をすべて拾う
                    .Where(p => (Nullable.GetUnderlyingType(p.ParameterType) ?? p.ParameterType).IsEnum)
                    .Select(p => $"{t.Name}.{m.Name}.{p.Name}")))
            // 同じアクションが複数の型から見えても 1 件に畳む(自前の基底から継いだ場合)
            .Distinct(StringComparer.Ordinal)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();
    }
}
