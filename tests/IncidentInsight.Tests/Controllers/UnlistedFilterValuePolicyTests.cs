// ClaimsPrincipal(実行ロール)をテストから指定するために使う
using System.Security.Claims;
// Razor ソースからコメントと foreach の対象を取り出すために使う
using System.Text.RegularExpressions;
using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
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
/// 「取り出した綴りを 1 件に決める並べ替え」と「その綴りが既に選択肢にあるときに
/// 補完を省く判定」の 2 つで、どちらも実測で「消しても全件緑」だった。
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

    // 採用しなかったことを画面へ伝える。黙って落とすと、絞り込んだつもりの利用者に
    // 全件が返り「絞り込み中」バッジも出ないので取り違えに気付けない。
    // 採用しない条件は「見えている範囲の実データに無い」＝データ側の状態に依存するので、
    // 打ち間違いだけでなく、正しくブックマークした URL でも該当行が消えれば当てはまる
    // (その 2 つを見分ける手段は無いので、どちらも同じように知らせる)
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
        // 対策 1 件と、その親インシデントを用意する
        var incident = await SeedIncidentAsync("ICU");
        // 選択肢の生成元となる担当部署を持つ対策を保存する
        _db.PreventiveMeasures.Add(new PreventiveMeasure
        {
            IncidentId = incident.Id,
            Description = "対策",
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "医療安全室",
            MeasureType = MeasureTypeKind.ShortTerm,
            Status = MeasureStatus.Planned,
            DueDate = TestFixtures.Today
        });
        await _db.SaveChangesAsync();

        // 実データのどの対策にも無い担当部署で絞り込む
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        await controller.Index(null, null, UnknownDepartment, null, null);

        // 自由記述なので「実在しない」と判定する手段が無く、適用値はそのまま補完される。
        // /Incidents と方式が違うのは値の集合の性質が違うため(SearchFilter の表を参照)
        var options = Assert.IsType<List<string>>(controller.ViewBag.ResponsibleDepartmentOptions);
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
        // 対策 1 件と、その親インシデントを用意する
        var incident = await SeedIncidentAsync("ICU");
        // 選択肢の生成元となる担当部署を持つ対策を保存する
        _db.PreventiveMeasures.Add(new PreventiveMeasure
        {
            IncidentId = incident.Id,
            Description = "対策",
            ResponsiblePerson = "担当者",
            ResponsibleDepartment = "医療安全室",
            MeasureType = MeasureTypeKind.ShortTerm,
            Status = MeasureStatus.Planned,
            DueDate = TestFixtures.Today
        });
        await _db.SaveChangesAsync();

        // 実データから選択肢に載る値で絞り込む
        var controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            new SystemClock(),
            NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        await controller.Index(null, null, "医療安全室", null, null);

        // 選択肢にちょうど 1 回だけ現れる。
        // ViewBag は dynamic なので、いったん静的な型の変数へ受けてから LINQ を使う
        // (dynamic のままだとラムダを渡す呼び出しがコンパイルできない)
        object rawOptions = controller.ViewBag.ResponsibleDepartmentOptions;
        var options = Assert.IsType<List<string>>(rawOptions);
        Assert.Equal(1, options.Count(d => d == "医療安全室"));
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
        var loopCount = Regex.Matches(selectBlock, @"\bforeach\b").Count;
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
            var selectedExpression = ExtractAttributeValue(body, "selected");
            Assert.True(selectedExpression != null,
                $"{viewFolder}/Index.cshtml のループが作る <option> に selected 属性が無い。"
                + "現在値を示さないと select は先頭の「(全て)」を指し、"
                + "再送信で絞り込みが無言で解除される(issue #192)。");
            Assert.True(ContainsIdentifier(selectedExpression!, appliedValue),
                $"{viewFolder}/Index.cshtml の selected は {appliedValue} と比べること。"
                + $"実際の式: {selectedExpression}");
        });
    }

    // Razor のコメント(@* ... *@)。改行をまたぐので Singleline を付ける。
    // 入れ子は Razor 側が許さないので最短一致で足りる
    private static readonly Regex RazorComment =
        new(@"@\*.*?\*@", RegexOptions.Singleline | RegexOptions.Compiled);

    // 「採用しなかったことを画面へ伝える」旗を、ビューが実際に読んでいることを確かめる。
    // コントローラ級のテストは ViewModel までしか見ないので、@if のブロックごと消しても
    // 全件緑のまま通る(実測)。そうなると DepartmentFilterIgnored は誰も読まない
    // 書き込み専用のプロパティになり、利用者は黙って全件を見せられる ——
    // SearchFilter の表が「してはいけない」と書いている状態そのもの。
    // 選択肢の配線を Razor のソースで見張っているのと同じ理由・同じやり方で塞ぐ
    [Fact]
    public void IncidentsIndexView_RendersTheIgnoredFilterNotice()
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
        // 出し分けの構文そのものを探して、注意書きが実際に描画されることを確かめる
        var flag = nameof(IncidentListViewModel.DepartmentFilterIgnored);
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

    /// <summary>
    /// <paramref name="text"/> が <paramref name="identifier"/> を<b>識別子として</b>含むか。
    /// </summary>
    /// <remarks>
    /// 素の部分文字列検査だと、期待する名前が別の名前の<b>前置詞</b>のときに素通りする
    /// (<c>Model.Department</c> は <c>Model.DepartmentOptions</c> に含まれる)。
    /// 直後が識別子を構成する文字(英数字・アンダースコア)なら別の名前とみなす。
    /// 直前は見ない —— <c>Model.Department</c> のように区切り文字込みで指定するため。
    /// </remarks>
    private static bool ContainsIdentifier(string text, string identifier)
    {
        // 出現位置を順に調べる
        for (var i = text.IndexOf(identifier, StringComparison.Ordinal); i >= 0;
             i = text.IndexOf(identifier, i + 1, StringComparison.Ordinal))
        {
            // 一致部分の直後の位置
            var after = i + identifier.Length;
            // 末尾で終わっているか、直後が識別子の文字でなければ「その名前」だと判断する
            if (after >= text.Length || (!char.IsLetterOrDigit(text[after]) && text[after] != '_'))
                return true;
        }
        // どの出現も別の名前の一部だった
        return false;
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
    // どちらの差し戻しも実測で全件緑のまま通ったので、ソースの形で固定する
    [Fact]
    public void IncidentsIndexView_OpensTheFilterPanelForAnIgnoredValue_ButDoesNotCallItActive()
    {
        // 一覧ビューの Razor ソースを読む(Razor のコメントは落としてから見る)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = RazorComment.Replace(File.ReadAllText(viewPath), string.Empty);
        var flag = nameof(IncidentListViewModel.DepartmentFilterIgnored);

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
        // anyFilter を読むのはこの 2 箇所だけなので、両方が anyFilter を見ていることを確かめる
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
            // 次の foreach の位置を探す
            var keyword = block.IndexOf("foreach", cursor, StringComparison.Ordinal);
            if (keyword < 0) break;
            // 見つからない形でも無限ループにしないよう、次はこの先から探す
            cursor = keyword + "foreach".Length;
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
                        // 次のループはこの本体の外から探す
                        cursor = i;
                        break;
                    }
                }
            }
        }

        // 見つかったすべての本体を返す
        return bodies;
    }

    /// <summary>
    /// HTML 属性 <c>name="&lt;ここ&gt;"</c> の「ここ」を取り出す。見つからなければ <c>null</c>。
    /// </summary>
    /// <remarks>
    /// ブロック全体に対する部分文字列検査の代わりに使う。期待する名前が別の名前の
    /// <b>前置詞</b>になっている場合(<c>Model.Department</c> と <c>Model.DepartmentOptions</c>)、
    /// 「どこかに出てくるか」では別の行が条件を満たして検査が空振りするため。
    /// </remarks>
    private static string? ExtractAttributeValue(string block, string attributeName)
    {
        // 属性名と等号・引用符までを目印に開始位置を探す
        var marker = $"{attributeName}=\"";
        var start = -1;
        for (var i = block.IndexOf(marker, StringComparison.Ordinal); i >= 0;
             i = block.IndexOf(marker, i + 1, StringComparison.Ordinal))
        {
            // 直前が属性名の区切り(空白かタグの開始)でなければ別の属性の一部。
            // これを見ないと selected="..." が aria-selected="..." や data-selected="..." に
            // 引っかかり、本物の selected が消えていても検査が通ってしまう
            // (§7 で aria-selected を足すのは十分ありうる)
            var before = i == 0 ? '<' : block[i - 1];
            if (char.IsWhiteSpace(before) || before == '<')
            {
                start = i;
                break;
            }
        }
        // 見つからなければ属性が無い
        if (start < 0) return null;
        // 値の開始位置(引用符の次)
        var valueStart = start + marker.Length;
        // 閉じ引用符を探す(Razor の式に生の " は現れない)
        var valueEnd = block.IndexOf('"', valueStart);
        // 閉じ引用符が無ければ解析できない
        if (valueEnd < 0) return null;
        // 引用符の中身を返す
        return block[valueStart..valueEnd];
    }

    /// <summary>
    /// ブロック内の <b>すべての</b> <c>foreach (var d in &lt;ここ&gt;)</c> について
    /// 「ここ」(＝回している対象の式)を取り出す。
    /// </summary>
    /// <remarks>
    /// 括弧を数えて閉じ位置を探すのは、対象の式が括弧を含みうるため。
    /// 実際 <c>/PreventiveMeasures</c> は <c>(List&lt;string&gt;)ViewBag.Xxx</c> とキャストしており、
    /// 「最初の <c>)</c> まで」を取る正規表現ではキャストの閉じ括弧で切れて
    /// <c>"(List&lt;string&gt;"</c> だけが取れてしまう(実測で落ちた)。
    /// 検出網が対象を取り違えると、判定はいつも同じ答えになり黙って無力化される。
    /// </remarks>
    private static List<string> ExtractForeachSources(string block)
    {
        // 見つかった対象の式をためる
        var sources = new List<string>();
        // 走査の開始位置
        var cursor = 0;

        // ブロック内の foreach をすべて拾う。1 つ目だけを見ると、あとから
        // <optgroup> のグルーピング等で 2 つ目のループが足されたときに見えなくなる
        // (この repo は原因分類のドロップダウンで実際に入れ子の構造を使っている)
        while (true)
        {
            // 次の foreach キーワードを探す
            var keyword = block.IndexOf("foreach", cursor, StringComparison.Ordinal);
            // 無ければ走査を終える
            if (keyword < 0) break;
            // 次の周回はこのキーワードの先から探す(見つからない形でも無限ループにしない)
            cursor = keyword + "foreach".Length;

            // その直後の開き括弧を探す
            var open = block.IndexOf('(', keyword);
            if (open < 0) continue;

            // 入れ子を数えながら対応する閉じ括弧を探す
            var depth = 0;
            var close = -1;
            for (var i = open; i < block.Length; i++)
            {
                // 開き括弧で 1 段深くなる
                if (block[i] == '(') depth++;
                // 閉じ括弧で 1 段浅くなる
                else if (block[i] == ')')
                {
                    depth--;
                    // 深さが 0 に戻った位置が対応する閉じ括弧
                    if (depth == 0) { close = i; break; }
                }
            }
            // 閉じ括弧が見つからなければこの 1 件は解析できない
            if (close < 0) continue;

            // 括弧の中身から「 in 」の後ろを取り出す(前後の空白は落とす)
            var inside = block[(open + 1)..close];
            var inKeyword = inside.IndexOf(" in ", StringComparison.Ordinal);
            if (inKeyword < 0) continue;
            sources.Add(inside[(inKeyword + 4)..].Trim());
        }

        // 見つかったすべての対象を返す
        return sources;
    }
}
