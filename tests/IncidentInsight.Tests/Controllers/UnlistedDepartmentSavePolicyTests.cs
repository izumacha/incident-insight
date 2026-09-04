// ClaimsPrincipal(実行ロール)をテストから指定するために使う
using System.Security.Claims;
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
/// 「保存される発生部署をドロップダウンが表せない」ときの扱いを固定する(issue #196)。
///
/// <para><b>なぜ絞り込み側(<c>UnlistedFilterValuePolicyTests</c>)と分けるのか。</b>
/// 症状の入り口は同じ(<c>Incident.Departments</c> から部署名を外すと、過去の行は
/// リストに無い値を持ち続け、一致する <c>&lt;option&gt;</c> が無くなる)だが、
/// <b>結果と規則が違う</b>。絞り込みは「どの行を見るか」なので、失うのは絞り込み状態だけ。
/// 保存側は「どの値を書き込んでよいか」なので、失敗すると<b>保存された業務データが
/// 書き換わる</b> —— 別項目だけ直して保存しようとすると <c>[Required]</c> で弾かれ、
/// 通すには許可リストのどれかを選ぶしかない。
/// <c>SearchFilter</c> の表が「この表を保存側へ広げないこと」と明記しているとおり
/// 規則も別なので、それを固定するテストも分けてある。</para>
///
/// <para><b>規則の正本は <c>IncidentsController.ResolveDepartmentSaveSelection</c> の解説。</b>
/// 要点は 2 つ: (1) <b>現在保存されている値に限り</b>選択肢へ足して保存も通す、
/// (2) <b>新規登録では例外を作らない</b>(許可リストから外した部署名を新しい行へ付けられない)。
/// ただし (2) が覆うのは<b>この規則が作る例外だけ</b>で、Staff のクレーム経由で
/// 許可リスト外の部署名が新しい行へ入るのは意図的に残してある(理由は
/// <c>CreatePost_StaffWithUnlistedClaim_SavesWithThatDepartment</c> のコメント)。</para>
///
/// <para><b>ここで守る不変条件は「表示側と適用側が同じ判定を通る」こと。</b>
/// 選択肢の方が広ければ、利用者が画面で選べる値で保存が弾かれる(何を選べば通るのか
/// 画面からは分からない)。許可の方が広ければ、画面に出ない値をフォーム改ざんで保存できる。
/// <c>EditForm_EveryOfferedOption_IsAcceptedOnSave</c> がこの一致そのものを固定する。</para>
///
/// <para><b>Staff はこの規則の対象外で、編集と登録で意味が違う。</b>
/// <c>EnforceKnownDepartment</c> は Staff を検証しないが、
/// <b>編集</b>では書き換わらない —— <c>SameDepartmentHandler</c> が「インシデントの発生部署 ==
/// 本人のクレーム」の行しか編集させないため、<c>EnforceOwnDepartmentForStaff</c> による
/// 上書きは同じ値の代入にしかならない(<c>EditPost_StaffOwningAnUnlistedDepartment_KeepsIt</c>)。
/// 一方<b>登録</b>では、クレームが許可リストから外れている Staff の新しい行にその部署名が
/// 入る —— これは塞ぐとロックアウトになるため<b>意図的に残してある</b>
/// (<c>CreatePost_StaffWithUnlistedClaim_SavesWithThatDepartment</c>)。
/// どちらも暗黙の前提なので固定する ——前者は認可側の判定基準が変わると黙って崩れ、
/// 後者は暗黙のままだと「塞ぎ忘れ」と読まれて塞がれてしまう。</para>
///
/// <para><b>失敗したときは</b>、実装だけを直すのではなく
/// <c>ResolveDepartmentSaveSelection</c> の解説と <c>SearchFilter</c> の該当段落も
/// 同じ変更セットで見直すこと(片方だけ直すと、次はもう食い違いに気付けない)。</para>
/// </summary>
public class UnlistedDepartmentSavePolicyTests : IDisposable
{
    // 1 テストにつき 1 インスタンスの InMemory DB(Mock より InMemory を優先する方針)
    private readonly ApplicationDbContext _db;

    // 現在の許可リスト(Incident.Departments)には無いが、過去の行が持ちうる部署名。
    // CLAUDE.md が「部署の値追加は static 配列を更新(マイグレーション不要)」と明記しているとおり
    // この配列は可変なので、運用で部署名を入れ替えるとこういう値が実データに残る
    private const string RetiredDepartment = "旧・第 3 病棟";

    // 許可リストにも実データにも無い部署名(フォーム改ざん・打ち間違いの想定)
    private const string UnknownDepartment = "存在しない部署";

    // 上と同じ「許可リストから外された部署名」だが、こちらは大文字小文字の違いを作れるよう
    // ラテン文字を含む。序数比較(完全一致)であることを確かめる検査で使う
    private const string RetiredDepartmentWithLetters = "旧 ICU";

    // その大文字小文字だけを変えた綴り。序数比較なら別の値として扱われる
    private const string RetiredDepartmentCaseVariant = "旧 icu";

    public UnlistedDepartmentSavePolicyTests()
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

    // 前提が崩れたら落とす: この一連の検査は「許可リストに無い部署名」で成り立っている。
    // 誰かが RetiredDepartment / UnknownDepartment と同じ名前を Incident.Departments へ
    // 足すと、検査は同じ緑を返しながら何も確かめなくなる(fail-open)
    private static void RequireOutsideAllowList(string department) =>
        Assert.False(Incident.Departments.Contains(department),
            $"このテストは「{department}」が許可リストに無いことを前提にしている。"
            + "Incident.Departments へ足したなら、テスト側の定数も同じ変更セットで別の値へ変えること。");

    // 指定した発生部署のインシデントを 1 件保存して返す
    private async Task<Incident> SeedIncidentAsync(string department)
    {
        // 編集に必要な最小限のインシデントを作る
        var incident = new Incident
        {
            Department = department,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者",
            // 実行日時に依存させないため固定日を使う
            OccurredAt = TestFixtures.Today,
            // 発生日時より後になるよう報告日時を置く(Edit の整合検証を通すため)
            ReportedAt = TestFixtures.Today
        };
        // 追加して保存する
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 保存した行を追跡から外す。編集アクションは FindAsync で読み直すので、
        // 追跡済みのインスタンスが残っていると「保存されたか」を確かめる読み直しが
        // メモリ上の同じインスタンスを返してしまい、検査が空振りする
        _db.ChangeTracker.Clear();
        // 呼び出し側が Id を使えるよう返す
        return incident;
    }

    // /Incidents を扱うコントローラを用意する。
    // 実行ロールは呼び出し側が渡す(既定を置いて上書きさせると、AttachUser が
    // ControllerContext を作り直すため「2 回目が勝つ」暗黙の順序に検査が乗ってしまう)
    private IncidentsController NewIncidentsController(ClaimsPrincipal? user = null)
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(new SystemClock(), NullLogger<RecurrenceService>.Instance),
            new SystemClock(),
            NullLogger<IncidentsController>.Instance);
        // 指定が無ければ全部署を扱える Admin(部署スコープの影響を切り離すため)
        UserContextHelper.AttachUser(controller, user ?? UserContextHelper.Admin());
        // 組み立てたコントローラを返す
        return controller;
    }

    // 編集画面(GET)を開いて ViewModel を取り出す
    private async Task<IncidentCreateEditViewModel> EditFormAsync(int id, ClaimsPrincipal? user = null)
    {
        // 編集画面を開く
        var result = await NewIncidentsController(user).Edit(id) as ViewResult;
        // ビューが返っていることを確かめる(403/404 ならここで落ちる)
        Assert.NotNull(result);
        // 型を確かめたうえで ViewModel を返す
        return Assert.IsType<IncidentCreateEditViewModel>(result!.Model);
    }

    // 編集フォームの送信内容を組み立てる。
    // 選択肢は POST ボディに含まれないので、本番のモデルバインドと同じく空から始める
    // ——コントローラが再描画時に詰め直すかどうかを、ここで空にしておくことで観測できる
    private static IncidentCreateEditViewModel EditSubmission(
        Incident incident, string department, string description = "説明") => new()
        {
            DepartmentOptions = new List<string>(),
            Id = incident.Id,
            ConcurrencyToken = incident.ConcurrencyToken,
            OccurredAt = incident.OccurredAt,
            Department = department,
            IncidentType = incident.IncidentType,
            Severity = incident.Severity,
            Description = description,
            ReporterName = incident.ReporterName
        };

    // 保存されている発生部署を指定の値へ戻す(周回ごとに前提を揃えるため)。
    // コントローラを通さず直接書き戻すのは、ここが「検査の前提を作る」処理であって
    // 検査対象ではないから ——コントローラ経由にすると、通したい値が許可リスト外のときに
    // まさに検査したい規則へ依存してしまう
    private async Task ResetStoredDepartmentAsync(int id, string department)
    {
        // 追跡中の状態を捨ててから読み直す
        _db.ChangeTracker.Clear();
        var incident = await _db.Incidents.FirstAsync(i => i.Id == id);
        // 部署だけを元の値へ戻す
        incident.Department = department;
        await _db.SaveChangesAsync();
        // 次の読み直しがメモリ上の同じインスタンスを返さないよう追跡から外す
        _db.ChangeTracker.Clear();
    }

    // DB から発生部署を読み直す(コントローラが書き換えたかどうかを確かめる)
    private async Task<string> StoredDepartmentAsync(int id)
    {
        // 追跡中のインスタンスではなく DB の現在値を読む
        _db.ChangeTracker.Clear();
        var stored = await _db.Incidents.AsNoTracking().FirstAsync(i => i.Id == id);
        return stored.Department;
    }

    // --- 表示側: どの値を選択肢に並べるか -------------------------------------

    // 許可リストから外された部署名を持つインシデントの編集画面には、その値が選択肢に出る。
    // 出ないと asp-for="Department" に一致する <option> が無く、ブラウザは
    // 「-- 選択してください --」を選ぶ ——issue #196 の再現手順の起点
    [Fact]
    public async Task EditGet_StoredDepartmentOutsideAllowList_IsOfferedAsAnOption()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);

        var vm = await EditFormAsync(incident.Id);

        // 現在値が選択肢にある(＝ブラウザが正しく選択状態にできる)
        Assert.Contains(RetiredDepartment, vm.DepartmentOptions);
        // 位置は先頭。末尾へ足すと、選択肢が多い画面ではスクロールしないと現在値が見えず
        // 「選ばれていない」と誤解した利用者が別の値を選んで書き換えてしまう
        // (位置の規則は共有ヘルパ EnsureAppliedValueIsSelectable が持つ)
        Assert.Equal(RetiredDepartment, vm.DepartmentOptions[0]);
        // 許可リストは丸ごと残っている(補完のために取り落としていない)
        Assert.Equal(Incident.Departments, vm.DepartmentOptions.Skip(1));
    }

    // 許可リストにある部署名なら、選択肢は許可リストちょうど(余分な補完をしない)
    [Fact]
    public async Task EditGet_StoredDepartmentInAllowList_OffersExactlyTheAllowList()
    {
        var listed = Incident.Departments[0];
        var incident = await SeedIncidentAsync(listed);

        var vm = await EditFormAsync(incident.Id);

        // 同じ値が二重に並ばないこと(共有ヘルパの「既にあれば足さない」判定が効いている)
        Assert.Equal(Incident.Departments, vm.DepartmentOptions);
    }

    // 新規登録の選択肢は常に許可リストちょうど。
    // 「編集で補完する」規則が新規登録へ漏れると、許可リストから外した部署名を
    // 新しいインシデントへ付けられるようになり、外した意図そのものが失われる
    [Fact]
    public async Task CreateGet_OffersExactlyTheAllowList()
    {
        RequireOutsideAllowList(RetiredDepartment);
        // 許可リスト外の部署名を持つ行が実データにあっても、新規登録の選択肢は変わらない
        await SeedIncidentAsync(RetiredDepartment);

        var result = await NewIncidentsController().Create() as ViewResult;
        Assert.NotNull(result);
        var vm = Assert.IsType<IncidentCreateEditViewModel>(result!.Model);

        Assert.Equal(Incident.Departments, vm.DepartmentOptions);
    }

    // 登録画面(GET)を開いて ViewModel を取り出す。実行ロールは呼び出し側が渡す
    // ——この一連の検査は「誰が開いたか」で選択肢が変わることを見るため
    private async Task<IncidentCreateEditViewModel> CreateFormAsync(ClaimsPrincipal? user = null)
    {
        // 登録画面を開く
        var result = await NewIncidentsController(user).Create() as ViewResult;
        // ビューが返っていることを確かめる
        Assert.NotNull(result);
        // 型を確かめたうえで ViewModel を返す
        return Assert.IsType<IncidentCreateEditViewModel>(result!.Model);
    }

    // 登録フォームの送信内容を組み立てる。
    // 選択肢は POST ボディに含まれないので、編集側と同じく空から始める
    // ——コントローラが再描画時に詰め直すかどうかを、ここで空にしておくことで観測できる
    private static IncidentCreateEditViewModel CreateSubmission(
        string department, bool withMeasure = true) => new()
        {
            DepartmentOptions = new List<string>(),
            OccurredAt = TestFixtures.Today,
            Department = department,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者",
            // 業務ルール(HasAtLeastOneValidMeasure)を満たす対策 1 件。
            // withMeasure: false にすると必ず検証に落ちるので、再描画の検査に使う
            Measures = withMeasure
                ? new List<MeasureFormViewModel>
                {
                    // 保存まで到達するので、保存に必要な項目をすべて埋める
                    // (テストではモデルバインドが走らず [Required] が効かないため、
                    //  埋めないと Create の保存処理が null 参照で落ちる)
                    new()
                    {
                        Description = "対策",
                        MeasureType = MeasureTypeKind.ShortTerm,
                        ResponsiblePerson = "担当者",
                        ResponsibleDepartment = Incident.Departments[0],
                        DueDate = TestFixtures.Today.AddDays(30),
                        Priority = 2
                    }
                }
                : new List<MeasureFormViewModel>()
        };

    // 所属部署クレームが許可リストから外れている Staff の登録画面には、その値が選択肢に出る。
    //
    // issue #204 課題 1 の再現手順そのもの。出ないと asp-for="Department" に一致する
    // <option> が無く「-- 選択してください --」が選ばれるのに、保存されるのは
    // EnforceOwnDepartmentForStaff が上書きするクレームの値になる ——
    // 画面に一度も表示されていない部署でインシデントが保存される
    [Fact]
    public async Task CreateGet_StaffWithUnlistedClaim_OffersItsOwnDepartment()
    {
        RequireOutsideAllowList(RetiredDepartment);
        // 所属部署クレームが許可リスト外の値になっている Staff(部署名変更直後の実在の状態)
        var vm = await CreateFormAsync(UserContextHelper.Staff(RetiredDepartment));

        // クレームの値が選択肢にある(＝実際に保存される値が画面に出ている)
        Assert.Contains(RetiredDepartment, vm.DepartmentOptions);
        // 位置は先頭。規則は共有ヘルパ EnsureAppliedValueIsSelectable が持つ(編集側と同じ)
        Assert.Equal(RetiredDepartment, vm.DepartmentOptions[0]);
        // 許可リストは丸ごと残っている(補完のために取り落としていない)
        Assert.Equal(Incident.Departments, vm.DepartmentOptions.Skip(1));
    }

    // クレームが許可リストに載っている Staff では、選択肢は許可リストちょうど。
    // 二重に並ぶと、同じ部署がドロップダウンに 2 回出る
    [Fact]
    public async Task CreateGet_StaffWithListedClaim_OffersExactlyTheAllowList()
    {
        // 許可リストに載っている部署を所属とする Staff(通常の状態)
        var vm = await CreateFormAsync(UserContextHelper.Staff(Incident.Departments[0]));

        // 共有ヘルパの「既にあれば足さない」判定が効いている
        Assert.Equal(Incident.Departments, vm.DepartmentOptions);
    }

    // 登録画面が並べた選択肢に、実際に保存される発生部署が含まれている。
    //
    // これが課題 1 の完了条件そのもの。上の 2 つは「クレームが選択肢に出るか」を見るが、
    // <b>保存される値と突き合わせていない</b>ため、上書きの規則
    // (EnforceOwnDepartmentForStaff)が変わると黙って食い違いが戻る。
    // 選択肢を固定値で書き並べず<b>画面が実際に返したもの</b>と<b>DB に入った値</b>を
    // 突き合わせるのが要点 ——どちらの規則が変わってもここで落ちる
    [Fact]
    public async Task CreateForm_OffersTheDepartmentThatIsActuallySaved()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var staff = UserContextHelper.Staff(RetiredDepartment);

        // 登録画面が実際に並べる選択肢を取り出す
        var offered = (await CreateFormAsync(staff)).DepartmentOptions;
        // 空だと「見るべき対象ゼロ＝緑」になるので fail-closed で落とす
        Assert.NotEmpty(offered);

        // 画面の先頭に出ている値をそのまま選んで登録する(利用者が普通に行う操作)
        var result = await NewIncidentsController(staff).Create(CreateSubmission(offered[0]));
        Assert.IsType<RedirectToActionResult>(result);

        // 実際に保存された発生部署が、画面に出ていた選択肢の中にある
        var saved = await _db.Incidents.AsNoTracking().SingleAsync();
        Assert.Contains(saved.Department, offered);
    }

    // 選択肢へ足すだけでなく、Staff の所属部署を<b>初期選択</b>にする。
    //
    // 足すだけだと「-- 選択してください --」が選ばれたままになり、利用者が別の部署を
    // 選んで送信しても EnforceOwnDepartmentForStaff がクレームで上書きするので、
    // 「画面が実際に保存される値を表していない」という課題 1 の症状が選択状態の側に残る
    [Fact]
    public async Task CreateGet_StaffWithUnlistedClaim_PreselectsItsOwnDepartment()
    {
        RequireOutsideAllowList(RetiredDepartment);

        var vm = await CreateFormAsync(UserContextHelper.Staff(RetiredDepartment));

        // asp-for="Department" が一致する <option> を選択状態にする値
        Assert.Equal(RetiredDepartment, vm.Department);
    }

    // 画面が選択状態として示す値と、実際に保存される値が一致する。
    //
    // 上の 2 つ(選択肢に出る / 初期選択になる)は画面の中だけを見るので、
    // 上書きの規則(EnforceOwnDepartmentForStaff)が変わると黙って食い違いが戻る。
    // 初期選択の値をそのまま送り返して DB を読み直すことで、両側を突き合わせる
    [Fact]
    public async Task CreateForm_PreselectedDepartmentIsTheOneThatGetsSaved()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var staff = UserContextHelper.Staff(RetiredDepartment);

        // 画面が初期選択として示す部署を取り出す
        var preselected = (await CreateFormAsync(staff)).Department;
        // 空だと「見るべき対象ゼロ＝緑」になるので fail-closed で落とす
        Assert.False(string.IsNullOrWhiteSpace(preselected),
            "登録画面が発生部署を初期選択していない(何も選ばれていない状態から始まっている)。");

        // 利用者が何も触らずに送信した場合に相当する
        var result = await NewIncidentsController(staff).Create(CreateSubmission(preselected));
        Assert.IsType<RedirectToActionResult>(result);

        // 保存された値が、画面が示していた値と同じ
        var saved = await _db.Incidents.AsNoTracking().SingleAsync();
        Assert.Equal(preselected, saved.Department);
    }

    // Admin / RiskManager は所属で縛られないので、従来どおり未選択で始まる。
    // ここを固定しないと、初期選択を入れる変更が全ロールへ広がったときに
    // 「管理者が意図せず特定の部署で登録してしまう」壊れ方に気付けない
    [Fact]
    public async Task CreateGet_FullAccessRole_LeavesDepartmentUnselected()
    {
        var vm = await CreateFormAsync(UserContextHelper.Admin());

        // 初期値は空のまま(ビューは「-- 選択してください --」を選択状態にする)
        Assert.True(string.IsNullOrEmpty(vm.Department),
            $"Admin の登録画面で発生部署が初期選択されている: 「{vm.Department}」");
    }

    // 検証エラーで登録画面を再描画するときも、Staff の所属部署を選択肢へ戻す。
    // 戻さないと再描画された画面から現在値が消え、初回表示と同じ食い違いが続く
    // (選択肢は POST ボディに含まれないので「バインドされた値が返る」ことに頼れない)
    [Fact]
    public async Task CreatePost_Invalid_RedisplaysStaffOwnDepartment()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var controller = NewIncidentsController(UserContextHelper.Staff(RetiredDepartment));

        // 対策が 1 件も無いので業務ルール(HasAtLeastOneValidMeasure)で必ず再描画になる
        var result = await controller.Create(
            CreateSubmission(Incident.Departments[0], withMeasure: false));

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<IncidentCreateEditViewModel>(view.Model);
        // 送信時は空だった選択肢が詰め直され、クレームの値も入っている
        Assert.Contains(RetiredDepartment, vm.DepartmentOptions);
        Assert.Equal(RetiredDepartment, vm.DepartmentOptions[0]);
    }

    // --- 適用側: どの値の保存を通すか -----------------------------------------

    // issue #196 の再現手順そのもの: 許可リスト外の部署名を持つインシデントの
    // 「別項目だけ」を直して保存できる。しかも発生部署は書き換わらない
    [Fact]
    public async Task EditPost_KeepingStoredDepartmentOutsideAllowList_Saves()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);
        var controller = NewIncidentsController();

        // 編集画面が返す現在値(=補完された部署名)をそのまま送り返し、説明だけを直す
        var result = await controller.Edit(
            incident.Id, EditSubmission(incident, RetiredDepartment, description: "説明を直した"));

        // 保存されて詳細画面へリダイレクトする(検証エラーで再描画されない)
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Details), redirect.ActionName);
        // 発生部署は元のまま(黙って書き換わらない)
        Assert.Equal(RetiredDepartment, await StoredDepartmentAsync(incident.Id));
    }

    // 許可リスト外の値へ「変える」ことはできない。
    // 例外は「現在保存されている 1 件」に限る規則なので、別の未知の値は従来どおり弾く
    [Fact]
    public async Task EditPost_ChangingToAnotherUnlistedDepartment_IsRejected()
    {
        RequireOutsideAllowList(RetiredDepartment);
        RequireOutsideAllowList(UnknownDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);
        var controller = NewIncidentsController();

        var result = await controller.Edit(
            incident.Id, EditSubmission(incident, UnknownDepartment));

        // フォームを再描画する(保存しない)
        Assert.IsType<ViewResult>(result);
        // 部署欄に検証エラーが積まれている
        Assert.True(controller.ModelState.ContainsKey(nameof(IncidentCreateEditViewModel.Department)));
        // DB の値は変わっていない
        Assert.Equal(RetiredDepartment, await StoredDepartmentAsync(incident.Id));
    }

    // 例外の判定は序数(完全一致)。大文字小文字だけが違う綴りは別の値として弾く。
    //
    // 緩めて OrdinalIgnoreCase にしても、他の検査は全件緑のまま通る(実測。件数も変わらない)。
    // それでは ResolveDepartmentSaveSelection の解説が「保存される綴りが編集のたびに揺れる」
    // として禁じている状態がそのまま通ってしまう。実害は綴りが変わることだけに留まらない:
    // 大文字小文字を区別する既定プロバイダ(SQLite / PostgreSQL)では、書き換わった行が
    // 元の綴りでの絞り込み(?department=旧 ICU)に一致しなくなり、一覧から到達できなくなる。
    //
    // 選択肢を組み立てる側の Contains も序数なので、緩めると表示側と適用側の判定もずれる
    // ——画面には「旧 ICU」しか出ないのに、保存では「旧 icu」も通る状態になる
    [Fact]
    public async Task EditPost_CaseVariantOfStoredDepartment_IsRejected()
    {
        RequireOutsideAllowList(RetiredDepartmentWithLetters);
        RequireOutsideAllowList(RetiredDepartmentCaseVariant);
        var incident = await SeedIncidentAsync(RetiredDepartmentWithLetters);
        var controller = NewIncidentsController();

        // 保存されている綴りの大文字小文字だけを変えて送る
        var result = await controller.Edit(
            incident.Id, EditSubmission(incident, RetiredDepartmentCaseVariant));

        // 保存されず再描画される
        Assert.IsType<ViewResult>(result);
        Assert.True(controller.ModelState.ContainsKey(nameof(IncidentCreateEditViewModel.Department)));
        // DB の綴りは元のまま(揺れない)
        Assert.Equal(RetiredDepartmentWithLetters, await StoredDepartmentAsync(incident.Id));
    }

    // 許可リスト外から許可リスト内へ直すのは通る。
    // 例外は「触らない編集を通す」ためのもので、正しい値への修正まで塞いではいけない
    [Fact]
    public async Task EditPost_ChangingFromUnlistedToListedDepartment_Saves()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);
        var listed = Incident.Departments[0];

        var result = await NewIncidentsController().Edit(incident.Id, EditSubmission(incident, listed));

        Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(listed, await StoredDepartmentAsync(incident.Id));
    }

    // 新規登録では例外が働かない(実データに同じ部署名の行があっても弾く)。
    // これが漏れると、許可リストから外した部署名で新しいインシデントを作れてしまう
    [Fact]
    public async Task CreatePost_UnlistedDepartment_IsRejected()
    {
        RequireOutsideAllowList(RetiredDepartment);
        // 許可リスト外の部署名を持つ行を先に用意する(「実データにあるから通る」を封じる)
        await SeedIncidentAsync(RetiredDepartment);
        var controller = NewIncidentsController();

        // 登録フォームの送信内容(対策 1 件は業務ルール上必須)
        var vm = new IncidentCreateEditViewModel
        {
            DepartmentOptions = new List<string>(),
            OccurredAt = TestFixtures.Today,
            Department = RetiredDepartment,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者",
            Measures = new List<MeasureFormViewModel>
            {
                // 保存まで到達するテストがあるので、保存に必要な項目をすべて埋める
                // (テストではモデルバインドが走らず [Required] が効かないため、
                //  埋めないと Create の保存処理が null 参照で落ちる)
                new()
                {
                    Description = "対策",
                    MeasureType = MeasureTypeKind.ShortTerm,
                    ResponsiblePerson = "担当者",
                    ResponsibleDepartment = Incident.Departments[0],
                    DueDate = TestFixtures.Today.AddDays(30),
                    Priority = 2
                }
            }
        };

        var result = await controller.Create(vm);

        // 再描画される(保存されない)
        Assert.IsType<ViewResult>(result);
        Assert.True(controller.ModelState.ContainsKey(nameof(IncidentCreateEditViewModel.Department)));
        // インシデントは 1 件(セットアップで入れた分)のまま
        Assert.Equal(1, await _db.Incidents.CountAsync());
    }

    // Staff は EnforceKnownDepartment の対象外だが、それでも発生部署は書き換わらない。
    // 根拠は認可側にある(SameDepartmentHandler が「発生部署 == 本人のクレーム」の行しか
    // 編集させないので、EnforceOwnDepartmentForStaff の上書きは同じ値の代入になる)。
    // 暗黙の前提なので固定する ——認可の判定基準が変わると黙って崩れる
    [Fact]
    public async Task EditPost_StaffOwningAnUnlistedDepartment_KeepsIt()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);
        // 所属部署クレームが許可リスト外の値になっている Staff(部署名変更後の実在の状態)
        var staff = UserContextHelper.Staff(RetiredDepartment);

        var result = await NewIncidentsController(staff)
            .Edit(incident.Id, EditSubmission(incident, RetiredDepartment, description: "説明を直した"));

        Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(RetiredDepartment, await StoredDepartmentAsync(incident.Id));
    }

    // 新規登録で許可リスト外の部署名が入りうる経路は Staff のクレームだけで、これは意図的。
    //
    // EnforceOwnDepartmentForStaff がフォームの値をクレームで上書きし、
    // EnforceKnownDepartment は Staff を対象にしないので、クレームが許可リストから
    // 外れている Staff の登録はその部署名のまま保存される。
    // Staff も検証対象にすれば塞げるが、そうすると部署名を入れ替えた直後に
    // その部署の Staff 全員がインシデントを報告できなくなる ——原因は自分では直せない
    // クレーム(管理者管理下の値)なので復旧手段が無い。「報告できない」の方が重い障害なので
    // こちらを選んでいる(判断の正本は EnforceKnownDepartment のコメント。issue #196 の前からある)。
    //
    // 意図した挙動なので固定する。暗黙にしておくと、次に読む人がこれを
    // 「塞ぎ忘れ」と読んで塞ぎに行き、上のロックアウトを起こす
    [Fact]
    public async Task CreatePost_StaffWithUnlistedClaim_SavesWithThatDepartment()
    {
        RequireOutsideAllowList(RetiredDepartment);
        // 所属部署クレームが許可リスト外の値になっている Staff(部署名変更直後の実在の状態)
        var controller = NewIncidentsController(UserContextHelper.Staff(RetiredDepartment));

        // 部署はフォームで何を送っても EnforceOwnDepartmentForStaff がクレームで上書きする
        var vm = new IncidentCreateEditViewModel
        {
            DepartmentOptions = new List<string>(),
            OccurredAt = TestFixtures.Today,
            Department = Incident.Departments[0],
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者",
            Measures = new List<MeasureFormViewModel>
            {
                // 保存まで到達するテストがあるので、保存に必要な項目をすべて埋める
                // (テストではモデルバインドが走らず [Required] が効かないため、
                //  埋めないと Create の保存処理が null 参照で落ちる)
                new()
                {
                    Description = "対策",
                    MeasureType = MeasureTypeKind.ShortTerm,
                    ResponsiblePerson = "担当者",
                    ResponsibleDepartment = Incident.Departments[0],
                    DueDate = TestFixtures.Today.AddDays(30),
                    Priority = 2
                }
            }
        };

        var result = await controller.Create(vm);

        // 保存される(報告そのものを塞がない)
        Assert.IsType<RedirectToActionResult>(result);
        // 発生部署はクレームの値(許可リスト外)になる
        var saved = await _db.Incidents.AsNoTracking().SingleAsync();
        Assert.Equal(RetiredDepartment, saved.Department);
    }

    // --- 表示側と適用側が同じ判定を通っていること -----------------------------

    // 編集画面が並べた選択肢は、1 つ残らず保存が通る。
    // これが issue #196 の完了条件そのもの: 片方だけ広いと
    //   - 選択肢が広い → 画面で選べる値が保存で弾かれ、何を選べば通るか分からない
    //   - 許可が広い   → 画面に出ない値をフォーム改ざんで保存できる
    // どちらも「選択肢を組み立てる側」と「保存を許す側」が別々に判定を持つと戻る。
    // 選択肢を固定値で書き並べず<b>画面が実際に返したもの</b>を回すのが要点 ——
    // 補完の規則が変わっても、この検査は新しい選択肢に対して自動で掛かる
    [Fact]
    public async Task EditForm_EveryOfferedOption_IsAcceptedOnSave()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);

        // 編集画面が実際に並べる選択肢を取り出す
        var offered = (await EditFormAsync(incident.Id)).DepartmentOptions;
        // 空だと「見るべき対象ゼロ＝緑」になるので fail-closed で落とす
        Assert.NotEmpty(offered);

        foreach (var option in offered)
        {
            // 各周回の前に、保存されている部署を必ず元の(許可リスト外の)値へ戻す。
            //
            // 戻さないと検査が<b>選択肢の並び順に依存する</b>: 1 周目で許可リスト内の値を
            // 保存してしまうと、2 周目以降は「保存されている値」がその許可リスト内の値になり、
            // 補完された部署名に対する例外が消える。今は補完が先頭に入るおかげでたまたま
            // 1 周目に当たって通っているだけで、EnsureAppliedValueIsSelectable の位置の規則を
            // 末尾へ変えた瞬間、この検査は「選択肢が保存で弾かれた」と<b>位置とは無関係の
            // 見出しで</b>落ちる ——直す人が原因を取り違える
            await ResetStoredDepartmentAsync(incident.Id, RetiredDepartment);

            // 毎回新しいコントローラを使う(ModelState は前の送信を持ち越さない)
            var controller = NewIncidentsController();
            // 現在の DB の値を読み直してからトークン込みで送る
            // (前の周回が保存に成功していると ConcurrencyToken が回っているため)
            var current = await _db.Incidents.AsNoTracking().FirstAsync(i => i.Id == incident.Id);
            _db.ChangeTracker.Clear();

            var result = await controller.Edit(incident.Id, EditSubmission(current, option));

            // 部署欄の検証エラーが積まれていないこと(=この選択肢は保存が通る)
            Assert.False(
                controller.ModelState.ContainsKey(nameof(IncidentCreateEditViewModel.Department)),
                $"編集画面が並べた選択肢「{option}」が保存で弾かれた。"
                + "選択肢を組み立てる側と保存を許す側が同じ判定を通っていない(issue #196)。");
            // 保存まで通っていること(検証エラーが別の欄に出ていないことも同時に確かめる)
            Assert.IsType<RedirectToActionResult>(result);
        }
    }

    // --- 再描画: 選択肢を詰め直しているか -------------------------------------

    // 検証エラーで編集画面を再描画するときも、補完した部署名を選択肢へ戻す。
    // 戻さないと再描画された画面から現在値が消え、次の送信で issue #196 の
    // 書き換えがそのまま起きる。選択肢は POST ボディに含まれないので
    // 「モデルバインドされた値がそのまま返る」ことに頼れない
    [Fact]
    public async Task EditPost_Invalid_RedisplaysOptionsIncludingStoredDepartment()
    {
        RequireOutsideAllowList(RetiredDepartment);
        var incident = await SeedIncidentAsync(RetiredDepartment);
        var controller = NewIncidentsController();
        // 部署とは無関係の欄で検証を失敗させる(部署の判定そのものは他のテストが見る)
        controller.ModelState.AddModelError(
            nameof(IncidentCreateEditViewModel.Description), "テスト用の検証エラー");

        var result = await controller.Edit(incident.Id, EditSubmission(incident, RetiredDepartment));

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<IncidentCreateEditViewModel>(view.Model);
        // 送信時は空だった選択肢が詰め直され、補完した現在値も入っている
        Assert.Contains(RetiredDepartment, vm.DepartmentOptions);
        Assert.Equal(RetiredDepartment, vm.DepartmentOptions[0]);
    }

    // 登録画面の再描画でも選択肢を詰め直す(空のまま返すとビューの foreach が
    // 何も並べず、部署を選べないフォームが表示される)
    [Fact]
    public async Task CreatePost_Invalid_RedisplaysTheAllowList()
    {
        var controller = NewIncidentsController();
        // 対策が 1 件も無いので業務ルール(HasAtLeastOneValidMeasure)で必ず再描画になる
        var vm = new IncidentCreateEditViewModel
        {
            DepartmentOptions = new List<string>(),
            OccurredAt = TestFixtures.Today,
            Department = Incident.Departments[0],
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "説明",
            ReporterName = "報告者"
        };

        var result = await controller.Create(vm);

        var view = Assert.IsType<ViewResult>(result);
        var model = Assert.IsType<IncidentCreateEditViewModel>(view.Model);
        Assert.Equal(Incident.Departments, model.DepartmentOptions);
    }

    // --- 表示側(Razor)がコントローラの結論を実際に使っているか -----------------

    // 上のコントローラ級テストは ViewModel までしか見ないので、**ビューが選択肢を
    // どこから取るか**は見ていない。ビューを元どおり
    // `@foreach (var d in Incident.Departments)` へ戻しても上の Assert はすべて素通りし、
    // 画面だけが issue #196 の壊れ方に戻る(補完した値の option が消え、別項目だけ直した
    // 保存で発生部署が書き換わる)。その配線だけを Razor のソースから直接確かめる。
    //
    // 走査の作りは一覧側(UnlistedFilterValuePolicyTests)と同じ考え方で、部品は
    // RazorSource で共有している: コメントを落としてから対象の <select> ブロックだけを見て、
    // 「foreach が回している対象」がコントローラの用意した名前かを識別子として照合する。
    // 「禁止する名前を含まないか」と書かないのは、画面ごとに「ありえない書き換え」を
    // 予想して列挙することになるため ——回している対象そのものを見れば、別の何に
    // 差し替えられても落ちる。
    //
    // 一覧側と違って selected の検査は要らない。こちらの <select> は asp-for の
    // タグヘルパーが現在値に一致する option を自動で選択状態にするため
    // ——「一致する option が無い」ことだけが issue #196 の原因だった
    [Theory]
    // 登録フォーム: 許可リストそのままだが、出所は編集フォームとそろえる
    [InlineData("Create.cshtml")]
    // 編集フォーム: 補完した部署名を含む選択肢を回す(これが本体)
    [InlineData("Edit.cshtml")]
    public void IncidentForms_BuildDepartmentOptionsFromTheControllersResult(string viewFileName)
    {
        // 対象ビューの Razor ソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", viewFileName);
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"フォームのビューが見つからない: {viewPath}");
        var source = File.ReadAllText(viewPath);

        // 発生部署のドロップダウンの開始タグを探す(asp-for が目印)
        var selectStart = source.IndexOf(
            $"<select asp-for=\"{nameof(IncidentCreateEditViewModel.Department)}\"", StringComparison.Ordinal);
        // 見つからなければ、ビューの構造が変わったか目印が消えている。
        // 「見るべきブロックが無い＝緑」にすると検出網が黙って死ぬので fail-closed で落とす
        Assert.True(selectStart >= 0,
            $"Incidents/{viewFileName} に発生部署の <select asp-for=\"Department\"> が見つからない。"
            + "この検査はこのブロックの中身だけを見るので、目印を変えるならこのテストも"
            + "同じ変更セットで直すこと。");
        // 対応する閉じタグまでを切り出す(select は入れ子にならないので最初の </select> でよい)
        var selectEnd = source.IndexOf("</select>", selectStart, StringComparison.Ordinal);
        Assert.True(selectEnd > selectStart,
            $"Incidents/{viewFileName} の <select> に対応する </select> が見つからない。");
        // Razor のコメントを取り除く。コメントで検査を満たしたり破ったりできないようにする
        var selectBlock = RazorSource.StripComments(source[selectStart..selectEnd]);

        // ブロックの中の foreach が「何を」回しているかをすべて取り出す
        var loopSources = RazorSource.ExtractForeachSources(selectBlock);

        // 解析できた数が、ブロック内の foreach の数と一致していることを先に確かめる。
        // ExtractForeachSources は解析できないループを読み飛ばすので、ずれたまま使うと
        // 「出所の検査だけが素通りする」fail-open になる
        var loopCount = RazorSource.CountForeach(selectBlock);
        Assert.True(loopSources.Count == loopCount,
            $"Incidents/{viewFileName} の発生部署の <select> にある foreach {loopCount} 件のうち "
            + $"{loopSources.Count} 件しか解析できていない。解析できないループは検査から外れるので、"
            + "書き方を揃えるか RazorSource.ExtractForeachSources を直すこと。");
        // foreach が無ければ選択肢を組み立てていない(静的な option だけになっている)
        Assert.True(loopSources.Count > 0,
            $"Incidents/{viewFileName} の発生部署の <select> に選択肢を組み立てる foreach が見つからない。");

        // すべてのループがコントローラの用意した選択肢を回していること。
        // 照合は識別子の境界まで見る(部分文字列だと別の名前へ差し替えても前置詞が一致して通る)
        var expected = $"Model.{nameof(IncidentCreateEditViewModel.DepartmentOptions)}";
        Assert.All(loopSources, loop => Assert.True(RazorSource.ContainsIdentifier(loop, expected),
            $"Incidents/{viewFileName} の発生部署の選択肢は {expected} から作る。"
            + $"静的な一覧へ戻すと補完した部署名の option が消え、別項目だけ直した保存で"
            + $"発生部署が書き換わる(issue #196)。実際に回しているのは: {loop}"));
    }
}
