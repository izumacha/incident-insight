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

    // /Incidents を扱うコントローラを Admin ユーザーで用意する
    private IncidentsController NewIncidentsController()
    {
        // 実際の依存をそのまま渡す(Mock より InMemory を優先する方針)
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(new SystemClock(), NullLogger<RecurrenceService>.Instance),
            new SystemClock(),
            NullLogger<IncidentsController>.Instance);
        // 全部署を見られる Admin として実行する(部署スコープの影響を切り離すため)
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
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

        // 自部署 ICU の Staff としてアクセスする
        var controller = NewIncidentsController();
        UserContextHelper.AttachUser(controller, UserContextHelper.Staff("ICU"));
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

    // --- 表示側(Razor)がコントローラの結論を実際に使っているか -----------------

    // 上のコントローラ級テストは ViewModel までしか見ないので、**ビューが選択肢を
    // どこから取るか**は見ていない。実測すると、ビューを元どおり
    // `@foreach (var d in Incident.Departments)` へ戻しても上の 8 件は全件緑のまま通り、
    // 画面だけが issue #192 の壊れ方に戻る(補完した値の option が消えて select が
    // 「部署（全て）」を指す)。コントローラで正しく決めた結論を表示側が使わなければ
    // 意味がないので、その配線だけを Razor のソースから直接確かめる。
    //
    // 検査は「この 1 ファイルが Model.DepartmentOptions を回していること」と
    // 「部署の select の選択肢づくりに static 配列を直接使っていないこと」の 2 点に絞る。
    // 走査対象を 1 ファイルに限るのは、Incident.Departments の参照自体は他の画面
    // (登録・編集フォーム)では正しい書き方だから ——一律に禁じると正しいコードを咎める
    // 検出網になり、いずれ緩められる(この repo が繰り返し避けている形)
    [Fact]
    public void IncidentsIndexView_BuildsDepartmentOptionsFromTheViewModel()
    {
        // 一覧ビューの Razor ソースを読む(ビルド出力にはコピーされないので絶対パスで開く)
        var viewPath = Path.Combine(RepositoryPaths.Views, "Incidents", "Index.cshtml");
        // 見つからなければ「対象ゼロ＝緑」を避けるため fail-closed で落とす
        Assert.True(File.Exists(viewPath), $"一覧ビューが見つからない: {viewPath}");
        var source = File.ReadAllText(viewPath);

        // (1) ViewModel が用意した選択肢を実際に回している
        Assert.Contains("Model.DepartmentOptions", source);

        // (2) 部署の選択肢づくりで static 配列を直接回していない。
        //     `Incident.Departments` を foreach の列挙対象にしている行だけを違反とみなす
        //     (登録・編集フォームのような他の使い方はこの画面には無いが、
        //      将来この画面へ足したときに巻き添えで落とさないよう書き方で絞る)
        var offendingLines = source
            .Split('\n')
            .Where(line => line.Contains("foreach") && line.Contains("Incident.Departments"))
            .ToList();
        Assert.True(offendingLines.Count == 0,
            "部署の選択肢は Model.DepartmentOptions から作る。Incident.Departments を直接回すと、"
            + "許可リストから外れた過去の部署名で絞り込んだときに一致する option が無くなり、"
            + "再送信で絞り込みが無言で解除される(issue #192)。該当行: "
            + string.Join(" / ", offendingLines.Select(l => l.Trim())));
    }
}
