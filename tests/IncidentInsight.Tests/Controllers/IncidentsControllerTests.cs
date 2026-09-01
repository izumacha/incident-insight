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

public class IncidentsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly IncidentsController _controller;

    public IncidentsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            // InMemory プロバイダはトランザクションをサポートしないため警告が出るが、
            // テスト用途ではトランザクション整合性を検証しないので例外扱いにせず無視する。
            // 本番の SQLite/SQL Server/PostgreSQL では BeginTransactionAsync は正常に動作する。
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(new SystemClock(), NullLogger<RecurrenceService>.Instance),
            new SystemClock(),
            NullLogger<IncidentsController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    private IncidentCreateEditViewModel ValidViewModel(string dept = "内科病棟") => new()
    {
        // TestFixtures.Today を使い実行日時に依存しない決定論的テストにする
        OccurredAt = TestFixtures.Today,
        Department = dept,
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト状況",
        ReporterName = "テスト太郎",
        Measures = new List<MeasureFormViewModel>
        {
            new()
            {
                Description = "テスト対策",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = dept,
                // DueDate も TestFixtures.Today 基準にして決定論的テストにする
                DueDate = TestFixtures.Today.AddDays(30),
                Priority = 2
            }
        }
    };

    // --- Create POST ---

    [Fact]
    public async Task Create_Post_ValidModel_RedirectsToDetails()
    {
        var vm = ValidViewModel();

        var result = await _controller.Create(vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesIncidentToDb()
    {
        var vm = ValidViewModel("外科病棟");

        await _controller.Create(vm);

        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("外科病棟", saved.Department);
        Assert.Equal(IncidentTypeKind.Medication, saved.IncidentType);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesMeasure()
    {
        var vm = ValidViewModel();

        await _controller.Create(vm);

        var measure = await _db.PreventiveMeasures.FirstOrDefaultAsync();
        Assert.NotNull(measure);
        Assert.Equal("テスト対策", measure.Description);
        Assert.Equal(MeasureStatus.Planned, measure.Status);
    }

    [Fact]
    public async Task Create_Post_InvalidModel_ReturnsCreateView()
    {
        _controller.ModelState.AddModelError("Department", "Required");
        var vm = new IncidentCreateEditViewModel();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
    }

    [Fact]
    public async Task Create_Post_InvalidModel_RetainsEnteredMeasuresInViewModel()
    {
        // バリデーション失敗で再描画する際、入力済みの対策行が ViewModel に
        // そのまま残ること(Create.cshtml は Model.Measures をループ描画するため、
        // ここが消えると利用者が入力した再発防止策が全消失する)
        // 有効な入力から始めて対策行を2件に増やす
        var vm = ValidViewModel();
        // 2件目の対策行を追加する(入力途中のデータを想定)
        vm.Measures.Add(new MeasureFormViewModel
        {
            Description = "テスト対策2",
            MeasureType = MeasureTypeKind.LongTerm,
            ResponsiblePerson = "担当者2",
            ResponsibleDepartment = "内科病棟",
            DueDate = TestFixtures.Today.AddDays(60),
            Priority = 1
        });
        // 別項目のバリデーション失敗を人為的に発生させる
        _controller.ModelState.AddModelError("Description", "状況・経緯を入力してください");

        // Create POST を実行する
        var result = await _controller.Create(vm);

        // フォーム再描画(ViewResult)になること
        var viewResult = Assert.IsType<ViewResult>(result);
        // ビューへ渡されたモデルを取り出す
        var model = Assert.IsType<IncidentCreateEditViewModel>(viewResult.Model);
        // 対策行が2件とも保持されていること
        Assert.Equal(2, model.Measures.Count);
        // 1件目の入力内容が失われていないこと
        Assert.Equal("テスト対策", model.Measures[0].Description);
        // 2件目の入力内容も失われていないこと
        Assert.Equal("テスト対策2", model.Measures[1].Description);
        // インシデント自体は保存されていないこと
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_InvalidModel_NullMeasures_ReturnsEmptyListNotNull()
    {
        // POST ボディに Measures が1件も無い場合(null)でも、再描画用モデルの
        // Measures が空リストに補正され、ビュー側のループが null 参照で落ちないこと
        var vm = ValidViewModel();
        // Measures をあえて null にして未送信の POST を模す
        vm.Measures = null!;

        // Create POST を実行する
        var result = await _controller.Create(vm);

        // フォーム再描画(ViewResult)になること
        var viewResult = Assert.IsType<ViewResult>(result);
        // ビューへ渡されたモデルを取り出す
        var model = Assert.IsType<IncidentCreateEditViewModel>(viewResult.Model);
        // Measures が null ではなく空リストになっていること
        Assert.NotNull(model.Measures);
        // 補正結果が空リスト(0件)であり、勝手な空行が追加されていないこと
        Assert.Empty(model.Measures);
    }

    [Fact]
    public async Task Create_Post_WithoutMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_WithOnlyWhitespaceMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>
        {
            new() { Description = "   " },
            new() { Description = "\t" }
        };

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_PartialAnalysis_MissingCategory_ReturnsView_AndDoesNotSave()
    {
        // なぜ1〜のテキストを書いたのに原因分類だけ選び忘れた「部分入力」のフォーム。
        // 以前はこの場合、インシデントだけ保存され成功トーストの裏で分析テキストが
        // 無言で全破棄されていた(利用者が気づけないデータ消失)。修正後は入力不備として
        // フォームを再描画し、入力を完成させるよう促すことを確認する(回帰防止)。
        var vm = ValidViewModel();
        vm.CauseAnalysis.CauseCategoryId = 0;   // 原因分類は未選択のまま
        vm.CauseAnalysis.Why1 = "確認を怠った"; // 分析テキストだけ入力されている

        var result = await _controller.Create(vm);

        // Create ビューが再描画され、何も保存されていないこと
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(
            $"{nameof(IncidentCreateEditViewModel.CauseAnalysis)}.{nameof(CauseAnalysisFormViewModel.CauseCategoryId)}"));
        Assert.Empty(_db.Incidents);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task Create_Post_PartialAnalysis_MissingWhy1_ReturnsView_AndDoesNotSave()
    {
        // 原因分類は選んだのに なぜ1 が未入力の「部分入力」も同様に入力不備として扱う
        var category = new CauseCategory { Name = "確認不足" };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var vm = ValidViewModel();
        vm.CauseAnalysis.CauseCategoryId = category.Id; // 原因分類は選択済み
        vm.CauseAnalysis.Why1 = "";                     // なぜ1 は未入力

        var result = await _controller.Create(vm);

        // Create ビューが再描画され、何も保存されていないこと
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(
            $"{nameof(IncidentCreateEditViewModel.CauseAnalysis)}.{nameof(CauseAnalysisFormViewModel.Why1)}"));
        Assert.Empty(_db.Incidents);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task Create_Post_NonExistentCauseCategory_ReturnsView_AndDoesNotSave()
    {
        var vm = ValidViewModel();
        // DB にカテゴリを一切投入していないので、この Id は必ず存在しない。
        // Why1 も入れて「原因分析を保存する」分岐に入る条件を満たす。
        vm.CauseAnalysis.CauseCategoryId = 999999;
        vm.CauseAnalysis.Why1 = "原因の仮説";

        var result = await _controller.Create(vm);

        // 未捕捉の 500 ではなく、入力値を保持したまま登録フォームを再描画する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(
            $"{nameof(IncidentCreateEditViewModel.CauseAnalysis)}.{nameof(CauseAnalysisFormViewModel.CauseCategoryId)}"));
        // インシデント・原因分析ともに保存されていないこと
        Assert.Empty(_db.Incidents);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task Create_Post_ExistingCauseCategoryWithWhy1_SavesCauseAnalysis()
    {
        // 実在する原因カテゴリを 1 件用意する
        var category = new CauseCategory { Name = "手順" };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        var vm = ValidViewModel();
        // 実在カテゴリ Id と Why1 を指定して原因分析を保存させる
        vm.CauseAnalysis.CauseCategoryId = category.Id;
        vm.CauseAnalysis.Why1 = "手順が未整備だった";

        var result = await _controller.Create(vm);

        // 正常系は詳細画面へリダイレクトし、原因分析が保存される
        Assert.IsType<RedirectToActionResult>(result);
        var analysis = await _db.CauseAnalyses.FirstOrDefaultAsync();
        Assert.NotNull(analysis);
        Assert.Equal(category.Id, analysis.CauseCategoryId);
        Assert.Equal("手順が未整備だった", analysis.Why1);
    }

    [Fact]
    public async Task Create_Post_OverLimitWhy1_ReturnsCreateView_AndDoesNotSave()
    {
        // 実在する原因カテゴリを 1 件用意する(保存対象=IsSavable の分岐に入るため)
        var category = new CauseCategory { Name = "確認不足" };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        // 妥当なインシデント入力に、上限(500文字)超のなぜ1 を持つ原因分析を付ける
        var vm = ValidViewModel();
        vm.CauseAnalysis.CauseCategoryId = category.Id;      // 原因分類は選択済み
        vm.CauseAnalysis.Why1 = new string('あ', 501);       // 500文字上限を1文字超過

        // Create POST を実行する
        var result = await _controller.Create(vm);

        // 以前は CauseAnalysis.* の一括除外で MaxLength 違反まで破棄され保存されてしまった。
        // 修正後は Create ビューを再描画し、Why1 にモデルエラーが付くことを確認する(回帰防止)
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効で、Why1 のキーにエラーが積まれていること
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(
            $"{nameof(IncidentCreateEditViewModel.CauseAnalysis)}.{nameof(CauseAnalysisFormViewModel.Why1)}"));
        // インシデント・原因分析ともに保存されていないこと
        Assert.Empty(_db.Incidents);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task Create_Post_OverLimitAnalystName_ReturnsCreateView_AndDoesNotSave()
    {
        // 実在する原因カテゴリを 1 件用意する(保存対象=IsSavable の分岐に入るため)
        var category = new CauseCategory { Name = "手順" };
        _db.CauseCategories.Add(category);
        await _db.SaveChangesAsync();

        // 妥当な分析入力に、上限(100文字)超の分析者名だけを混ぜる
        var vm = ValidViewModel();
        vm.CauseAnalysis.CauseCategoryId = category.Id;       // 原因分類は選択済み
        vm.CauseAnalysis.Why1 = "確認を怠った";               // なぜ1 は正常
        vm.CauseAnalysis.AnalystName = new string('あ', 101); // 100文字上限を1文字超過

        // Create POST を実行する
        var result = await _controller.Create(vm);

        // Create ビューが再描画され、AnalystName にモデルエラーが付き、何も保存されないこと
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効で、AnalystName のキーにエラーが積まれていること
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(
            $"{nameof(IncidentCreateEditViewModel.CauseAnalysis)}.{nameof(CauseAnalysisFormViewModel.AnalystName)}"));
        // インシデント・原因分析ともに保存されていないこと
        Assert.Empty(_db.Incidents);
        Assert.Empty(_db.CauseAnalyses);
    }

    [Fact]
    public async Task Create_Post_PersistedMeasureWithFieldError_KeepsError_AndDoesNotSave()
    {
        // 対策内容ありの行(=保存対象)を 1 件持つ妥当な ViewModel を用意する
        var vm = ValidViewModel();
        // model binding が「実施期限が不正」と判定した状況を再現する(保存される行のエラー)
        _controller.ModelState.AddModelError("Measures[0].DueDate", "実施期限を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 保存される対策行のフィールド検証は除去されず、再描画されることを確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効のまま(エラーが残っている)であること
        Assert.False(_controller.ModelState.IsValid);
        // 該当行のエラーキーが残っていること(空行のように消されていないこと)
        Assert.True(_controller.ModelState.ContainsKey("Measures[0].DueDate"));
        // 不正なデータでインシデントが保存されていないことを確認する
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_EmptyExtraMeasureRow_RemovesItsErrors_AndSaves()
    {
        // [0] は妥当な対策行、[1] は対策内容が空の余分な行(保存されない行)を用意する
        var vm = ValidViewModel();
        vm.Measures.Add(new MeasureFormViewModel { Description = "" });
        // 空行に対して model binding が付けた Required エラーを再現する
        _controller.ModelState.AddModelError("Measures[1].DueDate", "実施期限を入力してください");
        _controller.ModelState.AddModelError("Measures[1].ResponsiblePerson", "担当者を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 空行のエラーは除去され、検証を通過して詳細画面へリダイレクトされることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        // 空行のエラーキーが ModelState から除去されていること
        Assert.False(_controller.ModelState.ContainsKey("Measures[1].DueDate"));
        // インシデントが 1 件保存されていること
        Assert.Single(_db.Incidents);
        // 保存される対策は対策内容ありの 1 件だけ(空行は永続化されない)であること
        Assert.Single(_db.PreventiveMeasures);
    }

    [Fact]
    public async Task Create_Post_EmptyRow_DoesNotStripHigherIndexedRowError()
    {
        // [0] は妥当な対策行。[1..9] は空行、[10] は対策内容ありの保存対象行にする。
        var vm = ValidViewModel();
        // インデックス 1〜10 を埋める(1〜9 は空行、10 は対策内容あり)
        for (int i = 1; i <= 10; i++)
        {
            // i==10 のときだけ対策内容を入れて保存対象の行にする
            vm.Measures.Add(new MeasureFormViewModel { Description = i == 10 ? "10番目の対策" : "" });
        }
        // 空行[1]の Required エラーと、保存対象[10]のフィールドエラーを再現する
        _controller.ModelState.AddModelError("Measures[1].DueDate", "実施期限を入力してください");
        _controller.ModelState.AddModelError("Measures[10].DueDate", "実施期限を入力してください");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 空行[1]の除去で [10] のエラーが巻き込まれないこと(プレフィックス誤一致防止)を確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // 保存対象[10]のエラーは残っていること
        Assert.True(_controller.ModelState.ContainsKey("Measures[10].DueDate"));
        // 空行[1]のエラーは除去されていること
        Assert.False(_controller.ModelState.ContainsKey("Measures[1].DueDate"));
        // 不正データなのでインシデントは保存されないこと
        Assert.Empty(_db.Incidents);
    }

    // --- Create/Edit POST: future OccurredAt rejection ---

    // 時刻を固定した IClock でコントローラを組み立てるヘルパー。
    // 「未来の日時かどうか」の境界判定は実時刻(SystemClock)だとテスト実行時刻に依存して
    // 不安定になるため、FixedClock で決定論的に検証する
    private IncidentsController CreateControllerWithClock(IClock clock)
    {
        // 固定時刻のクロックを注入してコントローラを構築する
        var controller = new IncidentsController(
            _db,
            UserContextHelper.BuildAuthService(),
            new RecurrenceService(clock, NullLogger<RecurrenceService>.Instance),
            clock,
            NullLogger<IncidentsController>.Instance);
        // 既定の Admin ユーザーと TempData を配線する
        UserContextHelper.AttachUser(controller, UserContextHelper.Admin());
        // 構築したコントローラを返す
        return controller;
    }

    [Fact]
    public async Task Create_Post_FutureOccurredAt_ReturnsView_AndDoesNotSave()
    {
        // 「現在時刻」を固定日時に固定したコントローラを用意する
        var controller = CreateControllerWithClock(new FixedClock(TestFixtures.Today));
        // 発生日時が現在時刻より 1 分未来のインシデントを送信する
        var vm = ValidViewModel();
        vm.OccurredAt = TestFixtures.Today.AddMinutes(1);

        // Create POST を実行する
        var result = await controller.Create(vm);

        // 未来の発生日時は拒否され、フォームを再描画すること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効で、OccurredAt のキーにエラーが積まれていること
        Assert.False(controller.ModelState.IsValid);
        Assert.True(controller.ModelState.ContainsKey(nameof(vm.OccurredAt)));
        // インシデントは保存されていないこと
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_OccurredAtEqualToNow_Saves()
    {
        // 「現在時刻」を固定日時に固定したコントローラを用意する
        var controller = CreateControllerWithClock(new FixedClock(TestFixtures.Today));
        // 発生日時をちょうど現在時刻(境界値)にして送信する
        var vm = ValidViewModel();
        vm.OccurredAt = TestFixtures.Today;

        // Create POST を実行する
        var result = await controller.Create(vm);

        // 現在時刻ちょうどは未来ではないため正常に保存され、詳細画面へリダイレクトすること
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
        // インシデントが 1 件保存されていること
        Assert.Single(_db.Incidents);
    }

    // サブフォーム由来キーの一括除外が「序数比較」であることを固定する。
    //
    // 引数なしの string.StartsWith は現在のカルチャで比較するため、ICU が「無視できる文字」と
    // みなす記号(ソフトハイフン U+00AD / ZWJ U+200D 等)を挟んだキーまで前方一致と判定してしまう
    // (実測: "­CauseAnalysis.Why1".StartsWith("CauseAnalysis.") は true、
    //  StringComparison.Ordinal を渡すと false)。
    // 一致は「除去する側」に効くので、意図より多くの検証エラーを捨てる fail-open になり、
    // しかも成立するかどうかがサーバの OS ロケールと ICU の版に左右される。
    // ModelState のキーは画面が組み立てる識別子であって自然言語ではないため、序数比較が正しい。
    [Fact]
    public async Task Create_Post_SubFormKeyFilter_UsesOrdinalPrefixMatch()
    {
        // 妥当な入力(これ単体なら保存される)を用意する
        var vm = ValidViewModel();
        // 前方一致の対象と「カルチャ比較でだけ」一致するキーへ検証エラーを積む
        // (先頭にソフトハイフン U+00AD を置いた、除外対象ではないキー)
        // 前提（カルチャ比較なら誤一致すること）を共有ヘルパーで表明する。
        // 崩れていれば素通りせずその場で落ちる（理由は LocaleSensitiveTest を参照）
        LocaleSensitiveTest.RequireCultureSensitivePrefixMatch("­CauseAnalysis.Why1", "CauseAnalysis.");
        _controller.ModelState.AddModelError("­CauseAnalysis.Why1", "除外対象ではないエラー");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 除外されていない＝エラーが残っているので、保存されずフォームが再描画されること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効のままであること(カルチャ比較なら除外されて有効になってしまう)
        Assert.False(_controller.ModelState.IsValid);
        // 当該キーが除去されずに残っていること(この 1 行が序数比較かどうかを判別する)
        Assert.True(_controller.ModelState.ContainsKey("­CauseAnalysis.Why1"));
        // 検証エラーが残っている以上、インシデントは保存されていないこと
        Assert.Empty(_db.Incidents);
    }

    // Create の「行ごと」の除外(Measures[i]. の前置詞)も序数比較であることを固定する。
    //
    // 3 つある前方一致のうち、ここが最も影響が大きい。所有コメント(IncidentsController の
    // 同ループ)のとおり、この除外は「保存されない空行だけを消し、保存される行の
    // 担当者・実施期限などの検証は残す」ことでデータ整合性を守っている。カルチャ比較で
    // 保存対象の行にまで誤一致すると、DueDate=default(0001-01-01) のまま保存されて
    // IsOverdue が常に true になる。
    [Fact]
    public async Task Create_Post_PerRowMeasureKeyFilter_UsesOrdinalPrefixMatch()
    {
        // 対策内容ありの行(=保存対象。この行の検証は残されるべき)を持つ ViewModel を用意する
        var vm = ValidViewModel();
        // 空行(対策内容なし)を 2 行目として足し、行ごとの除外ループを実際に走らせる
        vm.Measures.Add(new MeasureFormViewModel { Description = "" });
        // 空行(index 1)の前置詞と「カルチャ比較でだけ」一致するキーへ検証エラーを積む。
        // ZWJ U+200D を語中に挟んであるので、序数比較なら除外対象にならない
        // 前提（カルチャ比較なら誤一致すること）を共有ヘルパーで表明する。
        // 崩れていれば素通りせずその場で落ちる（理由は LocaleSensitiveTest を参照）
        LocaleSensitiveTest.RequireCultureSensitivePrefixMatch("Meas‍ures[1].DueDate", "Measures[1].");
        _controller.ModelState.AddModelError("Meas‍ures[1].DueDate", "除外対象ではないエラー");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 除外されていない＝エラーが残っているので、保存されずフォームが再描画されること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // 当該キーが除去されずに残っていること(この 1 行が序数比較かどうかを判別する)
        Assert.True(_controller.ModelState.ContainsKey("Meas‍ures[1].DueDate"));
        // 検証エラーが残っている以上、インシデントは保存されていないこと
        Assert.Empty(_db.Incidents);
    }

    // Edit 側の一括除外も序数比較であることを固定する。
    // 判定条件が Create と別の式で書かれているため、片方だけ直す取りこぼしを防ぐ意味で個別に見る。
    // Edit の式は前置詞を 2 つ（CauseAnalysis. と Measures[）持つので、両方に 1 件ずつ積む。
    // 片方だけを見ていると、もう片方を素の StartsWith へ戻しても振る舞いのテストは緑のまま通る。
    [Fact]
    public async Task Edit_Post_SubFormKeyFilter_UsesOrdinalPrefixMatch()
    {
        // 編集対象のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today,
            // 報告日時を明示しておく。既定値(0001-01-01)のままだと
            // ValidateOccurredAtNotAfterReportedAt が「発生日時 > 報告日時」で
            // 常にエラーを積んでしまい、下の「ModelState が無効」「保存されていない」の
            // 各表明が前方一致の比較方法と無関係に成立してしまう(検査が空振りする)
            ReportedAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // それ以外は妥当な編集フォームを用意する
        var vm = ValidViewModel();
        vm.ConcurrencyToken = incident.ConcurrencyToken;
        // Measures[ の前置詞と「カルチャ比較でだけ」一致するキーへ検証エラーを積む
        // (ZWJ U+200D を語中に挟んだ、除外対象ではないキー)
        // 前提（カルチャ比較なら誤一致すること）を共有ヘルパーで表明する。
        // 崩れていれば素通りせずその場で落ちる（理由は LocaleSensitiveTest を参照）
        LocaleSensitiveTest.RequireCultureSensitivePrefixMatch("Meas‍ures[0].DueDate", "Measures[");
        _controller.ModelState.AddModelError("Meas‍ures[0].DueDate", "除外対象ではないエラー");
        // もう一方の前置詞（CauseAnalysis.）にも同じ形のキーを積む。Edit の除去式は
        // 2 つの前置詞を || で並べており、片方だけ素の StartsWith へ戻す変異を
        // 取りこぼさないため、両方を 1 つのテストで押さえる
        // こちらの前置詞についても前提（カルチャ比較なら誤一致すること）を表明する。
        // 片方だけ表明していると、ICU の版で U+00AD だけが無視されなくなったとき
        // CauseAnalysis. 側だけが黙って判別力を失う
        LocaleSensitiveTest.RequireCultureSensitivePrefixMatch("­CauseAnalysis.Why1", "CauseAnalysis.");
        _controller.ModelState.AddModelError("­CauseAnalysis.Why1", "除外対象ではないエラー");

        // Edit POST を実行する
        var result = await _controller.Edit(incident.Id, vm);

        // 除外されていない＝エラーが残っているので、保存されずフォームが再描画されること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効のままであること
        Assert.False(_controller.ModelState.IsValid);
        // 当該キーが除去されずに残っていること（2 つの前置詞それぞれについて見る）
        Assert.True(_controller.ModelState.ContainsKey("Meas‍ures[0].DueDate"));
        Assert.True(_controller.ModelState.ContainsKey("­CauseAnalysis.Why1"));
        // 検証エラーが残っている以上、既存の状況説明が書き換わっていないこと
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("編集前", reloaded!.Description);
    }

    [Fact]
    public async Task Edit_Post_FutureOccurredAt_ReturnsView_AndDoesNotSave()
    {
        // 編集対象のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // 「現在時刻」を固定日時に固定したコントローラを用意する
        var controller = CreateControllerWithClock(new FixedClock(TestFixtures.Today));
        // 発生日時を未来(翌日)へ書き換えようとする編集フォームを作る
        var vm = ValidViewModel();
        vm.OccurredAt = TestFixtures.Today.AddDays(1);
        vm.ConcurrencyToken = incident.ConcurrencyToken;

        // Edit POST を実行する
        var result = await controller.Edit(incident.Id, vm);

        // 未来の発生日時は拒否され、フォームを再描画すること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効で、OccurredAt のキーにエラーが積まれていること
        Assert.False(controller.ModelState.IsValid);
        Assert.True(controller.ModelState.ContainsKey(nameof(vm.OccurredAt)));
        // 発生日時が書き換わっていないこと
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal(TestFixtures.Today, reloaded!.OccurredAt);
    }

    [Fact]
    public async Task Edit_Post_OccurredAtAfterReportedAt_ReturnsView_AndDoesNotSave()
    {
        // 前日に発生し、前日のうちに報告済みのインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today.AddDays(-1),
            ReportedAt = TestFixtures.Today.AddDays(-1)
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // 「現在時刻」を固定日時に固定したコントローラを用意する
        var controller = CreateControllerWithClock(new FixedClock(TestFixtures.Today));
        // 発生日時を「現在時刻以前だが報告日時より後」(=本日)へ書き換えようとする編集フォームを作る
        var vm = ValidViewModel();
        vm.OccurredAt = TestFixtures.Today;
        vm.ConcurrencyToken = incident.ConcurrencyToken;

        // Edit POST を実行する
        var result = await controller.Edit(incident.Id, vm);

        // 報告日時より後の発生日時は「発生前に報告された」矛盾になるため拒否され、フォームを再描画すること
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        // ModelState は無効で、OccurredAt のキーにエラーが積まれていること
        Assert.False(controller.ModelState.IsValid);
        Assert.True(controller.ModelState.ContainsKey(nameof(vm.OccurredAt)));
        // 発生日時が書き換わっていないこと
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal(TestFixtures.Today.AddDays(-1), reloaded!.OccurredAt);
    }

    // --- Create POST: department scope enforcement for Staff (issue #63) ---

    [Fact]
    public async Task Create_Post_Staff_OverridesSubmittedDepartmentWithOwn()
    {
        // Staff(内科病棟)としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // フォームでは他部署(外科病棟)を選んで送信する
        var vm = ValidViewModel("外科病棟");

        // Create を実行する
        await _controller.Create(vm);

        // サーバ側で自部署(内科病棟)に上書きされて保存されることを確認する
        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("内科病棟", saved!.Department);
    }

    [Fact]
    public async Task Create_Post_StaffWithoutDepartmentClaim_ReturnsView_AndDoesNotSave()
    {
        // 所属部署クレームを持たない Staff としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Build(AppRoles.Staff));
        // 入力自体は妥当な ViewModel を送る
        var vm = ValidViewModel("内科病棟");

        // Create を実行する
        var result = await _controller.Create(vm);

        // 自部署を特定できないため再描画され、インシデントは保存されないことを確認する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Department)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_Admin_KeepsSubmittedDepartment()
    {
        // 既定の Admin(全件アクセス)のまま、他部署を指定して送信する
        var vm = ValidViewModel("外来");

        // Create を実行する
        await _controller.Create(vm);

        // Admin はフォームの部署がそのまま保存される(上書きされない)ことを確認する
        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("外来", saved!.Department);
    }

    [Fact]
    public async Task Create_Post_Admin_UnknownDepartment_ReturnsView_AndDoesNotSave()
    {
        // Admin が Incident.Departments の許可リストに無い文字列を送信する
        // (<select> をバイパスしたフォーム改ざんを想定。issue: Analytics 画面での XSS 対策)
        var vm = ValidViewModel("<script>alert(1)</script>");

        var result = await _controller.Create(vm);

        // 許可リスト外の値は拒否され、フォームを再描画する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Department)));
        // DB には保存されないことを確認する
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_Staff_DepartmentClaimNotInAllowList_StillSaves()
    {
        // Staff のクレームが Incident.Departments の許可リストと食い違っているケース
        // (部署名変更・タイポ等)を想定する。EnforceKnownDepartment は Admin/RiskManager の
        // フォーム改ざん対策であり、Staff の部署は EnforceOwnDepartmentForStaff により
        // 常にこの信頼できるクレーム値へ上書きされるため、許可リスト外でも本人が
        // ロックアウトされず登録できることを確認する。
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("旧・内科病棟"));
        var vm = ValidViewModel("内科病棟");

        var result = await _controller.Create(vm);

        Assert.IsType<RedirectToActionResult>(result);
        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("旧・内科病棟", saved!.Department);
    }

    [Fact]
    public async Task Edit_Post_Admin_UnknownDepartment_ReturnsView_AndDoesNotSave()
    {
        // 許可リストに載っている部署のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        var token = incident.ConcurrencyToken;

        // Admin が許可リスト外の文字列へ書き換えようとする
        var vm = ValidViewModel("<script>alert(1)</script>");
        vm.ConcurrencyToken = token;

        var result = await _controller.Edit(incident.Id, vm);

        // 許可リスト外の値は拒否され、フォームを再描画する
        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Null(viewResult.ViewName);
        Assert.False(_controller.ModelState.IsValid);
        // 部署が書き換わっていないことを確認する
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("内科病棟", reloaded!.Department);
    }

    [Fact]
    public async Task Edit_Post_Staff_CannotReassignDepartmentToAnother()
    {
        // 内科病棟のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Medication,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 楽観的同時実行制御用に現在のトークンを控える
        var token = incident.ConcurrencyToken;

        // Staff(内科病棟)としてログインする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // 編集フォームで部署を外科病棟へ付け替えようとする
        var vm = ValidViewModel("外科病棟");
        vm.ConcurrencyToken = token;

        // Edit を実行する
        await _controller.Edit(incident.Id, vm);

        // 部署が内科病棟のまま(他部署へ付け替えられない)ことを確認する
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("内科病棟", reloaded!.Department);
    }

    // --- Index GET / Filtering ---

    [Fact]
    public async Task Index_NoFilter_ReturnsAllIncidents()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(2, vm!.TotalCount);
    }

    [Fact]
    public async Task Index_DepartmentFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, "ICU", null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal("ICU", i.Department));
    }

    [Fact]
    public async Task Index_SeverityFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level4, Description = "A", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level0, Description = "B", ReporterName = "B", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, IncidentSeverity.Level4, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Equal(IncidentSeverity.Level4, vm.Incidents[0].Severity);
    }

    [Fact]
    public async Task Index_DateToMaxValueDate_DoesNotThrow_AndIncludesLastDay()
    {
        // 発生日が通常日と表現可能な最終日(9999-12-31)のインシデントを投入する
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "B", ReporterName = "B", OccurredAt = DateTime.MaxValue.Date }
        );
        await _db.SaveChangesAsync();

        // 以前は dateTo=9999-12-31 で Date.AddDays(1) が ArgumentOutOfRangeException(HTTP 500)
        // を投げていた。修正後は例外なく処理され、最終日の発生分も含めて返ることを確認する
        var result = await _controller.Index(null, null, null, null, null, DateTime.MaxValue.Date, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        // 2 件とも上限フィルタに含まれる(「その日いっぱいを含む」意味が保たれる)こと
        Assert.Equal(2, vm!.TotalCount);
    }

    [Fact]
    public async Task Index_SeveritySort_PaginationUsesIdTieBreaker_NoOverlapOrGap()
    {
        // 重症度がすべて同値のインシデントを 25 件投入する(PageSize=20 の 2 ページに跨る)。
        // severity 並び替えでは全行が同値となり、タイブレーカー(Id 降順)が無いと
        // ページングが非決定的になって重複・欠落が起きる。それを検証する。
        for (int i = 0; i < 25; i++)
        {
            // 全件同じ重症度・同じ発生日で追加し、severity ソートのキーを完全に同値にする
            _db.Incidents.Add(new Incident
            {
                Department = "ICU",
                IncidentType = IncidentTypeKind.Fall,
                Severity = IncidentSeverity.Level2,
                Description = $"case {i}",
                ReporterName = "R",
                OccurredAt = TestFixtures.Today
            });
        }
        await _db.SaveChangesAsync();

        // severity 並び替えで 1 ページ目(20 件)を取得する
        var page1 = (await _controller.Index(null, null, null, null, null, null, null, "severity", 1) as ViewResult)!
            .Model as IncidentListViewModel;
        // severity 並び替えで 2 ページ目(残り 5 件)を取得する
        var page2 = (await _controller.Index(null, null, null, null, null, null, null, "severity", 2) as ViewResult)!
            .Model as IncidentListViewModel;

        // 各ページの主キー Id を取り出す
        var page1Ids = page1!.Incidents.Select(x => x.Id).ToList();
        var page2Ids = page2!.Incidents.Select(x => x.Id).ToList();

        // 総件数 25 件が 20 + 5 に分割されることを確認する
        Assert.Equal(25, page1.TotalCount);
        Assert.Equal(20, page1Ids.Count);
        Assert.Equal(5, page2Ids.Count);
        // 1 ページ目が Id 降順(タイブレーカー)で並ぶこと。タイブレーカーが無ければ成立しない
        Assert.Equal(page1Ids.OrderByDescending(x => x).ToList(), page1Ids);
        // ページ間で重複が無いこと
        Assert.Empty(page1Ids.Intersect(page2Ids));
        // 2 ページ合わせて 25 件すべてを漏れなく網羅すること
        Assert.Equal(25, page1Ids.Concat(page2Ids).Distinct().Count());
    }

    [Theory]
    [InlineData(0)]              // ?page=0     : 補正しないと (0-1)*20 = 負の OFFSET
    [InlineData(-5)]            // ?page=-5    : 負数
    [InlineData(int.MaxValue)] // ?page=巨大 : (page-1)*20 が int 桁あふれで負値に化ける
    public async Task Index_OutOfRangePage_ClampsToFirstPageWithoutThrowing(int page)
    {
        // ページング境界(0・負数・巨大値)を投入する。
        // 補正しないと Skip((page-1)*PageSize) が負の OFFSET になり、
        // PostgreSQL / SQL Server では例外→500 になる(SQLite は 0 とみなすため見逃されやすい)。
        // ここではコントローラ側の Math.Clamp 補正で 1 ページ目にフォールバックすることを検証する。
        _db.Incidents.AddRange(
            // 3 件だけ投入し、総ページ数 1 の状態を作る
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level1, Description = "a", ReporterName = "R", OccurredAt = TestFixtures.Today },
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level1, Description = "b", ReporterName = "R", OccurredAt = TestFixtures.Today },
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Fall, Severity = IncidentSeverity.Level1, Description = "c", ReporterName = "R", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        // 範囲外のページ番号で一覧を要求する(例外を投げないこと自体が検証対象)
        var vm = (await _controller.Index(null, null, null, null, null, null, null, null, page) as ViewResult)!
            .Model as IncidentListViewModel;

        // 補正後のページ番号が 1(先頭ページ)であること
        Assert.Equal(1, vm!.Page);
        // 先頭ページに全 3 件が漏れなく載ること(負の OFFSET で欠落していない)
        Assert.Equal(3, vm.TotalCount);
        Assert.Equal(3, vm.Incidents.Count);
    }

    [Fact]
    public async Task Index_SearchFilter_MatchesDescription()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "点滴ラインが抜けた", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level1, Description = "薬を誤投与", ReporterName = "B", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("点滴", null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Contains("点滴", vm.Incidents[0].Description);
    }

    // 検索キーワードの大文字化が、サーバの OS ロケールに左右されないことを
    // 「コントローラ経由で」固定する。
    //
    // 正規化はヘルパ 1 箇所に集約してあるが、それだけでは「コントローラが実際に
    // そのヘルパを通っているか」は誰も見ていない(呼び出し側を素の ToUpper() へ戻すだけで
    // 元の不具合が復活する)。ここはその経路を押さえる。各コントローラが
    // 自分の呼び出し側を持つので、経路ごとに個別のテストを置く。
    //
    // 保存する状況説明を「あらかじめ大文字の ASCII」にしてあるのは、テストの InMemory
    // プロバイダには SQL が無く、式ツリーの col.ToUpper() が本番と違ってアプリ内で
    // 現在のカルチャに従って評価されるため。列の側を大文字のままにしておけば
    // トルコ語ロケールでも変化せず、判定対象をキーワード側の規則だけに絞れる
    // (この切り分けの根拠は IncidentControllerHelpers.NormalizeSearchKeyword の docstring「残る境界 2」を参照)。
    [Fact]
    public async Task Index_SearchUsesInvariantUpperCasing_NotServerLocale()
    {
        // 現在のスレッドのカルチャをトルコ語へ差し替える。前提（この環境で実際に
        // 大文字化の規則が変わること）の確認と、抜けるときの復元はヘルパーが担う
        using (LocaleSensitiveTest.UseTurkishCulture())
        {
            // 状況説明に大文字 ASCII を含むインシデントを 1 件用意する
            _db.Incidents.Add(new Incident
            {
                Department = "ICU",
                IncidentType = IncidentTypeKind.Medication,
                Severity = IncidentSeverity.Level2,
                Description = "INCIDENT: 点滴ラインが抜けた",
                ReporterName = "A",
                OccurredAt = TestFixtures.Today
            });
            await _db.SaveChangesAsync();

            // 小文字のキーワードで検索する。素の ToUpper() だと "İNCİDENT"(U+0130)になり
            // 列側の "INCIDENT" に一致しなくなる
            var result = await _controller.Index("incident", null, null, null, null, null, null, null, 1) as ViewResult;
            var vm = result?.Model as IncidentListViewModel;

            // ロケールに関わらず 1 件ヒットすること
            Assert.Equal(1, vm!.TotalCount);
        }
    }

    // 空白のみのフリーワード検索は「絞り込み無し」として扱われることを固定する(issue #187)。
    // 3 画面(インシデント一覧 / カンバン / 監査ログ)で空判定を SearchFilter.HasValue へ
    // 揃えた際の回帰テスト。この画面は元から IsNullOrWhiteSpace だったため挙動は変わらないが、
    // 判定を共有ヘルパーへ移したあとも規則が維持されていることをここで押さえる
    // (押さえないと、共有側の規則を IsNullOrEmpty へ緩めても 3 画面のうち
    //  カンバンのテストだけが落ち、この画面の退行は誰にも見えない)。
    [Theory]
    [InlineData(" ")]           // 半角スペース 1 つ
    [InlineData("   ")]         // 半角スペース複数
    [InlineData("\t")]          // タブ
    [InlineData("　")]          // 全角スペース
    public async Task Index_WhitespaceOnlySearch_IsTreatedAsNoFilter(string blankInput)
    {
        // 日本語の状況説明を持つインシデントを 1 件用意する(空白では絶対に部分一致しない)
        _db.Incidents.Add(new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "転倒しそうになった",
            ReporterName = "看護師A",
            OccurredAt = TestFixtures.Today
        });
        await _db.SaveChangesAsync();

        // 空白のみのキーワードで検索する
        var result = await _controller.Index(blankInput, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        // 絞り込みは走らず、全件がそのまま返ること
        Assert.Equal(1, vm!.TotalCount);
    }

    // --- Details GET ---

    [Fact]
    public async Task Details_ExistingId_ReturnsViewWithIncident()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "廊下で転倒",
            ReporterName = "山田",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(incident.Id) as ViewResult;
        var vm = result?.Model as IncidentDetailViewModel;

        Assert.NotNull(vm);
        Assert.Equal(incident.Id, vm.Incident.Id);
    }

    [Fact]
    public async Task Details_NonExistentId_ReturnsNotFound()
    {
        var result = await _controller.Details(9999);
        Assert.IsType<NotFoundResult>(result);
    }

    // --- Authorization: Staff scope ---

    [Fact]
    public async Task Index_Staff_OnlySeesOwnDepartment()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "内科病棟", IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "A", ReporterName = "A", OccurredAt = TestFixtures.Today },
            new Incident { Department = "外来",     IncidentType = IncidentTypeKind.Medication, Severity = IncidentSeverity.Level2, Description = "B", ReporterName = "B", OccurredAt = TestFixtures.Today }
        );
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal("内科病棟", i.Department));
    }

    [Fact]
    public async Task Details_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Details(incident.Id);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Edit_Get_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Edit(incident.Id);

        Assert.IsType<ForbidResult>(result);
    }

    [Fact]
    public async Task Edit_Post_Staff_OtherDepartment_ReturnsForbid()
    {
        // 外来(他部署)のインシデントを 1 件用意する
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "編集前",
            ReporterName = "他部署担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        // 楽観的同時実行制御用に現在のトークンを控える
        var token = incident.ConcurrencyToken;

        // Staff(内科病棟)として、他部署(外来)のインシデントを編集しようとする
        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        // 編集フォームを用意する(自部署を送っても、そもそも編集権限が無いはず)
        var vm = ValidViewModel("内科病棟");
        vm.ConcurrencyToken = token;

        // Edit(POST) を実行する
        var result = await _controller.Edit(incident.Id, vm);

        // 他部署のインシデントは部署スコープ認可で弾かれ ForbidResult になる
        // (部署上書きより前に認可で拒否されることの確認 = IDOR 防止)
        Assert.IsType<ForbidResult>(result);
        // インシデントの内容が一切変更されていないことを確認する
        var reloaded = await _db.Incidents.FindAsync(incident.Id);
        Assert.Equal("編集前", reloaded!.Description);
        Assert.Equal("外来", reloaded.Department);
    }

    [Fact]
    public async Task Delete_Staff_OtherDepartment_ReturnsForbid()
    {
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署",
            ReporterName = "他部署担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Delete(incident.Id, incident.ConcurrencyToken);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
    }

    [Fact]
    public async Task Delete_NotFound_ReturnsNotFound()
    {
        var result = await _controller.Delete(99999, Guid.NewGuid());
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Admin_RemovesIncident()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "削除対象",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var result = await _controller.Delete(incident.Id, incident.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Index), redirect.ActionName);
        Assert.False(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
        Assert.NotNull(_controller.TempData["Success"]);
    }

    [Fact]
    public async Task Delete_RiskManager_RemovesIncident_RegardlessOfDepartment()
    {
        // RiskManager は全部署横断で削除できる (Policies.CanDeleteIncident)。
        var incident = new Incident
        {
            Department = "外来",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "他部署の削除対象",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.RiskManager());
        var result = await _controller.Delete(incident.Id, incident.ConcurrencyToken);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(IncidentsController.Index), redirect.ActionName);
        Assert.False(await _db.Incidents.AnyAsync(i => i.Id == incident.Id));
    }

    [Fact]
    public async Task Edit_Get_Staff_SameDepartment_ReturnsView()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "同部署",
            ReporterName = "担当",
            OccurredAt = TestFixtures.Today
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Edit(incident.Id);

        Assert.IsType<ViewResult>(result);
    }
}
