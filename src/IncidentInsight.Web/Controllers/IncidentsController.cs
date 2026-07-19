// 部署スコープ拡張メソッド(ScopedByUser)を使う
using IncidentInsight.Web.Authorization;
// 共通ヘルパ(原因カテゴリ一覧 / 認可判定)を使う
using IncidentInsight.Web.Controllers.Internal;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル(Incident / CauseAnalysis など)を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別など)を使う
using IncidentInsight.Web.Models.Enums;
// フォーム用 ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// 時刻源 / 再発サービスを使う
using IncidentInsight.Web.Services;
// 認可 API(IAuthorizationService)を使う
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底を使う
using Microsoft.AspNetCore.Mvc;
// SelectListItem / SelectListGroup(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張を使う
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// インシデントの登録・編集・削除を担当するコントローラ。
// 原因分析(なぜなぜ)のネスト操作は CauseAnalysesController、
// 対策追加・完了・有効性評価は IncidentMeasuresController が担う。
[Authorize]
public class IncidentsController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // リソース認可評価用サービス
    private readonly IAuthorizationService _auth;
    // 再発検出サービス(同部署×同種別×原因カテゴリ一致)
    private readonly IRecurrenceService _recurrence;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;
    // ログ出力用(同時編集衝突などの警告)
    private readonly ILogger<IncidentsController> _logger;
    // 一覧の 1 ページあたりの件数
    private const int PageSize = 20;
    // Create 登録画面で対策の実施期限の初期値として使う日数（今日から30日後）。
    // Views/Incidents/Create.cshtml も既定値の唯一の源としてこの定数を参照するため public にしている
    public const int DefaultMeasureDueDays = 30;

    // コンストラクタ: DI で依存を受け取る
    public IncidentsController(
        ApplicationDbContext db,
        IAuthorizationService auth,
        IRecurrenceService recurrence,
        IClock clock,
        ILogger<IncidentsController> logger)
    {
        _db = db;
        _auth = auth;
        _recurrence = recurrence;
        _clock = clock;
        _logger = logger;
    }

    // GET /Incidents
    // 一覧画面。検索・絞り込み・並び替え・ページングを行う
    public async Task<IActionResult> Index(string? search, string? department,
        IncidentTypeKind? incidentType, IncidentSeverity? severity, DateTime? dateFrom, DateTime? dateTo,
        int? causeCategoryId, string? sortBy, int page = 1)
    {
        // 関連(対策・原因分析)込みで、ユーザー部署スコープに絞ったクエリを用意
        var query = _db.Incidents
            .Include(i => i.PreventiveMeasures)
            .Include(i => i.CauseAnalyses)
            .AsNoTracking()
            .ScopedByUser(User);

        // フリーワード検索(状況または報告者名を部分一致)
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(i => i.Description.Contains(search) || i.ReporterName.Contains(search));
        // 部署で絞り込み
        if (!string.IsNullOrWhiteSpace(department))
            query = query.Where(i => i.Department == department);
        // インシデント種別で絞り込み
        if (incidentType.HasValue)
            query = query.Where(i => i.IncidentType == incidentType.Value);
        // 重症度で絞り込み
        if (severity.HasValue)
            query = query.Where(i => i.Severity == severity.Value);
        // 発生日下限で絞り込み
        if (dateFrom.HasValue)
            query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 発生日上限で絞り込み(当日を含める)
        // 時刻成分を .Date で切り落としてから翌日 0 時より前までを対象にする。
        // これで「その日いっぱいを含む」上限の意味が他コントローラ(Analytics/AuditLogs 等)と一致する。
        if (dateTo.HasValue)
            query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));
        // 原因カテゴリで絞り込み(親カテゴリ指定時は子カテゴリも拾う)
        if (causeCategoryId.HasValue)
            query = query.Where(i => i.CauseAnalyses.Any(ca =>
                ca.CauseCategoryId == causeCategoryId.Value ||
                ca.CauseCategory.ParentId == causeCategoryId.Value));

        // Sort
        // 並び替え: severity=重症度降順、overdue=期限超過あり優先、既定=発生日の新しい順
        // どの並び順も末尾に主キー Id 降順のタイブレーカーを付ける。
        // 理由: 重症度(7値)や期限超過フラグ(真偽2値)は同値の行が大量に発生し、DB は
        // 同値行の並び順を保証しない。タイブレーカーが無いと Skip/Take のページングが
        // 非決定的になり、同じ行が複数ページに出たり抜け落ちたりする(AuditLogsController と同じ対策)。
        query = sortBy switch
        {
            "severity" => query.OrderByDescending(i => i.Severity).ThenByDescending(i => i.Id),
            "overdue"  => query.OrderByDescending(i => i.PreventiveMeasures
                              .Any(m => m.Status != MeasureStatus.Completed && m.DueDate < _clock.Today))
                              .ThenByDescending(i => i.Id),
            _          => query.OrderByDescending(i => i.OccurredAt).ThenByDescending(i => i.Id)
        };

        // 総件数(ページング計算用)
        var total = await query.CountAsync();
        // ページ番号を有効範囲[1..総ページ数]に補正する(URL 改ざん・桁あふれ対策)。
        // 補正しないと ?page=0 や負数で (page-1)*PageSize が負の OFFSET になり、
        // また巨大値では (page-1)*PageSize が int の範囲を超えて桁あふれ(オーバーフロー)で
        // 負値に化ける。SQLite は負の OFFSET を 0 とみなすが、PostgreSQL / SQL Server は
        // 例外を投げて 500 になるため、DB プロバイダ非依存の不変条件を守るためにここで丸める。
        var totalPages = (int)Math.Ceiling(total / (double)PageSize);
        page = Math.Clamp(page, 1, Math.Max(1, totalPages));
        // 現在ページ分のレコードだけ取得
        var incidents = await query
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        // Build cause category options (parent categories only)
        // 原因カテゴリの絞り込みドロップダウン用に親カテゴリのみ取得
        var parentCats = await _db.CauseCategories
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            .ToListAsync();

        // ビューに渡す ViewModel を組み立てる
        var vm = new IncidentListViewModel
        {
            Incidents = incidents,
            TotalCount = total,
            Page = page,
            PageSize = PageSize,
            Search = search,
            Department = department,
            IncidentType = incidentType,
            Severity = severity,
            DateFrom = dateFrom,
            DateTo = dateTo,
            CauseCategoryId = causeCategoryId,
            SortBy = sortBy,
            CauseCategoryOptions = parentCats
                .Select(c => new SelectListItem(c.Name, c.Id.ToString()))
                .ToList()
        };

        // 一覧ビューへ ViewModel を渡して描画
        return View(vm);
    }

    // GET /Incidents/Details/5
    // 詳細画面。原因分析・対策・類似インシデントを併せて表示
    public async Task<IActionResult> Details(int id)
    {
        // 画面用 ViewModel の組み立ては IncidentMeasuresController.AddMeasure /
        // CauseAnalysesController.AddCauseAnalysis がバリデーション失敗時にこの画面を
        // 再描画する場合とも共有するヘルパーに集約する(CLAUDE.md §6 DRY)。
        // NewCauseAnalysis/NewMeasure は override 未指定のため通常どおり空の ViewModel になる。
        var vm = await IncidentControllerHelpers.BuildIncidentDetailViewModelAsync(_db, _recurrence, _clock, id);

        // レコードが無ければ 404
        if (vm == null) return NotFound();
        // 閲覧権限がなければ 403
        if (!await IsAuthorizedFor(vm.Incident, Policies.CanViewIncident)) return Forbid();

        // 詳細ビューを描画
        return View(vm);
    }

    // GET /Incidents/Create
    // 登録画面の初期表示
    public async Task<IActionResult> Create()
    {
        // IClock から現在時刻を取得する(DateTime.Now を ViewModel 内で使わないための委譲)
        var now = _clock.Now;
        // 発生日時と対策の実施期限の既定値をクロックから設定して空の ViewModel を用意
        var vm = new IncidentCreateEditViewModel
        {
            // 発生日時の初期値: 現在時刻(JST ベースの IClock 経由)
            OccurredAt = now,
            // 種別・重症度の初期選択値(ViewModel を nullable 化したため GET 側で設定する)
            IncidentType = IncidentTypeKind.Other,   // 種別の初期選択は「その他」
            Severity = IncidentSeverity.Level0,      // 重症度の初期選択は「レベル0」
            // 対策リストの最初の行: 実施期限を30日後・種別を短期対策に設定する
            Measures = new List<MeasureFormViewModel>
            {
                new MeasureFormViewModel
                {
                    DueDate = now.AddDays(DefaultMeasureDueDays),      // 期限の初期値: 30日後
                    MeasureType = MeasureTypeKind.ShortTerm            // 種別の初期選択: 短期対策
                }
            },
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        // 登録フォームを描画
        return View(vm);
    }

    // POST /Incidents/Create
    // 登録フォーム送信を受けてインシデント・原因分析・対策をまとめて保存
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(IncidentCreateEditViewModel vm)
    {
        // なぜなぜ分析サブフォーム由来の ModelState キーを除外する。
        // Why2–5 などの任意項目やドロップダウン選択肢(CauseCategoryOptions)が
        // 未送信のときに残る不要な Required エラーを取り除く。原因分析は
        // CauseCategoryId と Why1 が揃ったときだけ保存するため、ここで一括除外してよい。
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith("CauseAnalysis."))
            .ToList())
        {
            // 原因分析サブフォーム由来の各キーを ModelState から除去する
            ModelState.Remove(key);
        }

        // 対策サブフォームの ModelState は「行ごと」に整理する。
        // Edit POST は対策を永続化しないため Measures[*] を一括削除して問題ないが、
        // Create POST は下の Where(Description 非空)で残った対策行を実際に保存する。
        // そのため一括削除はせず、保存されない空行(対策内容が未入力の行)だけ
        // Required エラーを取り除き、保存される行(対策内容あり)の担当者・担当部署・
        // 実施期限などのフィールド検証は残してデータ整合性を守る。
        // (一括削除すると DueDate=default(0001-01-01) のまま保存され IsOverdue が
        //  常に true になる等の不正データを生む。)
        for (int i = 0; vm.Measures != null && i < vm.Measures.Count; i++)
        {
            // この行が保存対象か(対策内容が入力されているか)を判定する
            if (!string.IsNullOrWhiteSpace(vm.Measures[i].Description))
                // 保存される行はフィールド検証を残すのでスキップ
                continue;

            // 保存されない空行のキー(Measures[i].*)だけをまとめて除去する。
            // 末尾に "]." まで含めてプレフィックス照合する。"Measures[1]" のように
            // 角括弧で止めると "Measures[10]." 等の別の行にも誤一致してしまうため。
            var rowPrefix = $"Measures[{i}].";
            foreach (var key in ModelState.Keys.Where(k => k.StartsWith(rowPrefix)).ToList())
            {
                // 空行由来の各キーを ModelState から除去する
                ModelState.Remove(key);
            }
        }

        // 部署スコープを強制する: Staff は自分の所属部署にしか登録できない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

        // 発生部署が許可リスト外の値でないか検証する(Admin/RiskManager のフォーム改ざん対策)
        EnforceKnownDepartment(vm);

        // 業務ルール: 再発防止策が1件も無ければ登録不可
        if (!HasAtLeastOneValidMeasure(vm.Measures))
            ModelState.AddModelError(nameof(vm.Measures), "再発防止策を1件以上入力してください。");

        // 原因分析タブが「一部だけ」入力されている場合は入力不備として通知する。
        // 原因分析は CauseCategoryId と Why1 が揃ったときだけ保存する仕様のため、
        // ここで検知しないと、なぜ1〜5 を書き込んだのに原因分類を選び忘れただけで
        // 「登録しました」の成功トーストとともに分析テキストが無言で全破棄されてしまう
        // (利用者が気づけないデータ消失)。判定条件は ViewModel の計算プロパティに一元化。
        // エラーキーはフォームのフィールド名(CauseAnalysis.〜)に合わせる。文字列直書きだと
        // プロパティ改名時に黙ってエラー表示が外れるため nameof で組み立てる(§6)
        if (vm.CauseAnalysis.HasAnyInput && !vm.CauseAnalysis.IsSavable)
        {
            // 原因分類が未選択ならその旨を通知
            if (vm.CauseAnalysis.CauseCategoryId <= 0)
                ModelState.AddModelError(
                    $"{nameof(vm.CauseAnalysis)}.{nameof(vm.CauseAnalysis.CauseCategoryId)}",
                    "原因分析を登録するには原因分類を選択してください（分析を登録しない場合は分析欄をすべて空にしてください）。");
            // なぜ1 が未入力ならその旨を通知
            if (string.IsNullOrWhiteSpace(vm.CauseAnalysis.Why1))
                ModelState.AddModelError(
                    $"{nameof(vm.CauseAnalysis)}.{nameof(vm.CauseAnalysis.Why1)}",
                    "原因分析を登録するにはなぜ1を入力してください（分析を登録しない場合は分析欄をすべて空にしてください）。");
        }

        // 原因分析を保存する場合のみ、選択された原因カテゴリが実在するか検証する。
        // CauseAnalysis.* の ModelState は上で一括除外しているため、ここで外部キーの存在を
        // 明示確認しないと、存在しない CauseCategoryId が来たとき下の INSERT が失敗し、
        // トランザクション全体が未捕捉の DbUpdateException(=HTTP 500)になって入力が全消失する。
        // 事前に検証してフォームを再描画する(§9 入力は信用しない / fail-closed)。
        if (vm.CauseAnalysis.IsSavable
            && !await IncidentControllerHelpers.CauseCategoryExistsAsync(_db, vm.CauseAnalysis.CauseCategoryId))
        {
            // 存在しないカテゴリが選ばれた場合は入力不備として扱う(キーは nameof で組み立てる)
            ModelState.AddModelError(
                $"{nameof(vm.CauseAnalysis)}.{nameof(vm.CauseAnalysis.CauseCategoryId)}",
                "選択された原因カテゴリが存在しません。");
        }

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            // POST ボディに Measures[] フィールドが一つも無い場合 vm.Measures が null になるため
            // null 合体代入で空リストを保証し、View 側の foreach で NullReferenceException を防ぐ
            vm.Measures ??= new List<MeasureFormViewModel>();
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        // ここに到達する時点では HasAtLeastOneValidMeasure(vm.Measures) が true であることが
        // 保証されている(false なら直前の ModelState.IsValid チェックで return 済み)ため、
        // 実行時には vm.Measures は null にならない。ただしその保証は
        // HasAtLeastOneValidMeasure 側の実装に暗黙に依存しており、コンパイラの null 許容参照型
        // 解析はメソッド境界をまたいでこの関係を追えず CS8604 を報告する。将来
        // HasAtLeastOneValidMeasure の実装が変わってこの前提が崩れても NullReferenceException で
        // 落ちないよう、ここで明示的に空リストへフォールバックしておく(§9 失敗しても安全側に倒す)。
        vm.Measures ??= new List<MeasureFormViewModel>();

        // Incident と関連エンティティを単一トランザクションで保存する。
        // トランザクションがないと、Incident は保存されたが対策がまだ保存されていない
        // 中間状態が生じ、「最低1件の対策が必要」という業務ルールが DB 上で破れる。
        await using var transaction = await _db.Database.BeginTransactionAsync();

        // 登録時刻を一度だけ取得する。ReportedAt と AnalyzedAt に同じ時刻を使うため、
        // _clock.Now を 2 回以上呼ぶと微妙にズレる可能性があるので単一変数に束縛する。
        var now = _clock.Now;

        // 入力値から新しい Incident を作成
        var incident = new Incident
        {
            // ModelState.IsValid 通過後は [Required] により null にならないため .Value で取り出す
            OccurredAt = vm.OccurredAt!.Value,
            Department = vm.Department,
            // 種別・重症度も同様に IsValid 通過後は null にならない
            IncidentType = vm.IncidentType!.Value,
            Severity = vm.Severity!.Value,
            Description = vm.Description,
            ImmediateActions = vm.ImmediateActions,
            ReporterName = vm.ReporterName,
            ReportedAt = now
        };

        // ChangeTracker に追加して Id を採番するため一旦保存(まだコミットしない)
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        // Save cause analysis
        // 保存可能な組(原因分類 + なぜ1)が揃っていれば原因分析を保存
        // (判定は ViewModel の IsSavable に一元化。部分入力は上の検証で弾かれここには到達しない)
        if (vm.CauseAnalysis.IsSavable)
        {
            // 入力値から CauseAnalysis を組み立てる
            var analysis = new CauseAnalysis
            {
                IncidentId = incident.Id,
                CauseCategoryId = vm.CauseAnalysis.CauseCategoryId,
                Why1 = vm.CauseAnalysis.Why1,
                Why2 = vm.CauseAnalysis.Why2,
                Why3 = vm.CauseAnalysis.Why3,
                Why4 = vm.CauseAnalysis.Why4,
                Why5 = vm.CauseAnalysis.Why5,
                RootCauseSummary = vm.CauseAnalysis.RootCauseSummary,
                AnalystName = vm.CauseAnalysis.AnalystName,
                AnalyzedAt = now,
                AdditionalNotes = vm.CauseAnalysis.AdditionalNotes
            };
            // ChangeTracker に追加(実 INSERT は下の SaveChanges で)
            _db.CauseAnalyses.Add(analysis);
        }

        // Save measures
        // 内容が空でない対策のみ保存
        foreach (var m in vm.Measures.Where(m => !string.IsNullOrWhiteSpace(m.Description)))
        {
            // 新しい PreventiveMeasure を ChangeTracker に追加
            _db.PreventiveMeasures.Add(new PreventiveMeasure
            {
                IncidentId = incident.Id,
                Description = m.Description,
                MeasureType = m.MeasureType!.Value,
                ResponsiblePerson = m.ResponsiblePerson,
                ResponsibleDepartment = m.ResponsibleDepartment,
                // 保存対象行(Description 非空)は ModelState 検証が残っているため、
                // IsValid 通過後は [Required] により null にならず .Value で取り出せる
                DueDate = m.DueDate!.Value,
                Priority = m.Priority,
                AnalysisNote = m.AnalysisNote,
                Status = MeasureStatus.Planned
            });
        }

        // 原因分析+対策をまとめて DB に反映
        await _db.SaveChangesAsync();

        // すべて正常に保存できたのでトランザクションをコミットする
        await transaction.CommitAsync();

        // 成功通知をセット(画面上のトースト表示用)
        TempData["Success"] = "インシデントを登録しました。";
        // 詳細画面にリダイレクト
        return RedirectToAction(nameof(Details), new { id = incident.Id });
    }

    // 「少なくとも1件の有効な対策が入力されているか」を判定するヘルパー
    private static bool HasAtLeastOneValidMeasure(IEnumerable<MeasureFormViewModel>? measures)
        => measures?.Any(m => !string.IsNullOrWhiteSpace(m.Description)) == true;

    // Staff(全件アクセス権を持たない役割)が登録・編集するインシデントの部署を、
    // フォーム入力ではなく本人の所属部署クレームに固定する(issue #63)。
    // 画面で他部署を選んでもサーバ側で上書きするため、他部署のキュー・ダッシュボード・
    // 再発統計への誤投入やなりすまし、編集での部署付け替えを防ぐ。閲覧側の
    // DepartmentScope.ScopedByUser と同じ判定(Admin/RiskManager は全件)で整合させる。
    private void EnforceOwnDepartmentForStaff(IncidentCreateEditViewModel vm)
    {
        // Admin / RiskManager は全部署を扱えるので、フォームの値をそのまま使う
        if (User.IsInRole(AppRoles.Admin) || User.IsInRole(AppRoles.RiskManager))
            return;

        // ログインユーザー(Staff)の所属部署クレームを取り出す
        var ownDepartment = User.FindFirst(AppClaimTypes.Department)?.Value;

        // 所属部署が未設定の Staff は自部署を特定できないので操作を拒否する(fail-closed)
        if (string.IsNullOrWhiteSpace(ownDepartment))
        {
            // 入力画面に戻すためのエラーを積む(Department 欄に紐づける)
            ModelState.AddModelError(
                nameof(vm.Department),
                "所属部署が設定されていないため、この操作は行えません。管理者に連絡してください。");
            return;
        }

        // フォームの値を無視し、必ず本人の所属部署に固定する(他部署への投入/付け替え防止)
        vm.Department = ownDepartment;

        // model binding が先に「Department が空」と判定した [Required] エラーを取り除く。
        // この時点では vm.Department に正しい値を設定済みなのでエラーは無効となる。
        // これを除去しないと ModelState.IsValid が false のままになり、
        // Staff がフォームを送信しても常にバリデーションエラーになってしまう(issue #63)。
        ModelState.Remove(nameof(vm.Department));
    }

    // 発生部署が Incident.Departments(唯一の真実の源)の許可リストに含まれているか検証する。
    // Create/Edit 画面の <select> はこの配列だけを選択肢として描画するが、Admin/RiskManager は
    // EnforceOwnDepartmentForStaff で上書きされずフォームの値がそのまま使われるため、
    // フォーム改ざん(未定義文字列の直接 POST)をサーバ側で拒否しないと、任意の文字列が
    // Department として保存されてしまう(IncidentType/Severity の EnumDataType 検証と同じ
    // fail-closed の考え方。§9 入力は信用しない)。
    // Staff はこの検証の対象外: vm.Department は EnforceOwnDepartmentForStaff によって
    // 常に本人のクレーム値(ユーザーが直接入力できない、管理者管理下の信頼できる値)へ
    // 上書きされるため、フォーム改ざんの経路が存在しない。もし対象にすると、クレームの
    // 値が(部署名変更やタイポで)許可リストと一時的に食い違っただけで本人が復旧できない
    // ままロックアウトされてしまう。
    private void EnforceKnownDepartment(IncidentCreateEditViewModel vm)
    {
        // Admin/RiskManager 以外(=Staff)はフォーム改ざんの経路が無いため検証をスキップする
        if (!User.IsInRole(AppRoles.Admin) && !User.IsInRole(AppRoles.RiskManager))
            return;

        // 許可リストに含まれない値なら不正入力としてエラーを積む
        if (!Incident.Departments.Contains(vm.Department))
        {
            ModelState.AddModelError(nameof(vm.Department), "部署の値が不正です。");
        }
    }

    // GET /Incidents/Edit/5
    // 編集画面の初期表示
    public async Task<IActionResult> Edit(int id)
    {
        // 指定 ID のインシデントを取得
        var incident = await _db.Incidents.FindAsync(id);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // 編集フォーム用 ViewModel に現在値と同時実行トークンを詰める
        var vm = new IncidentCreateEditViewModel
        {
            Id = incident.Id,
            ConcurrencyToken = incident.ConcurrencyToken,
            OccurredAt = incident.OccurredAt,
            Department = incident.Department,
            IncidentType = incident.IncidentType,
            Severity = incident.Severity,
            Description = incident.Description,
            ImmediateActions = incident.ImmediateActions,
            ReporterName = incident.ReporterName,
            CauseCategoryOptions = await BuildCauseCategoryOptions()
        };
        // 編集ビューを描画
        return View(vm);
    }

    // POST /Incidents/Edit/5
    // 編集フォーム送信を受けて Incident 本体を更新
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(int id, IncidentCreateEditViewModel vm)
    {
        // 対象エンティティを再取得
        var incident = await _db.Incidents.FindAsync(id);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 編集権限がなければ 403
        if (!await IsAuthorizedFor(incident, Policies.CanEditIncident)) return Forbid();

        // Remove sub-form keys from ModelState
        // 原因分析・対策のサブフォーム由来の ModelState キーをまとめて除外
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith("CauseAnalysis.") || k.StartsWith("Measures["))
            .ToList())
        {
            ModelState.Remove(key);
        }

        // 部署スコープを強制する: Staff は自部署のインシデントしか編集できず、
        // 他部署への付け替えもできない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

        // 発生部署が許可リスト外の値でないか検証する(Admin/RiskManager のフォーム改ざん対策)
        EnforceKnownDepartment(vm);

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            return View(vm);
        }

        // 入力値を本体に反映
        // ModelState.IsValid 通過後は [Required] により null にならないため .Value で取り出す
        incident.OccurredAt = vm.OccurredAt!.Value;
        incident.Department = vm.Department;
        // 種別・重症度も IsValid 通過後は [Required] により null にならない
        incident.IncidentType = vm.IncidentType!.Value;
        incident.Severity = vm.Severity!.Value;
        incident.Description = vm.Description;
        incident.ImmediateActions = vm.ImmediateActions;
        incident.ReporterName = vm.ReporterName;

        // 楽観的同時実行制御: クライアントが編集開始時点で保持していたトークンを
        // OriginalValue に適用する。DB の現在値と一致しない場合に
        // DbUpdateConcurrencyException が投げられる。
        _db.Entry(incident).Property(nameof(Incident.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;

        // 保存試行(この時点で衝突があれば DbUpdateConcurrencyException を捕捉してログに残す共通処理)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict updating Incident {IncidentId}", id))
        {
            // 衝突発生: ユーザーに再読み込みを促す
            TempData["Warning"] = "他のユーザが先に更新したため、変更は保存されませんでした。最新の内容を読み直してから再度編集してください。";
            return RedirectToAction(nameof(Edit), new { id });
        }
        // 成功通知
        TempData["Success"] = "インシデントを更新しました。";
        // 詳細画面へリダイレクト
        return RedirectToAction(nameof(Details), new { id });
    }

    // POST /Incidents/Delete/5
    // インシデント削除(管理者/リスクマネージャー限定)
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Policy = Policies.CanDeleteIncident)]
    public async Task<IActionResult> Delete(int id, Guid concurrencyToken)
    {
        // 子(CauseAnalysis / PreventiveMeasure)を Include して ChangeTracker に載せておく。
        // OnDelete(Cascade) は DB 側でも子行を消すが、それだけだと AuditSaveChangesInterceptor が
        // 子の Deleted エントリを拾えず、監査ログから抜け落ちる。
        var incident = await _db.Incidents
            .Include(i => i.CauseAnalyses)
            .Include(i => i.PreventiveMeasures)
            .FirstOrDefaultAsync(i => i.Id == id);
        // 無ければ 404
        if (incident == null) return NotFound();
        // 削除権限がなければ 403(部署スコープも考慮)
        if (!await IsAuthorizedFor(incident, Policies.CanDeleteIncident)) return Forbid();

        // 同時編集検知のトークン固定(画面表示後に他ユーザーが更新した内容を
        // 気づかず削除してしまわないよう、クライアントが保持していた表示時点の
        // トークンを DB の現在値と突き合わせる)
        _db.Entry(incident).Property(nameof(Incident.ConcurrencyToken)).OriginalValue = concurrencyToken;

        // 削除マークを付けて DB へ反映(子エンティティも監査対象になる)
        _db.Incidents.Remove(incident);
        // 保存試行(この時点で他ユーザーの更新と衝突していれば共通処理がログを残す)
        if (!await IncidentControllerHelpers.TrySaveChangesHandlingConcurrencyAsync(
                _db, _logger, "Concurrency conflict deleting Incident {IncidentId}", id))
        {
            // 衝突発生: ユーザーに再読み込みを促す
            TempData["Warning"] = "他のユーザが先に更新したため、削除できませんでした。最新の内容を確認してから再度お試しください。";
            return RedirectToAction(nameof(Details), new { id });
        }
        // 成功通知
        TempData["Success"] = "インシデントを削除しました。";
        // 一覧へリダイレクト
        return RedirectToAction(nameof(Index));
    }

    // リソース(Incident)に対する Policy 評価をヘルパに委譲する小ラッパ。
    // 既存の呼び出し箇所(Details / Edit / Delete)から使うためインスタンスメソッドのまま残す。
    private Task<bool> IsAuthorizedFor(Incident? incident, string policy)
        => IncidentControllerHelpers.IsAuthorizedForAsync(_auth, User, incident, policy);

    // 原因カテゴリのドロップダウン用にヘルパへ委譲する小ラッパ
    private Task<List<SelectListItem>> BuildCauseCategoryOptions()
        => IncidentControllerHelpers.BuildCauseCategoryOptionsAsync(_db);
}
