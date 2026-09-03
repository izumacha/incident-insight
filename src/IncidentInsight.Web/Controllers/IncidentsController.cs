// DataAnnotations 属性の手動再検証(Validator / ValidationContext / ValidationResult)を使う
using System.ComponentModel.DataAnnotations;
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
// 絞り込み入力の「空かどうか」の唯一の真実の源(SearchFilter)を使う
using IncidentInsight.Web.Models.Validation;
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
        // 関連(対策)込みで、ユーザー部署スコープに絞ったクエリを用意。
        // CauseAnalyses は Include しない: 一覧ビュー(Views/Incidents/Index.cshtml)は
        // PreventiveMeasures しか参照せず、下の causeCategoryId 絞り込みも
        // Where(...Any(...)) が SQL の EXISTS に翻訳されるため Include を必要としない(§8 N+1/過剰取得の回避)
        var query = _db.Incidents
            .Include(i => i.PreventiveMeasures)
            .AsNoTracking()
            .ScopedByUser(User);

        // フリーワード検索(状況または報告者名を部分一致・大文字小文字を区別しない)
        // 「入力が空か」の判定は SearchFilter.HasValue に集約してある(空白のみは絞り込み無し)。
        // 大文字化の規則と「なぜ両辺を大文字化するのか / なぜ不変規則なのか」は
        // IncidentControllerHelpers.NormalizeSearchKeyword に集約してある
        if (SearchFilter.HasValue(search))
        {
            var normalizedSearch = IncidentControllerHelpers.NormalizeSearchKeyword(search);
            query = query.Where(i => i.Description.ToUpper().Contains(normalizedSearch) || i.ReporterName.ToUpper().Contains(normalizedSearch));
        }
        // 部署で絞り込み。「空白のみか」に加えて「ドロップダウンが表せる値か」まで決めるので、
        // 判定とドロップダウンの選択肢づくりを ResolveDepartmentFilterAsync にまとめてある
        // (許可リストから外れた過去の部署名は選択肢へ補完し、実データに無い値は採用しない。
        //  どちらを選ぶかの規則と理由は SearchFilter の解説に集約。issue #192)
        var departmentFilter = await ResolveDepartmentFilterAsync(department);
        // 採用した値だけを絞り込みに使う(採用しなかった場合は null なのでこの節を飛ばす)
        if (departmentFilter.Effective != null)
            query = query.Where(i => i.Department == departmentFilter.Effective);
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
        // 「その日いっぱいを含む」排他的上限(翌日 0 時)は共通ヘルパで安全に計算する。
        // 9999-12-31 のような極端な値でも AddDays(1) の桁あふれで 500 にならない(§9 fail-safe)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(i => i.OccurredAt < dateToExclusive);
        }
        // 原因分類で絞り込み。部署と同じく「ドロップダウンが表せる値か」まで決めるので、
        // 判定と選択肢づくりを ResolveCauseCategoryFilterAsync にまとめてある
        // (選択肢は親カテゴリだけで作る一方、絞り込みは子カテゴリの id も受け付けるため、
        //  子の id は選択肢へ補完し、マスタに無い id は採用しない。issue #195)
        var causeCategoryFilter = await ResolveCauseCategoryFilterAsync(causeCategoryId);
        // 採用した値だけを絞り込みに使う(採用しなかった場合は null なのでこの節を飛ばす)。
        // パターンマッチでローカル変数へ取り出すのは、「null でないことの確認」と
        // 「式ツリーが捕まえる値」を 1 か所で結び付けるため(HasValue と .Value に分けて書くと、
        //  条件を直したときに片方だけ取り残される)
        if (causeCategoryFilter.Effective is int effectiveCauseCategoryId)
            // 親カテゴリ指定時は子カテゴリの分析も拾う(この「親を選ぶと子も拾う」仕様が、
            // 選択肢(親のみ)と受け付ける値(子も可)のずれを生んでいる元)
            query = query.Where(i => i.CauseAnalyses.Any(ca =>
                ca.CauseCategoryId == effectiveCauseCategoryId ||
                ca.CauseCategory.ParentId == effectiveCauseCategoryId));

        // Sort
        // 並び替え: severity=重症度降順、overdue=期限超過あり優先、既定=発生日の新しい順
        // どの並び順も末尾に主キー Id 降順のタイブレーカーを付ける。
        // 理由: 重症度(7値)や期限超過フラグ(真偽2値)は同値の行が大量に発生し、DB は
        // 同値行の並び順を保証しない。タイブレーカーが無いと Skip/Take のページングが
        // 非決定的になり、同じ行が複数ページに出たり抜け落ちたりする(AuditLogsController と同じ対策)。
        query = sortBy switch
        {
            // 【注意】Severity は DB に enum 名の文字列(HasConversion<string>)で保存されるため、
            // この OrderByDescending は SQL では辞書順(アルファベット順)ソートになる。
            // 現状は "Level0".."Level5" の辞書順が重症度順と一致しているから正しく並ぶだけ。
            // 重症度コードを追加するときは辞書順が崩れないか必ず確認すること(IncidentSeverity.cs の注意書き参照)
            "severity" => query.OrderByDescending(i => i.Severity).ThenByDescending(i => i.Id),
            // 「期限超過」の唯一の定義は PreventiveMeasure.OverdueOn(today)。ただし
            // OrderByDescending の射影(式ツリー)内で外部の Expression を差し込めない
            // (AnalyticsController.MeasureStatus の GroupBy と同じ制約)ため、OverdueOn と
            // 同一条件 (Status != Completed && DueDate < today) をインライン展開する。
            // 条件を変えるときは OverdueOn と両方を必ず一致させること。
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

        // ビューに渡す ViewModel を組み立てる
        var vm = new IncidentListViewModel
        {
            Incidents = incidents,
            TotalCount = total,
            Page = page,
            PageSize = PageSize,
            Search = search,
            // 採用しなかった部署値は画面へ返さない。返すと、絞り込みは効いていないのに
            // 「絞り込み中」バッジが出てページャの URL にも載る食い違いになる(/AuditLogs と同じ扱い)
            Department = departmentFilter.Effective,
            // ドロップダウンの選択肢。上の絞り込み値と必ず対で使う(片方だけ差し替えない)
            DepartmentOptions = departmentFilter.Options,
            // 値を受け取ったのに採用しなかったなら、その事実を画面へ伝える。
            // 判定は解決側が返す(呼び出し側で SearchFilter.HasValue を引き直すと、
            // 解決側の「入力なし」の規則を変えたときに片方だけ古くなる)
            DepartmentFilterIgnored = departmentFilter.Ignored,
            IncidentType = incidentType,
            Severity = severity,
            DateFrom = dateFrom,
            DateTo = dateTo,
            // 採用しなかった原因分類の id は画面へ返さない(部署と同じ扱い。
            // 返すと絞り込みは効いていないのに「絞り込み中」バッジが出てページャの URL にも載る)
            CauseCategoryId = causeCategoryFilter.Effective,
            SortBy = sortBy,
            // ドロップダウンの選択肢。上の絞り込み値と必ず対で使う(片方だけ差し替えない)
            CauseCategoryOptions = causeCategoryFilter.Options,
            // 値を受け取ったのに採用しなかったなら、その事実を画面へ伝える(判定は解決側が返す)
            CauseCategoryFilterIgnored = causeCategoryFilter.Ignored
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
        var vm = await IncidentControllerHelpers.BuildIncidentDetailViewModelAsync(_db, _recurrence, _clock, User, id);

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
            CauseCategoryOptions = await BuildCauseCategoryOptions(),
            // 新規登録なので保存されている値は無い＝許可リストそのまま(過去の部署名は選べない)
            DepartmentOptions = ResolveDepartmentSaveSelection(null).Options
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
        // なぜなぜ分析サブフォーム由来の ModelState キーをいったん除外する。
        // Why2–5 などの任意項目やドロップダウン選択肢(CauseCategoryOptions)が
        // 未送信のときに残る不要な Required エラーを取り除くため。ただし一括除外だけだと
        // 保存対象(IsSavable)の分析の MaxLength 違反まで一緒に破棄されてしまうので、
        // 保存対象の場合は直後の再検証ブロックで本物の検証エラーを積み直す。
        // StringComparison.Ordinal を明示する。引数なしの StartsWith は現在のカルチャで比較するため、
        // ICU が「無視できる文字」とみなす記号(ソフトハイフン U+00AD・ZWJ U+200D 等)を挟んだキーまで
        // 前方一致と判定してしまう(実測: "­CauseAnalysis.Why1" が true になる)。この一致は
        // 除去する側へ効く＝意図より多くの検証エラーを捨てる fail-open で、しかも成立するかどうかが
        // サーバの OS ロケールと ICU の版に左右される(CLAUDE.md §10 プラットフォーム差異ゼロ設計)。
        // ModelState のキーは画面が組み立てる識別子であって自然言語ではないので、序数比較が正しい。
        // 前置詞は文字列直書きではなく nameof で組み立てる(§6。同じ規則をこのファイルの
        // 再検証ブロックと Views/Incidents/Details.cshtml が既に守っている)。直書きだと
        // ViewModel のプロパティを改名したとき、キーを組み立てる側だけが追随して
        // 除去する側が取り残され、空行の Required エラーが消えなくなる——利用者には
        // 「対応する入力欄が見当たらないエラー」で登録できない状態として現れる
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith($"{nameof(vm.CauseAnalysis)}.", StringComparison.Ordinal))
            .ToList())
        {
            // 原因分析サブフォーム由来の各キーを ModelState から除去する
            ModelState.Remove(key);
        }

        // 保存対象になる原因分析(原因分類 + なぜ1 が揃っている)は、上の一括除外で消えた
        // DataAnnotations 検証(Why1〜Why5 / RootCauseSummary / AdditionalNotes の500文字上限、
        // AnalystName の100文字上限など)をここで再実行して ModelState に積み直す。
        // これをしないと上限超過の文字列が検証をすり抜けて保存され(SQLite)、SQL Server /
        // PostgreSQL では未捕捉の DbUpdateException(HTTP 500)になる(§9 入力は信用しない)。
        // 検証水準は同じ ViewModel を素の model binding で検証する
        // CauseAnalysesController.AddCauseAnalysis と揃える。
        if (vm.CauseAnalysis.IsSavable)
        {
            // DataAnnotations 検証の結果(エラー一覧)を受け取る入れ物を用意する
            var analysisValidationResults = new List<ValidationResult>();
            // ViewModel に付与された属性([MaxLength] 等)を全プロパティに対して検証する
            Validator.TryValidateObject(
                vm.CauseAnalysis,
                new ValidationContext(vm.CauseAnalysis),
                analysisValidationResults,
                validateAllProperties: true);
            // 見つかった各エラーを Create ビューのフィールド名に合わせて ModelState に登録する
            foreach (var validationResult in analysisValidationResults)
            {
                // エラーが指すプロパティ名ごとに処理する(プロパティ名が無い場合はサブフォーム全体に紐づける)
                foreach (var memberName in validationResult.MemberNames.DefaultIfEmpty(string.Empty))
                {
                    // 「CauseAnalysis.プロパティ名」のキーでエラーを積む(nameof で改名に追従させる §6)
                    ModelState.AddModelError(
                        string.IsNullOrEmpty(memberName)
                            ? nameof(vm.CauseAnalysis)
                            : $"{nameof(vm.CauseAnalysis)}.{memberName}",
                        validationResult.ErrorMessage ?? "入力値が不正です。");
                }
            }
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
            // StringComparison.Ordinal を明示する理由は上の CauseAnalysis. 除外ループのコメントを参照。
            // この行ごとの除外は 3 つの前方一致の中で最も影響が大きい: 上のコメントのとおり
            // 「保存される行のフィールド検証は残す」ことでデータ整合性を守っているため、
            // カルチャ比較で保存対象の行にまで誤一致すると DueDate=default(0001-01-01) のまま
            // 保存され IsOverdue が常に true になる
            var rowPrefix = $"{nameof(vm.Measures)}[{i}].";
            foreach (var key in ModelState.Keys.Where(k => k.StartsWith(rowPrefix, StringComparison.Ordinal)).ToList())
            {
                // 空行由来の各キーを ModelState から除去する
                ModelState.Remove(key);
            }
        }

        // 部署スコープを強制する: Staff は自分の所属部署にしか登録できない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

        // 発生部署の選択肢と「保存を通す例外」を決める。新規登録なので保存されている値は無く、
        // 例外も生じない(許可リストから外れた部署名を新しい行へ付けられないようにするため)
        var departmentSelection = ResolveDepartmentSaveSelection(null);

        // 発生部署が許可リスト外の値でないか検証する(Admin/RiskManager のフォーム改ざん対策)
        EnforceKnownDepartment(vm, departmentSelection.Grandfathered);

        // 発生日時が未来でないかをサーバ側で検証する(未来のインシデントは報告できない)
        ValidateOccurredAtNotInFuture(vm);

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
            // 選択肢は POST ボディに含まれないため、再描画のたびに詰め直す
            // (詰め忘れるとビューの foreach が null を回して HTTP 500 になる)
            vm.DepartmentOptions = departmentSelection.Options;
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

    /// <summary>
    /// <c>/Incidents</c> の発生部署フィルタについて、<b>実際に絞り込みへ使う値</b>と
    /// <b>ドロップダウンに並べる選択肢</b>を同時に決める。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ 2 つを一緒に返すのか。</b> この 2 つは<b>必ず整合していなければならない</b>。
    /// 絞り込みに使った値が選択肢に無いと、ブラウザは <c>&lt;select&gt;</c> を「部署（全て）」の位置に置く。
    /// 絞り込みは効いたままなので画面と実状態が食い違い、利用者がそのフォームを再送信した瞬間に
    /// <c>department=""</c> が送られて<b>絞り込みが無言で解除される</b>(issue #192 の再現手順)。
    /// 別々の関数にすると片方だけ直したときにこの食い違いが戻るので、1 か所で決めて一緒に返す。</para>
    ///
    /// <para><b>判断の規則そのもの</b>(3 画面のどれが「補完」でどれが「採用しない」か、その理由)は
    /// <see cref="SearchFilter"/> の解説に集約してある。ここはそのうち <c>/Incidents</c> の
    /// 「実データにあれば補完、無ければ採用しない」を実装する。</para>
    ///
    /// <para><b>実在確認に部署スコープを掛ける理由。</b> 存在するかどうかの答えは
    /// 「その部署名の選択肢が出るか」という形で画面に現れる。スコープを外すと、Staff が
    /// <c>?department=...</c> を総当たりして<b>他部署にインシデントがあるかどうかを推測できる</b>
    /// (§9 最小公開)。一覧本体と同じ <c>ScopedByUser</c> を通しておけば、見える範囲の外は
    /// 「存在しない」と等しく扱われる。</para>
    ///
    /// <para><b>綴り違いをアプリ側で畳まない(実測に基づく判断)。</b> 許可リストの判定を
    /// 大文字小文字や前後空白を無視する比較にすると、<b>既定プロバイダで絞り込みが壊れる</b>。
    /// Staff の部署クレームは自由記述で <c>EnforceKnownDepartment</c> の対象外なので、
    /// <c>Department</c> が <c>"icu"</c> の行は実在しうる。アプリ側で <c>"ICU"</c> へ畳むと、
    /// 大文字小文字を区別する SQLite(既定)/ PostgreSQL では
    /// <c>Where(Department == "ICU")</c> が<b>その行に一致せず 0 件になる</b>——
    /// 絞り込み無しなら見えている行が、絞り込むと消える。
    /// <b>どの行が一致するかを決めてよいのは DB だけ</b>なので、判定は DB へ委ね、
    /// アプリ側の比較は序数(完全一致)に統一する。</para>
    ///
    /// <para><b>この判断で「配備先による違い」は狭まらず、形が変わる(意図的)。</b>
    /// 許可リストと大文字小文字だけが違う値(<c>?department=icu</c>、実データは <c>"ICU"</c>)は、
    /// 大文字小文字を区別する SQLite / PostgreSQL では<b>絞り込みを適用せず全件</b>を返し、
    /// 区別しない SQL Server では<b>ICU の行だけ</b>を返す。この変更の前は前者が
    /// 「0 件」だったので、違いは「0 件 対 N 件」から「全件 対 N 件」へ<b>広がっている</b>。
    /// それでもこちらを採るのは、0 件は<b>絞り込みが効いた結果だと誤読される</b>のに対し、
    /// 全件は注意書き付きで「適用しなかった」と明示されるため
    /// (<see cref="Models.ViewModels.IncidentListViewModel.DepartmentFilterIgnored"/>)。
    /// 返る行はどちらも部署スコープの中なので、見せてよい範囲は変わらない。
    /// <b>照合順序をまたいで同じ結果にすることはアプリ側からはできない</b>(§10 の限界)ので、
    /// 誤読しにくい側へ倒している。</para>
    ///
    /// <para><b>その代わりに残す不都合(意図的)。</b> 照合順序が大文字小文字を区別しない
    /// 配備先(SQL Server の <c>Japanese_CI_AS</c> 等)で、実データに <c>"icu"</c> と
    /// <c>"ICU"</c> の両方がある場合、選択肢に見た目のよく似た 2 項目が並ぶことがある。
    /// ただし<b>どちらを選んでも同じ行が出るだけ</b>で、絞り込みは正しく効き、
    /// 再送信しても解除されない(この関数が守る不変条件は保たれる)。
    /// 見た目の冗長さと「既定プロバイダで行に到達できない」を秤にかけて、前者を採っている。
    /// 綴りの揺れを本気で無くすなら、畳むべき場所はここではなく
    /// <b>保存する側</b>(Staff のクレームを許可リストへ正規化する)で、それは別の判断
    /// (issue #196 と同じ「保存される値」の話)。</para>
    ///
    /// <para><b>問い合わせは許可リストを外れたときだけ走る。</b> 通常の操作では値が
    /// <see cref="Incident.Departments"/> に載っているため、追加のクエリは発生しない。
    /// 走る場合も <c>Incident(Department, IncidentType)</c> インデックスに乗る問い合わせ 1 本で済む(§8)。
    /// 返すのは真偽値ではなく<b>保存されている綴りそのもの</b>(先頭 1 件の射影)である点が要で、
    /// 下の照合順序の項がその理由。<c>Any()</c> へ「戻す」と、コメントは残ったまま
    /// 照合順序のずれが黙って復活する。</para>
    /// </remarks>
    /// <param name="department">クエリ文字列から届いた発生部署の絞り込み値(未指定なら <c>null</c>)。</param>
    /// <returns>採用した絞り込み値(採用しないなら <c>null</c>)と、ドロップダウンの選択肢。</returns>
    private async Task<DepartmentFilterSelection> ResolveDepartmentFilterAsync(string? department)
    {
        // 選択肢の土台は常に Incident.Departments(部署一覧の唯一の真実の源)。
        // 補完する場合に先頭へ差し込むので、書き換えられるリストとして複製しておく
        var options = Incident.Departments.ToList();

        // 空・空白のみは「絞り込み無し」。判定は SearchFilter.HasValue に集約してある
        if (!SearchFilter.HasValue(department))
            return new DepartmentFilterSelection(null, options, Ignored: false);

        // 現在の許可リストに載っている値は、そのまま採用してよい(選択肢にも既に並んでいる)。
        // 比較は序数(完全一致)で行う。ここを大文字小文字を無視する比較にしてはいけない
        // —— 下の「綴り違いをアプリ側で畳まない」の項を参照
        if (options.Contains(department))
            return new DepartmentFilterSelection(department, options, Ignored: false);

        // ここから先は「現在の許可リストに無い値」。過去の部署名なのか、打ち間違い・改ざんなのかを
        // 実データで見分ける。判定は見えている範囲(部署スコープ)の中だけで行う。
        //
        // 「あるか」ではなく「DB に入っている綴りそのもの」を取り出すのが要点。上の
        // options.Contains は C# の序数比較(大文字小文字・末尾空白を区別する)なのに、
        // ここの == は DB の照合順序に従うため、両者の判定が食い違う配備先がある。
        // SQL Server の既定(Japanese_CI_AS など)は大文字小文字を区別せず末尾空白も無視するので、
        // ?department=icu は「許可リストに無い(序数)」かつ「実データにある(照合順序)」となり、
        // 利用者の綴りをそのまま補完すると本物の "ICU" の上に偽の "icu" が並ぶ。
        // SQLite / PostgreSQL は区別するので同じ URL でも挙動が変わる —— テストの InMemory は
        // 序数比較なので、全件緑のまま SQL Server 配備でだけ壊れる形になる(§10)。
        // DB 側の綴りを持ち帰れば、どちらの経路を通っても選択肢に並ぶのは実在する値だけになる
        var storedDepartment = await _db.Incidents
            .AsNoTracking()
            .ScopedByUser(User)
            // その部署のインシデントに絞る(照合順序による一致は DB の判断に委ねる)
            .Where(i => i.Department == department)
            // 並びを固定してから先頭を取る。照合順序が大文字小文字を区別しない配備先では
            // "ICU" と "icu" が同時に一致しうる(Staff の部署クレームは自由記述で、
            // EnforceKnownDepartment は Staff を対象外にしているため綴り違いが実在しうる)。
            // 並びを決めずに先頭を取ると同じ URL でもリクエストごとに違う綴りが返り、
            // 選択肢の増減もページャの URL も揺れる。DB は同値行の並び順を保証しないので、
            // 一覧のページングが Id のタイブレーカーを付けているのと同じ理由で並びを固定する。
            // キーが Id だけなのは、上の Where を通った行は Department が(DB 自身の
            // 照合順序で)すべて同値だから —— Department を第 1 キーに足しても必ずタイになり、
            // 結果は変わらないまま SQL にソート列が増えるだけ。
            // なお Id だけにしても整列そのものは消えない: Incident(Department, IncidentType)
            // インデックスは Department の中を IncidentType 順に並べるので、Id 順に読むには
            // その部署の行を並べ替える必要がある。決定性のために整列 1 回を払う判断で、
            // 「seek だけで済む」わけではない(この問い合わせは許可リストを外れた値の
            //  ときだけ走るので、その頻度でこの費用は許容している)
            .OrderBy(i => i.Id)
            // 保存されている綴りを 1 件だけ取り出す
            .Select(i => i.Department)
            .FirstOrDefaultAsync();

        // 実データに無いなら採用しない。絞り込みも掛けず、画面へも値を返さない。
        // こうすると「絞り込み無し・バッジ非表示・select は全て」の三者が揃う(/AuditLogs と同じ扱い)
        if (storedDepartment == null)
            return new DepartmentFilterSelection(null, options, Ignored: true);

        // 実データにある＝許可リストから外れた過去の部署名。選択肢へ補完して絞り込みを維持する。
        // 「既にあれば足さない・無ければ先頭へ」の手順は /PreventiveMeasures と共通なので
        // 共有ヘルパに寄せてある(照合順序が大文字小文字を区別しない配備先では、DB が
        // 許可リストどおりの綴りを返してくることがある。その場合は足さないのが正しい)
        IncidentControllerHelpers.EnsureAppliedValueIsSelectable(options, storedDepartment);
        // 以降は利用者の入力ではなく DB 側の綴りを使う。これで
        // 「絞り込みに使った値は必ず選択肢にある」が照合順序によらず成り立つ
        return new DepartmentFilterSelection(storedDepartment, options, Ignored: false);
    }

    /// <summary>
    /// <see cref="ResolveDepartmentFilterAsync"/> の結果。
    /// 「実際に絞り込みへ使う値」と「ドロップダウンに並べる選択肢」を組にして運ぶ。
    /// </summary>
    /// <remarks>
    /// 2 つを 1 つの型にまとめてあるのは、片方だけを受け取って使う書き方をできなくするため。
    /// タプルではなく名前付きの型にしているのは、呼び出し側で <c>Item1</c> / <c>Item2</c> の
    /// 取り違えが起きないようにするのと、この解説の置き場所を作るため。
    /// </remarks>
    /// <param name="Effective">
    /// 絞り込みに使う発生部署名。採用しなかった場合(空入力・実データに無い値)は <c>null</c>。
    /// ViewModel へもこの値を載せる——採用しなかった値を画面へ返すと、絞り込みは効いていないのに
    /// 「絞り込み中」バッジが出る食い違いになるため。
    /// </param>
    /// <param name="Options">
    /// 発生部署ドロップダウンに並べる選択肢。通常は <see cref="Incident.Departments"/> そのままで、
    /// 許可リストから外れた過去の部署名で絞り込んでいるときだけ、その値が先頭に補完されている。
    /// </param>
    /// <param name="Ignored">
    /// <b>値を受け取ったのに採用しなかった</b>とき <c>true</c>。画面の注意書きの出し分けに使う。
    /// <para><see cref="Effective"/> が <c>null</c> になる理由は 2 つあり
    /// (「そもそも入力が無かった」と「入力はあったが実データに無かった」)、
    /// <b>注意書きを出してよいのは後者だけ</b>。前者でも出すと、絞り込みを使っていない
    /// 普通の一覧表示で警告が出続け、利用者は読まなくなる。
    /// この区別は <see cref="ResolveDepartmentFilterAsync"/> の中にしかないので、
    /// 呼び出し側で <c>SearchFilter.HasValue</c> を引き直さずここで受け取る
    /// ——引き直すと、解決側の「入力なし」の規則を変えたときに片方だけ古くなる。</para>
    /// </param>
    private readonly record struct DepartmentFilterSelection(string? Effective, List<string> Options, bool Ignored);

    /// <summary>
    /// 原因分類の絞り込み値について「実際に絞り込みへ使う id」と
    /// 「ドロップダウンに並べる選択肢」を決める。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ要るのか(issue #195)。</b> この画面のドロップダウンは
    /// <b>親カテゴリだけ</b>で作るのに、絞り込みは<b>子カテゴリの id も受け付ける</b>
    /// (「親を選ぶと子も拾う」仕様の裏返しで、子の id を直接指せば当然その子だけに絞れる)。
    /// そのため子の id を指す URL では絞り込みが効いているのに一致する
    /// <c>&lt;option&gt;</c> が無く、ブラウザが <c>&lt;select&gt;</c> を
    /// 「原因分類（全て）」の位置に置き、<b>再送信した瞬間に絞り込みが無言で解除される</b>
    /// ——発生部署で塞いだのとまったく同じ食い違い。</para>
    ///
    /// <para><b>方式は「実在すれば補完、無ければ採用しない」。</b> 選択肢の集合が
    /// コード側で閉じておらず<b>実データ(原因分類マスタ)から作られる</b>うえ、
    /// 受け付ける値がその表示用の部分集合(親のみ)より広いため、一律に捨てると
    /// 「子カテゴリで絞り込む」経路そのものが失われる。逆に一律に補完すると
    /// 打ち間違い・URL 改ざんの id が選択肢に現れる。方式の割り当てと理由の正本は
    /// <see cref="Models.Validation.SearchFilter"/> の解説(そこの表がこの画面の行を持つ)。</para>
    ///
    /// <para><b>実在確認に部署スコープを掛けない</b>——発生部署のときとは違う判断で、
    /// ここが取り違えやすい。あちらは実在確認の対象が<b>インシデントの行</b>なので、
    /// スコープを外すと Staff が総当たりで他部署の部署名の有無を推測できてしまう。
    /// こちらが照会するのは<b>原因分類マスタ</b>で、PHI ではないうえ
    /// <see cref="Internal.IncidentControllerHelpers.BuildCauseCategoryOptionsAsync"/> が
    /// 登録・詳細画面で全ロールへ子カテゴリまで並べている。つまり隠せていない情報であり、
    /// ここだけスコープを掛けても防御にはならない。それどころか
    /// <b>自部署にまだ 1 件も無い分類で絞り込めなくなる</b>(0 件と「絞り込めない」は別物)
    /// という実害だけが残る。</para>
    ///
    /// <para><b>補完する子カテゴリは「親名 &gt; 子名」で並べる。</b> 選択肢の他の行は
    /// 親カテゴリ名なので、子の名前を裸で先頭へ足すと<b>親と対等の分類に見える</b>。
    /// 表記は <see cref="CauseCategory.FormatFullName"/>(<see cref="CauseCategory.FullName"/> と
    /// 再発アラートの見出しが使う既存の規則)へ委ねる——ここで <c>$"{parent} &gt; {name}"</c> と
    /// 書き直すと、区切り文字を変えたときに画面ごとに表記が食い違う(§6 DRY)。</para>
    ///
    /// <para><b>親の名前は追加の問い合わせをせず選択肢から引く。</b>
    /// <paramref name="causeCategoryId"/> が子なら、その親は
    /// <c>ParentId == null</c> の行なので既に <c>options</c> に載っている。
    /// 3 階層目(孫)は現在のシード・画面にはないが、あった場合は親が
    /// <c>options</c> に居ないため名前が引けない ——そのときは
    /// <see cref="CauseCategory.FormatFullName"/> の <c>null</c> 分岐で
    /// 自分の名前だけになる(選択肢に並ぶこと自体は保たれる)。</para>
    ///
    /// <para><b>分岐の基準は「親か子か」ではなく「選択肢にあるか」。</b>
    /// この関数が守る不変条件が後者そのものなので、基準を揃えておくと
    /// <b>どの枝を通っても不変条件が構造的に成り立つ</b>。<c>ParentId</c> で分けると
    /// 「親＝選択肢にあるはず」という推論が要り、それは
    /// <b>選択肢を作る問い合わせと id を引く問い合わせが同じ瞬間を見ている</b>
    /// という(スナップショットを取っていない以上、保証の無い)前提に寄りかかる
    /// ——2 つの読みの間に親カテゴリが 1 行増えれば、その id は「補完しない」のに
    /// 選択肢には無い、という issue #195 そのものの状態になる。
    /// あわせて、利用者が実際に押す経路(選択肢から親を選ぶ)では
    /// マスタへの問い合わせが 1 本まるごと消える。</para>
    /// </remarks>
    /// <param name="causeCategoryId">クエリ文字列から届いた原因分類の絞り込み値(未指定なら <c>null</c>)。</param>
    /// <returns>採用した絞り込み値(採用しないなら <c>null</c>)と、ドロップダウンの選択肢。</returns>
    private async Task<CauseCategoryFilterSelection> ResolveCauseCategoryFilterAsync(int? causeCategoryId)
    {
        // 選択肢の土台は親カテゴリの一覧(表示順)。エンティティ全体ではなく
        // 選択肢に要る 2 列だけを射影して取る(§8 過剰取得の回避)。
        // SelectListItem への詰め替えを DB 側でやらせないのは、int.ToString() の
        // SQL への翻訳可否がプロバイダで揃わないため(§10 プロバイダ非依存)
        var parents = await _db.CauseCategories
            .AsNoTracking()
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            // 主キーのタイブレーカーを付ける。CauseCategory(ParentId, DisplayOrder) は
            // 一意ではないので、表示順が同じ親カテゴリは実在しうる。DB は同値行の並び順を
            // 保証しないため、これが無いと同じリクエストでも選択肢の並びが揺れる
            // ——同じ絞り込みのまま次ページへ進んだだけでドロップダウンの項目が入れ替わる。
            // 一覧のページングや ResolveDepartmentFilterAsync が Id を足しているのと同じ理由
            .ThenBy(c => c.Id)
            .Select(c => new { c.Id, c.Name })
            .ToListAsync();
        // 補完する場合に先頭へ差し込むので、書き換えられるリストとして組み立てる
        var options = parents
            .Select(c => new SelectListItem(c.Name, c.Id.ToString()))
            .ToList();

        // 未指定は「絞り込み無し」。int? なので SearchFilter.HasValue(string 用)は使えず、
        // 「値が入っているか」はこの型自身の HasValue で判定する
        if (causeCategoryId is not int requestedId)
            return new CauseCategoryFilterSelection(null, options, Ignored: false);

        // 送信値の文字列表現。選択肢の同値判定にも補完する項目にも使うので一度だけ作る
        var requestedValue = requestedId.ToString();

        // 既に選択肢にある id は、それ以上何も調べずそのまま採用してよい
        // (この枝が守る不変条件は「絞り込みに使った値は必ず選択肢にある」ことそのもの。
        //  基準を「親か子か」ではなくここに置いた理由は上の <remarks> が持つ。
        //  同じ説明を書き写すと、規則を変えたときに片方だけが古くなる)
        if (options.Any(o => o.Value == requestedValue))
            return new CauseCategoryFilterSelection(requestedId, options, Ignored: false);

        // ここから先は「選択肢に無い id」。子カテゴリなのか、打ち間違い・改ざんなのかを
        // 原因分類マスタで見分ける(部署スコープは掛けない。理由は上の解説を参照)
        var requested = await _db.CauseCategories
            .AsNoTracking()
            .Where(c => c.Id == requestedId)
            .Select(c => new { c.Name, c.ParentId })
            .FirstOrDefaultAsync();

        // マスタに無い id は採用しない。絞り込みも掛けず、画面へも値を返さない
        // (「絞り込み無し・バッジ非表示・select は全て」の三者が揃う)
        if (requested == null)
            return new CauseCategoryFilterSelection(null, options, Ignored: true);

        // 実在する＝選択肢に無いだけの分類。親の名前を選択肢から引いて見出しに添える
        // (子カテゴリの通常経路。親自身が選択肢から漏れていた場合や 3 階層目では
        //  引けず null になり、FormatFullName が自分の名前だけを返す)
        // 親の送信値も一度だけ作る(ラムダの中で作ると選択肢の数だけ文字列を作ることになる。
        // 上の requestedValue と規則を揃えておかないと、次に読む人がどちらが意図か分からない)
        var parentValue = requested.ParentId?.ToString();
        var parentName = parentValue == null
            ? null
            : options.FirstOrDefault(o => o.Value == parentValue)?.Text;
        // 「親名 > 子名」の見出しで選択肢の先頭へ補完する。
        // 「空なら足さない・既にあれば足さない・無ければ先頭へ」の手順は共有ヘルパに寄せてある
        IncidentControllerHelpers.EnsureAppliedValueIsSelectable(
            options,
            new SelectListItem(CauseCategory.FormatFullName(parentName, requested.Name), requestedValue));

        // 実在する分類なので絞り込みを維持する(選択肢には補完済み)
        return new CauseCategoryFilterSelection(requestedId, options, Ignored: false);
    }

    /// <summary>
    /// <see cref="ResolveCauseCategoryFilterAsync"/> の結果。
    /// 意味と各要素の役割は <see cref="DepartmentFilterSelection"/> と同じ
    /// (そちらの解説が正本。ここへ書き写すと片方だけ古くなる)。
    /// </summary>
    /// <param name="Effective">絞り込みに使う原因分類 id。採用しない場合は <c>null</c>。</param>
    /// <param name="Options">原因分類ドロップダウンに並べる選択肢(親カテゴリ＋補完した子)。</param>
    /// <param name="Ignored"><b>値を受け取ったのに採用しなかった</b>とき <c>true</c>。</param>
    private readonly record struct CauseCategoryFilterSelection(
        int? Effective, List<SelectListItem> Options, bool Ignored);

    /// <summary>
    /// 登録・編集フォームの発生部署について、<b>ドロップダウンに並べる選択肢</b>と
    /// <b>許可リスト外でも保存を通す 1 件</b>を同時に決める。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ要るのか(issue #196)。</b> <see cref="Incident.Departments"/> は
    /// CLAUDE.md が「値追加は static 配列を更新」と明記する<b>可変の真実の源</b>なので、
    /// 部署名を入れ替えると<b>過去の行はリストに無い部署名を持ち続ける</b>。
    /// そのインシデントの編集画面を開くと <c>asp-for="Department"</c> に一致する
    /// <c>&lt;option&gt;</c> が無く、ブラウザは「-- 選択してください --」を選択状態にする。
    /// 説明文だけを直して保存すると <c>Department=""</c> が飛んで
    /// <c>[Required]</c> で弾かれ、保存を通すには許可リストのどれかを選ぶしかない
    /// ——<b>そのインシデントの発生部署が黙って書き換わる</b>。一覧の絞り込みが
    /// 解除されるだけだった <see cref="ResolveDepartmentFilterAsync"/> と違い、
    /// こちらは<b>保存された業務データが変わる</b>。</para>
    ///
    /// <para><b>規則: 現在保存されている値に限り、その 1 件だけ選択肢へ足す。</b>
    /// 一律に補完しないのは、過去の部署名が<b>新規登録でも選べる</b>ようになり
    /// 許可リストから外した意図に反するため。したがって新規登録
    /// (保存されている値が無い)では許可リストそのままで、例外も作らない。</para>
    ///
    /// <para><b>この「新規登録では例外を作らない」が覆うのは、ここで作る例外だけ。</b>
    /// 許可リスト外の部署名が新しい行へ入る経路はもう 1 つあり、それは<b>意図的に残してある</b>:
    /// Staff の所属部署クレームである。<see cref="EnforceOwnDepartmentForStaff"/> が
    /// フォームの値をクレームで上書きし、<see cref="EnforceKnownDepartment"/> は Staff を
    /// 対象にしないので、クレームが許可リストから外れている Staff が登録すると
    /// その部署名のまま保存される。Staff も検証対象にすれば塞げるが、そうすると
    /// <b>部署名を入れ替えた直後、その部署の Staff 全員がインシデントを報告できなくなる</b>
    /// ——自分では直せないクレーム(管理者管理下の値)が原因なので復旧手段が無い。
    /// 「報告できない」は「古い部署名で報告される」より重い障害なので、後者を選んでいる
    /// (この判断そのものは <see cref="EnforceKnownDepartment"/> のコメントが正本で、
    ///  issue #196 の前からある)。<b>クレーム由来の値はフォーム改ざんの経路ではない</b>
    /// (利用者が直接入力できない)ので、ここで守っている「利用者が任意の文字列を
    /// 書き込めないようにする」性質は保たれている。挙動は
    /// <c>UnlistedDepartmentSavePolicyTests</c> が固定する ——暗黙にしておくと、
    /// 次に読む人がこの段落と実装のどちらを信じてよいか分からなくなる。</para>
    ///
    /// <para><b>絞り込み側の表(<see cref="SearchFilter"/>)を保存側へ広げないこと。</b>
    /// あちらの 2 択(補完 / 採用しない)はどちらも「どの行を見るか」の話で、
    /// 保存される値には当てはまらない。この関数がその保存側の規則の正本。</para>
    ///
    /// <para><b>なぜ選択肢と例外を一緒に返すのか。</b> この 2 つは<b>必ず整合していなければ
    /// ならない</b>。画面に出す選択肢が保存の許可より広ければ、利用者が選べる値で保存が
    /// 弾かれる(何を選べば通るのか画面からは分からない)。逆に許可の方が広ければ、
    /// 画面に出ないはずの値をフォーム改ざんで保存できる。別々の関数にすると片方だけ
    /// 直したときにこの食い違いが戻るので、1 か所で決めて一緒に返す
    /// ——<see cref="ResolveDepartmentFilterAsync"/> が値と選択肢を組で返すのと同じ構図。</para>
    ///
    /// <para><b>比較は序数(完全一致)で行う。</b> 例外を「大文字小文字を無視して同じ」まで
    /// 広げると、保存される綴りが編集のたびに揺れる(<c>"icu"</c> の行を開いて保存すると
    /// <c>"ICU"</c> になる等)。選択肢を組み立てる <c>Contains</c> も同じ序数比較なので、
    /// 表示側と適用側が同じ判定を通る ——この一致は
    /// <c>UnlistedDepartmentSavePolicyTests</c> が「編集画面が出す選択肢はすべて保存が通る」
    /// という形で固定している。</para>
    /// </remarks>
    /// <param name="storedDepartment">
    /// 現在 DB に保存されている発生部署(新規登録なら <c>null</c>)。
    /// <b>必ず DB から読んだ値を渡すこと</b> ——フォームから届いた値を渡すと、
    /// 「自分で送った値が自分を許可する」ことになり検証そのものが無意味になる。
    /// </param>
    /// <returns>ドロップダウンに並べる選択肢と、許可リスト外でも保存を通す 1 件。</returns>
    private static DepartmentSaveSelection ResolveDepartmentSaveSelection(string? storedDepartment)
    {
        // 選択肢の土台は常に Incident.Departments(部署一覧の唯一の真実の源)。
        // 補完する場合に先頭へ差し込むので、書き換えられるリストとして複製しておく
        var options = Incident.Departments.ToList();

        // 保存されている値が無い(新規登録)なら許可リストそのまま。例外も作らない
        if (!SearchFilter.HasValue(storedDepartment))
            return new DepartmentSaveSelection(options, null);

        // 既に許可リストにある値なら、選択肢にも並んでいるので足す必要も例外も無い
        if (options.Contains(storedDepartment))
            return new DepartmentSaveSelection(options, null);

        // ここから先は「許可リストから外された過去の部署名」。選択肢へ補完して、
        // その 1 件だけ保存も通す(部署を触らない編集を通すため)。
        // 「既にあれば足さない・無ければ先頭へ」の手順は一覧画面と共通なので共有ヘルパに寄せてある
        IncidentControllerHelpers.EnsureAppliedValueIsSelectable(options, storedDepartment);
        return new DepartmentSaveSelection(options, storedDepartment);
    }

    /// <summary>
    /// <see cref="ResolveDepartmentSaveSelection"/> の結果。
    /// 「画面に並べる選択肢」と「許可リスト外でも保存を通す 1 件」を組にして運ぶ。
    /// </summary>
    /// <remarks>
    /// 2 つを 1 つの型にまとめてある理由は <see cref="DepartmentFilterSelection"/> と同じ
    /// (片方だけを受け取って使う書き方をできなくする / 取り違えを防ぐ / 解説の置き場所)。
    /// </remarks>
    /// <param name="Options">発生部署ドロップダウンに並べる選択肢。</param>
    /// <param name="Grandfathered">
    /// 許可リストに無いが保存を通す値。無ければ <c>null</c>。
    /// 新規登録では<b>常に <c>null</c></b> ——過去の部署名を新しい行へ付けられないようにするため。
    /// </param>
    private readonly record struct DepartmentSaveSelection(List<string> Options, string? Grandfathered);

    // 発生部署が Incident.Departments(唯一の真実の源)の許可リストに含まれているか検証する。
    // Create/Edit 画面の <select> はこの配列を土台に選択肢を描画するが、Admin/RiskManager は
    // EnforceOwnDepartmentForStaff で上書きされずフォームの値がそのまま使われるため、
    // フォーム改ざん(未定義文字列の直接 POST)をサーバ側で拒否しないと、任意の文字列が
    // Department として保存されてしまう(IncidentType/Severity の EnumDataType 検証と同じ
    // fail-closed の考え方。§9 入力は信用しない)。
    // Staff はこの検証の対象外: vm.Department は EnforceOwnDepartmentForStaff によって
    // 常に本人のクレーム値(ユーザーが直接入力できない、管理者管理下の信頼できる値)へ
    // 上書きされるため、フォーム改ざんの経路が存在しない。もし対象にすると、クレームの
    // 値が(部署名変更やタイポで)許可リストと一時的に食い違っただけで本人が復旧できない
    // ままロックアウトされてしまう。
    // なお Staff がこの検証を素通りしても発生部署は書き換わらない: SameDepartmentHandler が
    // 「インシデントの発生部署 == 本人のクレーム」の行しか編集させないため、上書きは同じ値の
    // 代入にしかならない(許可リストから外れた部署名の行を編集できるのは、その部署の Staff 本人だけ)。
    private void EnforceKnownDepartment(IncidentCreateEditViewModel vm, string? grandfathered)
    {
        // Admin/RiskManager 以外(=Staff)はフォーム改ざんの経路が無いため検証をスキップする
        if (!User.IsInRole(AppRoles.Admin) && !User.IsInRole(AppRoles.RiskManager))
            return;

        // 許可リストに含まれる値なら、そのまま通してよい
        if (Incident.Departments.Contains(vm.Department))
            return;

        // 許可リスト外でも「現在保存されている値と同じ」なら通す(issue #196)。
        // これで部署を触らない編集は通り、別の許可リスト外の値へ「変える」ことはできない。
        // 比較を序数にする理由と、選択肢を組み立てる側と同じ判定でなければならない理由は
        // ResolveDepartmentSaveSelection の解説を参照
        if (grandfathered != null && string.Equals(vm.Department, grandfathered, StringComparison.Ordinal))
            return;

        // どちらにも当てはまらない値は不正入力としてエラーを積む
        ModelState.AddModelError(nameof(vm.Department), "部署の値が不正です。");
    }

    // 発生日時(OccurredAt)が未来の日時でないかをサーバ側で検証する。
    // ブラウザの datetime-local 入力は任意の未来日時を送信できるため、クライアント側の
    // 入力だけに頼ると「まだ起きていないインシデント」が登録・編集できてしまう
    // (§9 入力は信用しない)。時刻の比較は必ず注入された IClock を使う(JST / テスト差し替え可能)。
    // なお ReportedAt(報告日時)はフォーム入力ではなく Create POST 内で _clock.Now を
    // サーバ側で設定する値のため、未来日時の混入経路が無く、ここでの検証は不要。
    // 「発生日時 ≤ 報告日時」の整合は Create ではこの組み合わせ(OccurredAt ≤ 現在時刻
    // かつ ReportedAt = 現在時刻)により自動成立するが、Edit は ReportedAt を再設定
    // しないため自動では成立しない。Edit POST 側で ValidateOccurredAtNotAfterReportedAt
    // により別途検証する。
    private void ValidateOccurredAtNotInFuture(IncidentCreateEditViewModel vm)
    {
        // 発生日時が入力済みで、かつ現在時刻(IClock)より後ならエラーを積む
        // (未入力の null は [Required] 側が「発生日時は必須です」として検証する)
        if (vm.OccurredAt.HasValue && vm.OccurredAt.Value > _clock.Now)
        {
            // 発生日時フィールドに紐づくエラーとして登録し、フォーム再描画時に表示させる
            ModelState.AddModelError(nameof(vm.OccurredAt), "発生日時に未来の日時は指定できません。");
        }
    }

    // 発生日時(OccurredAt)が報告日時(ReportedAt)より後にならないかを検証する(Edit 専用)。
    // 発生は報告に必ず先行するという業務上の前提を守るための検証。Create ではサーバ側が
    // ReportedAt = 現在時刻 を設定するため未来日時検証だけで自動成立するが、Edit は
    // ReportedAt を再設定しないため、発生日時を報告日時より後へ書き換えると
    // 「発生前に報告された」矛盾データが保存でき、詳細画面の経過時間表示
    // (報告日時 - 発生日時)が負値になってしまう。
    private void ValidateOccurredAtNotAfterReportedAt(IncidentCreateEditViewModel vm, Incident incident)
    {
        // 発生日時が入力済みで、かつ既存の報告日時より後ならエラーを積む
        if (vm.OccurredAt.HasValue && vm.OccurredAt.Value > incident.ReportedAt)
        {
            // 発生日時フィールドに紐づくエラーとして登録し、フォーム再描画時に表示させる
            ModelState.AddModelError(nameof(vm.OccurredAt), "発生日時に報告日時より後の日時は指定できません。");
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
            CauseCategoryOptions = await BuildCauseCategoryOptions(),
            // 保存されている発生部署が許可リストから外れていれば、その 1 件だけ選択肢へ足す。
            // 足さないと一致する <option> が無く、別項目だけ直した保存で部署が書き換わる(issue #196)
            DepartmentOptions = ResolveDepartmentSaveSelection(incident.Department).Options
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
        // StringComparison.Ordinal を明示する理由は Create 側の同じ除外ループのコメントを参照
        foreach (var key in ModelState.Keys
            .Where(k => k.StartsWith($"{nameof(vm.CauseAnalysis)}.", StringComparison.Ordinal)
                     || k.StartsWith($"{nameof(vm.Measures)}[", StringComparison.Ordinal))
            .ToList())
        {
            ModelState.Remove(key);
        }

        // 部署スコープを強制する: Staff は自部署のインシデントしか編集できず、
        // 他部署への付け替えもできない(issue #63)
        EnforceOwnDepartmentForStaff(vm);

        // 発生部署の選択肢と「保存を通す例外」を決める。基準は DB に保存されている現在値で、
        // フォームから届いた vm.Department ではない ——フォームの値を渡すと「自分で送った値が
        // 自分を許可する」ことになり、許可リストの検証そのものが無意味になる。
        // incident.Department はまだ書き換えていない(下の反映は検証を通ってから)ので現在値そのもの
        var departmentSelection = ResolveDepartmentSaveSelection(incident.Department);

        // 発生部署が許可リスト外の値でないか検証する(Admin/RiskManager のフォーム改ざん対策)。
        // 保存されている値と同じであれば許可リスト外でも通す(issue #196)
        EnforceKnownDepartment(vm, departmentSelection.Grandfathered);

        // 発生日時が未来でないかをサーバ側で検証する(Create と同じ業務ルールを編集でも守る)
        ValidateOccurredAtNotInFuture(vm);

        // 発生日時が既存の報告日時より後になっていないかを検証する(Edit 専用の整合検証)
        ValidateOccurredAtNotAfterReportedAt(vm, incident);

        // バリデーション NG なら入力値を残してフォームを再描画
        if (!ModelState.IsValid)
        {
            vm.CauseCategoryOptions = await BuildCauseCategoryOptions();
            // 選択肢は POST ボディに含まれないため、再描画のたびに詰め直す。
            // 補完した過去の部署名もここで戻さないと、再描画された画面から現在値が消え、
            // 次の送信で issue #196 の書き換えがそのまま起きる
            vm.DepartmentOptions = departmentSelection.Options;
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
        // 削除権限がなければ 403。CanDeleteIncident は Admin/RiskManager のロール判定だけで、
        // CanEditIncident / CanViewIncident と違い SameDepartmentRequirement を持たない
        // (Program.cs のポリシー定義を参照)。リソースを渡しているのは、将来ポリシーへ部署要件を
        // 足したときにこの経路が自動で追随するようにするため
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
