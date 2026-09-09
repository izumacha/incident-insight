// 部署スコープ拡張メソッド(ScopedByUser)を使う
using IncidentInsight.Web.Authorization;
// DbContext を使う
using IncidentInsight.Web.Data;
// Incident エンティティを使う
using IncidentInsight.Web.Models;
// ViewModel(IncidentDetailViewModel / MeasureFormViewModel / CauseAnalysisFormViewModel)を使う
using IncidentInsight.Web.Models.ViewModels;
// 文字数上限とエラーメッセージ書式の唯一の真実の源(FieldLengths)を使う
using IncidentInsight.Web.Models.Validation;
// 時刻源(IClock)・再発検知サービス(IRecurrenceService)を使う
using IncidentInsight.Web.Services;
// 認可サービスのインタフェース
using Microsoft.AspNetCore.Authorization;
// ClaimsPrincipal を扱う
using System.Security.Claims;
// SelectListItem / SelectListGroup(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張(Include / ToListAsync / DbUpdateConcurrencyException)
using Microsoft.EntityFrameworkCore;
// ILogger を使う(同時編集衝突のログ出力)
using Microsoft.Extensions.Logging;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// 複数のコントローラが共有する小さなヘルパ群。テストを増やすほどの責務は持たず、
/// 純粋な再利用関数のみ置く。業務ルール(例: 「対策が1件以上」)は Controller 側に残し、
/// ここには持ち込まない。
///
/// <para>利用側はここに書き並べない(実際、当初挙げていた 3 コントローラ以外にも
/// AnalyticsController / AuditLogsController / PreventiveMeasuresController が
/// <c>ToExclusiveUpperBound</c> を使うようになり、一覧の方が先に古くなった)。
/// 誰が使っているかは参照を辿れば分かるので、写しは持たない。</para>
/// </summary>
internal static class IncidentControllerHelpers
{
    /// <summary>
    /// 適用中の値がドロップダウンの選択肢に無ければ、<b>先頭へ</b>補完する。
    /// </summary>
    /// <remarks>
    /// <para>「補完」方式を採る画面の共通手順。守る不変条件は
    /// <b>実際に使っている値は必ず選択肢にある</b>こと 1 つ。
    /// 一覧の絞り込みでこれが要る理由(壊れ方と、画面ごとの方式の割り当て)は
    /// <see cref="Models.Validation.SearchFilter"/> の解説が正本
    /// ——ここへ書き写すと、方針を変えたときにこちらが古くなる(issue #192)。</para>
    ///
    /// <para><b>絞り込み専用の部品ではない。</b> 登録・編集フォームの発生部署も、
    /// 保存されている値が許可リストから外れているときに同じ手順で補完する
    /// (規則は <c>IncidentsController.ResolveDepartmentSaveSelection</c> の解説が正本。issue #196)。
    /// そちらは「絞り込みが解除される」ではなく<b>保存された値が書き換わる</b>ので、
    /// <b>適用するかどうかの判断は呼び出し側にあり、この関数は位置だけを決める</b>。</para>
    ///
    /// <para><b>先頭に置く理由。</b> 末尾へ足すと、選択肢が多い画面ではスクロールしないと
    /// 現在値が見えず、「選ばれていない」と誤解した利用者が別の値を選んでしまう
    /// ——絞り込みなら絞り込みを失い、保存フォームなら保存された値が書き換わる。
    /// <b>先頭の固定項目</b>(一覧の「(全て)」/ フォームの「-- 選択してください --」)の
    /// 直後という位置そのものが規則なので、画面ごとに書き写さずここ 1 か所に置く。</para>
    ///
    /// <para><b>この関数は「補完するかどうか」を決めない。</b> それは画面ごとの方針で、
    /// <c>/PreventiveMeasures</c> は無条件、<c>/Incidents</c> の絞り込みは実データにあるときだけ、
    /// 登録・編集フォームは<b>現在保存されている値に限る</b>。
    /// 絞り込み側の規則は <c>Models.Validation.SearchFilter</c> に、
    /// 保存側の規則は <c>ResolveDepartmentSaveSelection</c> に、それぞれ集約してある
    /// (<b>利用側をここに書き並べない</b> ——一覧の方が先に古くなる)。</para>
    ///
    /// <para><b>2 つの門番はどちらもテストから直接は動かせない</b>(この型は <c>internal</c>)が、
    /// <b>どちらも <c>/PreventiveMeasures</c> 経由で機械的に見張られている</b>。
    /// あの画面は選択肢を実データから作り、担当部署は自由記述で許可リストを持てないため、
    /// 未指定・空白のみも既に選択肢にある値もそのままここへ届くからで、
    /// いずれも <c>UnlistedFilterValuePolicyTests</c> が消すと落ちる形で固定している
    /// （空値は <c>PreventiveMeasures_BlankResponsibleDepartment_AddsNoOption</c>、
    /// 重複は <c>PreventiveMeasures_ResponsibleDepartmentAlreadyInOptions_IsNotDuplicated</c>）。</para>
    ///
    /// <para>ただし<b>空値の門番がそうなったのは issue #202 から</b>。それまでは全呼び出し側が
    /// 手前で自前に弾いていたため「消しても全件緑」で、レビューだけが頼りだった。
    /// 写しを外して判定をここ 1 か所にしたことで見張られるようになった
    /// （<c>string?</c> を受けるのはそのため）。<b>呼び出し側で先に弾く形へ戻すと、
    /// この門番はまた誰にも見られなくなる。</b></para>
    ///
    /// <para><b>この関数を触る差分は、2 つの門番が残っているかをレビューでも確かめること。</b>
    /// 上の 2 件が見ているのは <c>List&lt;string&gt;</c> 版だけで、
    /// 隣の <see cref="SelectListItem"/> 版には対応するテストが無い。</para>
    /// </remarks>
    /// <param name="options">ドロップダウンの選択肢(この場に書き換える)。</param>
    /// <param name="appliedValue">
    /// 実際に絞り込みへ使っている値。<b>未指定・空白のみでもそのまま渡してよい</b>
    /// ——足すかどうかはこの関数が決めるので、呼び出し側で先に弾かない。
    /// </param>
    public static void EnsureAppliedValueIsSelectable(List<string> options, string? appliedValue)
    {
        // 空・空白のみ(null 含む)は足さない。足すと先頭の固定項目の直後に画面上は見分けの付かない
        // 空の項目が並び、押しても何も起きない選択肢として残る。
        // この判定を呼び出し側の記憶に任せないのは、位置の規則をここへ集めたのと同じ理由
        // ——次に足す人が同じことを思い出せるとは限らない。
        // 呼び出し側が同じ判定を写すと空値の規則を直す場所が 2 か所になるので、
        // 判定はここ 1 か所に持つ(issue #202 で /PreventiveMeasures 側の写しを外した)
        if (!SearchFilter.HasValue(appliedValue)) return;
        // 既に選択肢にあるなら何もしない(足すと同じ項目が 2 つ並ぶ)
        if (options.Contains(appliedValue)) return;
        // 先頭の固定項目(「(全て)」/「-- 選択してください --」)の直後に来るよう先頭へ差し込む
        options.Insert(0, appliedValue);
    }

    /// <summary>
    /// <see cref="SelectListItem"/> で選択肢を作る画面向けの
    /// <see cref="EnsureAppliedValueIsSelectable(List{string}, string?)"/>。
    /// 表示文字列と送信値が別々になるだけで、守る不変条件も置く位置も同じ。
    /// </summary>
    /// <remarks>
    /// <para><b>null の受け入れ方も隣と揃える。</b> 文字列版が <c>string?</c> を受けて
    /// 「未指定でもそのまま渡してよい」なら、こちらも項目そのものが <c>null</c> でよい。
    /// 片方だけ非 null にすると、隣のドキュメントを手本にした呼び出し
    /// (絞り込みが解決できたときだけ項目を作り、それ以外は <c>null</c> を渡す形)が
    /// <b>その画面だけ NullReferenceException で HTTP 500</b> になる ——
    /// 「呼び出し側に規則を思い出させない」というこの関数の目的に反するので、
    /// 判定を増やして揃える側を採る。</para>
    ///
    /// <para><b>重複を承知で 2 つ置いている理由。</b> 選択肢の要素型が違うだけで
    /// 判定は「空でないか」「既にあるか」「先頭へ入れる」の 3 つとも同じなので、
    /// <b>位置の規則が 2 か所に分かれないように隣同士へ置く</b>
    /// ——型で共通化しようとすると、片方だけが持つ「同値の判定は <c>Value</c> で行う」
    /// (表示文字列は違っても同じ選択肢)という性質を表せる抽象が要り、
    /// 2 つの利用側のために作る抽象としては大きすぎる(§6 の「将来を見越した過度な抽象化」)。
    /// <b>3 つ目の要素型が出てきたら、そのとき共通化を検討すること。</b></para>
    ///
    /// <para><b>同値の判定は <c>Value</c> だけで行う</b>(<c>Text</c> は見ない)。
    /// <c>&lt;select&gt;</c> がサーバへ送るのは <c>Value</c> なので、
    /// 「絞り込みに使った値が選択肢にある」かどうかを決めるのはそちらだけ。
    /// 表示文字列まで一致条件に混ぜると、同じ id を別の見出しで 2 回並べてしまう
    /// (例: <c>/Incidents</c> は補完する子カテゴリだけ「親名 &gt; 子名」で出すので、
    ///  同じ id でも <c>Text</c> は既存の選択肢と一致しないことがある)。</para>
    /// </remarks>
    /// <param name="options">ドロップダウンの選択肢(この場に書き換える)。</param>
    /// <param name="appliedItem">
    /// 実際に絞り込みへ使っている値の選択肢。<b>未指定なら <c>null</c> を渡してよい</b>
    /// ——足すかどうかはこの関数が決めるので、呼び出し側で先に弾かない(文字列版と同じ)。
    /// </param>
    public static void EnsureAppliedValueIsSelectable(List<SelectListItem> options, SelectListItem? appliedItem)
    {
        // 項目そのものが無い、または送信値が空・空白のみなら足さない(理由は上のオーバーロードと同じ)。
        // 2 つを 1 つの条件にまとめてあるのは、どちらも「足すものが無い」という同じ判断だから
        if (!SearchFilter.HasValue(appliedItem?.Value)) return;
        // 同じ送信値の選択肢が既にあるなら何もしない(足すと同じ項目が 2 つ並ぶ)
        if (options.Any(o => o.Value == appliedItem.Value)) return;
        // 先頭の固定項目(「(全て)」/「-- 選択してください --」)の直後に来るよう先頭へ差し込む
        options.Insert(0, appliedItem);
    }

    /// <summary>
    /// 原因カテゴリのドロップダウン用に、親カテゴリでグルーピングした子カテゴリ一覧を作る。
    /// </summary>
    public static async Task<List<SelectListItem>> BuildCauseCategoryOptionsAsync(ApplicationDbContext db)
    {
        // 親カテゴリと子カテゴリをまとめて取得(表示順付き)
        var cats = await db.CauseCategories
            .Include(c => c.Children)
            .Where(c => c.ParentId == null)
            .OrderBy(c => c.DisplayOrder)
            .ToListAsync();

        // 生成するアイテム一覧
        var items = new List<SelectListItem>();
        // 親ごとにループして <optgroup> を作る
        foreach (var parent in cats)
        {
            // <optgroup> として表示される親カテゴリのグループ
            var group = new SelectListGroup { Name = parent.Name };
            // 子カテゴリを表示順に並べて追加
            foreach (var child in parent.Children.OrderBy(c => c.DisplayOrder))
            {
                // 1 行の <option> を作って追加
                items.Add(new SelectListItem
                {
                    Value = child.Id.ToString(),
                    Text = child.Name,
                    Group = group
                });
            }
        }
        // 完成した選択肢リストを返す
        return items;
    }

    /// <summary>
    /// 指定された原因カテゴリ Id が実在するかを返す。CauseAnalysis を保存する前に
    /// 外部キー(CauseCategoryId)の存在を確認し、存在しない Id による INSERT 失敗
    /// (未捕捉の DbUpdateException = HTTP 500)を未然に防ぐためのバリデーション用。
    /// </summary>
    public static Task<bool> CauseCategoryExistsAsync(ApplicationDbContext db, int causeCategoryId)
    {
        // 指定 Id の原因カテゴリが 1 件でも存在するかを問い合わせて返す
        return db.CauseCategories.AnyAsync(c => c.Id == causeCategoryId);
    }

    /// <summary>
    /// リソース(Incident)に対する Policy 評価。fail-closed: incident が null の場合は拒否する。
    /// SameDepartmentHandler が判定する都合上、呼び出し側は Incident を eager-load しておくこと。
    /// </summary>
    public static async Task<bool> IsAuthorizedForAsync(
        IAuthorizationService auth,
        ClaimsPrincipal user,
        Incident? incident,
        string policy)
    {
        // null は認可不可として扱う
        if (incident == null) return false;
        // 認可サービスに Incident をリソースとして渡して判定
        var result = await auth.AuthorizeAsync(user, incident, policy);
        return result.Succeeded;
    }

    /// <summary>
    /// 生の文字列を直接受け取る POST アクション用の自由記述文字数チェック。EF Core は保存時に
    /// DataAnnotations を自動検証しないため、ViewModel を経由しない入力(CompleteMeasure /
    /// RateMeasure / PreventiveMeasuresController.Complete)はここで明示的に検証する
    /// (§9 入力は信用しない)。null(未入力)は許容し、上限を超えたときだけメッセージを返す。
    ///
    /// 上限値・文言の書式は <see cref="FieldLengths"/>(唯一の真実の源)から引く。以前はここに
    /// 独自の <c>FreeTextMaxLength = 500</c> を持っていたが、エンティティ / ViewModel 側の
    /// <c>[MaxLength]</c> とは別々の裸の数値だったため、片方だけ変更すると
    /// 「この経路だけ通るのに保存で落ちる(またはその逆)」という不整合になりえた(§6)。
    /// </summary>
    public static string? ValidateFreeTextLength(string? value, string fieldLabel)
    {
        // 未入力、または上限内ならエラーなし
        if (value == null || value.Length <= FieldLengths.FreeText) return null;
        // 上限超過なら呼び出し側がそのまま警告表示に渡せるメッセージを返す。
        // 文言の書式は ViewModel の [MaxLength] と共通のものを使い、
        // {0} に項目名、{1} に上限文字数を差し込む(表記ゆれを防ぐ)
        return string.Format(FieldLengths.MaxLengthMessage, fieldLabel, FieldLengths.FreeText);
    }

    /// <summary>
    /// 日付上限フィルタ(dateTo)の「その日いっぱいを含む」排他的上限(翌日 0 時)を安全に計算する。
    /// IncidentsController / PreventiveMeasuresController / AuditLogsController /
    /// AnalyticsController の各一覧・集計が共通で使う(CLAUDE.md §6 DRY)。
    /// dateTo に表現可能な最終日 9999-12-31(DateTime.MaxValue.Date)が指定されると、
    /// 素朴な Date.AddDays(1) は ArgumentOutOfRangeException(未捕捉の HTTP 500)を投げる。
    /// 極端な値はクラッシュさせずフォールバックする(§9 fail-safe)ため、その場合は
    /// これ以上進めず DateTime.MaxValue を上限として返す(最終日全体を含む意味は変わらない)。
    /// </summary>
    public static DateTime ToExclusiveUpperBound(DateTime dateTo)
    {
        // 時刻成分を切り落として日付(その日の 0 時)だけにする
        var date = dateTo.Date;
        // 表現可能な最終日(9999-12-31)なら「翌日」が存在しないため、桁あふれさせず
        // DateTime.MaxValue(9999-12-31 23:59:59.9999999)を排他的上限として返す
        if (date >= DateTime.MaxValue.Date) return DateTime.MaxValue;
        // 通常は翌日 0 時を返す(「< 翌日0時」でその日いっぱいを含む)
        return date.AddDays(1);
    }

    /// <summary>
    /// 楽観的排他制御の保存試行を共通化するヘルパー。CauseAnalysesController /
    /// IncidentMeasuresController / IncidentsController / PreventiveMeasuresController の
    /// 各アクションで重複していた「SaveChangesAsync → DbUpdateConcurrencyException 捕捉 →
    /// ログ出力」の定型処理をここに集約する(CLAUDE.md §6 DRY)。
    /// クライアントの編集前トークンを OriginalValue にピンする行(1 行で完結し呼び出し側の
    /// エンティティ型ごとに異なるため、ここには含めない)は呼び出し側で事前に行っておくこと。
    /// 戻り値が false のとき、呼び出し側は TempData["Warning"] とリダイレクト先(アクションごとに
    /// 異なる)を決めて処理を続ける。
    /// </summary>
    public static async Task<bool> TrySaveChangesHandlingConcurrencyAsync(
        ApplicationDbContext db,
        ILogger logger,
        string conflictLogMessage,
        params object[] logArgs)
    {
        try
        {
            // 保存試行。事前にピンした OriginalValue と DB の現在値が食い違えば例外が飛ぶ
            await db.SaveChangesAsync();
            // 成功: 呼び出し側は通常どおり成功メッセージ・リダイレクトへ進んでよい
            return true;
        }
        catch (DbUpdateConcurrencyException ex)
        {
            // 衝突発生: ログを残す(呼び出し側ごとに異なるメッセージ/引数をそのまま使う)
            logger.LogWarning(ex, conflictLogMessage, logArgs);
            // 失敗を呼び出し側へ伝える(TempData["Warning"] とリダイレクトは呼び出し側の責務)
            return false;
        }
    }

    /// <summary>
    /// インシデント詳細画面(Details)用の <see cref="IncidentDetailViewModel"/> を組み立てる。
    /// <see cref="Controllers.IncidentsController.Details"/> の GET 本来の呼び出しに加え、
    /// AddMeasure/AddCauseAnalysis がバリデーション失敗時に(別コントローラから)同じ詳細画面を
    /// 入力済みの値を保持したまま再描画するためにも使う(CLAUDE.md §6 DRY)。
    ///
    /// AddMeasure/AddCauseAnalysis は成功時は Details へリダイレクトするが、失敗時に同じ
    /// redirect を使うと入力済みの値が失われる。TempData(既定はクッキーに乗る
    /// CookieTempDataProvider)へ入力値そのものを退避する方式は、自由記述欄(なぜなぜ分析・
    /// 対策内容等、PHI を含みうる)をクライアント側のクッキーへ丸ごと載せてしまう上、Cookie の
    /// 実質的なサイズ上限(多くのブラウザで 4KB 程度)を超える恐れもあるため採用しない。代わりに
    /// 呼び出し側がこのメソッドで Details と同じ ViewModel をサーバー側だけで組み立て直し、
    /// <c>newMeasureOverride</c>/<c>newCauseAnalysisOverride</c> にバリデーション失敗した入力値を
    /// 渡すことで、それを保持したまま Details ビューをそのまま再描画できる(データはクライアントを
    /// 経由しない)。両パラメータを省略した場合は通常の GET と同じ空の ViewModel になる。
    ///
    /// 呼び出し側は事前に認可チェック(CanView/CanEditIncident)を済ませておくこと(ここでは行わない)。
    /// </summary>
    /// <returns>インシデントが存在しなければ null(呼び出し側は 404 として扱う)。</returns>
    public static async Task<IncidentDetailViewModel?> BuildIncidentDetailViewModelAsync(
        ApplicationDbContext db,
        IRecurrenceService recurrence,
        IClock clock,
        ClaimsPrincipal user,
        int incidentId,
        MeasureFormViewModel? newMeasureOverride = null,
        CauseAnalysisFormViewModel? newCauseAnalysisOverride = null)
    {
        // 原因分析 → カテゴリ → 親カテゴリまで、および対策一覧を eager-load で取得
        // (IncidentsController.Details と同じクエリ)
        var incident = await db.Incidents
            .Include(i => i.CauseAnalyses).ThenInclude(ca => ca.CauseCategory).ThenInclude(cc => cc!.Parent)
            .Include(i => i.PreventiveMeasures)
            // 2 つのコレクション(原因分析・対策)を 1 本の JOIN で取ると行数が
            // 「原因分析数 × 対策数」に膨らむ(デカルト爆発)ため、コレクションごとに
            // SQL を分けて取得する。SQLite / SQL Server / PostgreSQL いずれも
            // 分割クエリに対応しており、プロバイダ非依存の原則を崩さない(§8)
            .AsSplitQuery()
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.Id == incidentId);
        // レコードが無ければ呼び出し側で 404 にできるよう null を返す
        if (incident == null) return null;

        // 再発検出(HomeController と同じマッチングルールを共有するサービスに委譲)。
        // IRecurrenceService の契約どおり、候補集合は ScopedByUser で部署スコープを
        // 済ませてから渡す(HomeController.Index と同じ扱い)。現在のマッチングルールは
        // 同一部署のみを返すが、将来ルールが部署をまたいでも認可層で他部署の PHI が
        // 類似一覧に混入しないよう、ここで二重に防御する(§9 fail-safe)
        var similar = await recurrence.FindRecurrencesForIncidentAsync(
            incident, db.Incidents.AsNoTracking().ScopedByUser(user));
        // 原因カテゴリのドロップダウン選択肢(親カテゴリでグルーピング)
        var causeOptions = await BuildCauseCategoryOptionsAsync(db);

        // 画面用 ViewModel を組み立てる。NewCauseAnalysis/NewMeasure は override が渡されて
        // いればそれを使い(バリデーション失敗した入力値の保持)、無ければ通常どおり空にする
        return new IncidentDetailViewModel
        {
            Incident = incident,
            SimilarIncidents = similar,
            CauseCategoryOptions = causeOptions,
            NewCauseAnalysis = newCauseAnalysisOverride ?? new CauseAnalysisFormViewModel { IncidentId = incidentId },
            // DueDate を IClock で既定の日数後に初期化する(IncidentsController.Details と同じ規約)
            NewMeasure = newMeasureOverride
                ?? new MeasureFormViewModel
                {
                    IncidentId = incidentId,
                    DueDate = clock.Today.AddDays(Controllers.IncidentsController.DefaultMeasureDueDays),
                    // 種別の初期選択(ViewModel を nullable 化したため組み立て側で設定する)
                    MeasureType = Models.Enums.MeasureTypeKind.ShortTerm
                }
        };
    }
}
