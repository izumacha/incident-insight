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
    /// 一覧画面のフリーワード検索で、利用者が入力したキーワードを
    /// 「DB 側の大文字化と突き合わせられる形」へ正規化する。
    ///
    /// <para><b>なぜ必要か。</b> 一覧の部分一致検索はいずれも
    /// 「列を大文字化した結果に、大文字化したキーワードが含まれるか」で判定する。
    /// <c>string.Contains</c> をそのまま使うと、SQLite / SQL Server では大文字小文字を区別しない
    /// LIKE に翻訳されるのに Npgsql(PostgreSQL) は区別する比較に翻訳され、同じ検索語でも配備先で
    /// 結果が変わってしまうため(DB プロバイダ非依存の原則)。</para>
    ///
    /// <para><b>なぜ <c>ToUpperInvariant</c> なのか。</b> 突き合わせる 2 つの辺は、
    /// 大文字化する主体が違う。
    /// <list type="bullet">
    ///   <item>列の側 … 式ツリー内の <c>col.ToUpper()</c> は EF Core が SQL の <c>UPPER(col)</c> へ
    ///     翻訳するので、大文字化するのは <b>DB</b>(その照合順序)であってアプリではない。</item>
    ///   <item>キーワードの側 … C# で評価してパラメータとして渡すので、大文字化するのは <b>アプリ</b>。</item>
    /// </list>
    /// ここで引数なしの <c>ToUpper()</c> を使うと、アプリ側だけが
    /// <see cref="System.Globalization.CultureInfo.CurrentCulture"/>(＝サーバ OS のロケール)に
    /// 従ってしまう。トルコ語系ロケール(tr-TR / az-*)では <c>"incident".ToUpper()</c> が
    /// <c>"İNCİDENT"</c>(U+0130 を含む)になる一方、標準的な照合順序の DB が返す
    /// <c>UPPER('incident')</c> は <c>"INCIDENT"</c> なので、<b>正規の検索語が 1 件も
    /// ヒットしなくなる</b>(実測で確認済み)。「配備先によらず同じ結果」を狙って入れた正規化が、
    /// 逆にサーバのロケールという別の環境差を持ち込んでいたことになる
    /// (CLAUDE.md §10 プラットフォーム差異ゼロ設計)。</para>
    ///
    /// <para><b>残る境界 1: DB 側の照合順序は「ロケール中立」であることを前提にしている。</b>
    /// 「どの照合順序でも <c>UPPER('incident')</c> は <c>"INCIDENT"</c>」とは言えない。とくに
    /// PostgreSQL の <c>upper()</c> は引数の照合順序(データベースの <c>lc_ctype</c>、または
    /// 列・式に付けた ICU 照合順序)に従うため、<c>lc_ctype=tr_TR.UTF-8</c> で初期化した
    /// クラスタでは <c>UPPER('incident')</c> が <c>'İNCİDENT'</c> を返す。その場合はアプリ側を
    /// 不変規則にしても両辺は一致しない。<b>この関数が取り除くのは「アプリ側がサーバ OS の
    /// ロケールで揺れる」ことだけ</b>で、DB 側までロケール中立にすることはできない
    /// (それは配備時の照合順序の選択の問題であり、コードからは決められない)。
    /// PostgreSQL / Supabase は CLAUDE.md §1 が挙げる一次配備先なので、トルコ語系の
    /// <c>lc_ctype</c> でクラスタを作る場合はこの前提が崩れる点に注意する。</para>
    ///
    /// <para><b>残る境界 2: テストの InMemory プロバイダでは列の側もカルチャ依存になる。</b>
    /// 本番では列の側を大文字化するのは DB だが、InMemory プロバイダには SQL が無く、
    /// 式ツリーの <c>col.ToUpper()</c> は<b>アプリ内で</b>現在のカルチャに従って評価される。
    /// つまり InMemory 上では列の側だけがカルチャ依存のまま残る。これはテスト実行環境に限った
    /// 性質で、本番の経路(SQL への翻訳)には影響しない。そのためロケールを差し替える
    /// テストは、列の側が影響を受けないよう<b>あらかじめ大文字の ASCII</b> を保存したうえで
    /// 小文字のキーワードで引く形にしてある
    /// (各 <c>*ControllerTests</c> の <c>...SearchUsesInvariantUpperCasing</c>)。</para>
    ///
    /// <para><b>残る境界 3: SQLite の <c>upper()</c> は ASCII しか畳まない（この PR 以前からの制約）。</b>
    /// 既定プロバイダの SQLite は組み込みの <c>upper()</c> が <c>a-z</c> だけを大文字化する
    /// (ICU 拡張を組み込まない限り)。一方アプリ側は <see cref="string.ToUpperInvariant"/> で
    /// Unicode 全体を畳むため、<b>非 ASCII の小文字を含む検索語は既定プロバイダでだけ一致しない</b>:
    /// 「café」を保存して「café」で検索すると、アプリ側は <c>"CAFÉ"</c>、SQLite 側は
    /// <c>upper('café') = 'CAFé'</c> となり 0 件になる(全角の <c>ｉｃｕ</c> なども同様)。
    /// SQL Server / PostgreSQL は正しく畳むので一致する。
    /// <b>これは引数なしの <c>ToUpper()</c> だった頃から同じ</b>で、この PR が変えた点ではない
    /// (どちらの規則でも é は É へ畳まれる)。ドメイン語彙が日本語であるこのアプリでは、
    /// 仮名・漢字に大文字小文字の区別が無いため実害は限定的だが、
    /// <b>「配備先によらず同じ結果」を完全に達成できているわけではない</b>点は明記しておく。
    /// 塞ぐならプロバイダ非依存の別手段(照合順序の指定、正規化済み列の保持など)が要り、
    /// この関数の差し替えでは足りない。</para>
    ///
    /// <para><b>残る境界 4: この規則にはソース走査の検出網が無い。</b>
    /// ModelState のキーの前方一致には <c>ModelStateKeyPrefixMatchTests</c> があるが、
    /// こちらの「キーワード側は <c>ToUpperInvariant</c>、列の側は <c>ToUpper</c>」という
    /// 規則は<b>同じ形では機械化できない</b>。列の側は EF Core が SQL へ翻訳できる
    /// <c>ToUpper()</c> でなければならず、素の <c>ToUpper()</c> を一律に禁じると
    /// <b>必要な書き方まで違反として報告してしまう</b>。式ツリーの内側かどうかは
    /// テキストの走査では判別できないため(構文解析が要る)、正しいコードを咎める
    /// 検出網になるくらいなら置かない、という判断をしている。
    /// <b>したがって新しい一覧検索を足すときは、次の 2 つを手で守ること。</b>
    /// <list type="number">
    ///   <item>キーワード側は必ずこの関数を通す(素の <c>ToUpper()</c> を書かない)。</item>
    ///   <item>列の側にも <c>.ToUpper()</c> を付ける——付け忘れると PostgreSQL では
    ///     大文字小文字を区別する比較に翻訳されて一致しなくなる一方、SQLite / SQL Server と
    ///     テストの InMemory では一致してしまい、<b>特定の配備先でだけ</b>壊れる。</item>
    /// </list>
    /// 既存の 3 経路については、ロケールを差し替えるコントローラ級のテストが
    /// 「この関数が実際に経路上にあること」まで固定している。</para>
    ///
    /// <para><b>対になる規則。</b> 「そもそも絞り込むかどうか」(空・空白のみの入力を
    /// 絞り込み無しとして扱う)は <see cref="Models.Validation.SearchFilter.HasValue"/> が持つ。
    /// 呼び出し側は必ずその判定を通してからこの関数を呼ぶ。置き場所が分かれているのは、
    /// 空判定を絞り込みの適用側(コントローラ)と「絞り込み中」の表示側(ビュー)の両方が使うのに対し、
    /// この大文字化は EF Core のクエリを組み立てる経路にしか現れないため(issue #187)。</para>
    /// </summary>
    /// <param name="keyword">利用者が入力した検索キーワード(空でないことは呼び出し側が確認済み)。</param>
    /// <returns>ロケールに依存しない規則で大文字化したキーワード。</returns>
    public static string NormalizeSearchKeyword(string keyword)
        // 実行環境のロケールに左右されない不変(invariant)規則で大文字化して返す
        => keyword.ToUpperInvariant();

    /// <summary>
    /// 適用中の絞り込み値がドロップダウンの選択肢に無ければ、<b>先頭へ</b>補完する。
    /// </summary>
    /// <remarks>
    /// <para>一覧画面が「補完」方式を採るときの共通手順。どの画面でも守る不変条件は 1 つで、
    /// <b>絞り込みに使った値は必ず選択肢にある</b>こと。一致する <c>&lt;option&gt;</c> が無いと
    /// ブラウザは <c>&lt;select&gt;</c> を先頭の「(全て)」の位置に置き、絞り込みが効いたまま
    /// 画面だけが「絞り込み無し」に見える。その状態でフォームを再送信すると空値が送られ、
    /// <b>絞り込みが利用者の意図なく解除される</b>(issue #192)。</para>
    ///
    /// <para><b>先頭に置く理由。</b> 末尾へ足すと、選択肢が多い画面ではスクロールしないと
    /// 現在値が見えず、「選ばれていない」と誤解した利用者が別の値を選んで絞り込みを失う。
    /// 「(全て)」の直後という位置そのものが規則なので、画面ごとに書き写さず
    /// ここ 1 か所に置く(<c>/Incidents</c> と <c>/PreventiveMeasures</c> の 2 画面が使う)。</para>
    ///
    /// <para><b>この関数は「補完するかどうか」を決めない。</b> それは画面ごとの方針で、
    /// <c>/PreventiveMeasures</c> は無条件、<c>/Incidents</c> は実データにあるときだけ。
    /// 判断の規則と理由は <c>Models.Validation.SearchFilter</c> の解説に集約してある。</para>
    /// </remarks>
    /// <param name="options">ドロップダウンの選択肢(この場に書き換える)。</param>
    /// <param name="appliedValue">実際に絞り込みへ使っている値。</param>
    public static void EnsureAppliedValueIsSelectable(List<string> options, string appliedValue)
    {
        // 既に選択肢にあるなら何もしない(足すと同じ項目が 2 つ並ぶ)
        if (options.Contains(appliedValue)) return;
        // 「(全て)」の直後に来るよう先頭へ差し込む
        options.Insert(0, appliedValue);
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
