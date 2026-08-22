// モデル(Incidentなど)を使えるようにする
using IncidentInsight.Web.Models;
// ViewModel(RecurrenceAlertなど)を使えるようにする
using IncidentInsight.Web.Models.ViewModels;
// EF Core の拡張メソッド(Include / ToListAsync など)を使えるようにする
using Microsoft.EntityFrameworkCore;

// このサービスの名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Services;

/// <inheritdoc />
public class RecurrenceService : IRecurrenceService
{
    // 時刻源(テストで差し替えるために注入で受け取る)
    private readonly IClock _clock;

    // ダッシュボードの再発アラート候補として一度に読み込む過去インシデントの上限件数。
    // 候補クエリは「最近90日に登場した部署×種別×原因分類」に一致する全期間のインシデントを
    // 対象にするため、運用年数が長くなると条件がテーブルの大部分に一致し、上限が無いと
    // ログイン直後のダッシュボード表示のたびに全件近くをメモリへ読み込んでしまう(§8 の
    // 「一覧取得は必ず上限を持たせる」違反)。新しい発生ほど再発アラートとしての価値が
    // 高いため、発生日の新しい順に上限件数だけ取得する。/code-review ultra 指摘対応:
    // 直近90日の recentList クエリ自体にも同じ上限を課す(以前はここだけ無制限で、
    // 直近90日以内のインシデント数がテーブルの大部分を占める環境では実質上限が効いて
    // いなかった)。recentList と candidates は Id で重複排除しながら candidatePool へ
    // 合流させるため、打ち切りの影響は「パターンの相手が双方の上限を超えた古い
    // インシデントのみの場合、その類似・アラートを逃す」ことに限定される(意図的なトレードオフ)。
    // (public にしているのはテストが上限値と同期した件数でシードするため)
    public const int MaxAlertCandidateRows = 1000;

    // 再発パターンの説明文(PatternDescription)に並べる原因分類名の上限件数。
    // 1 件のインシデントにぶら下がるなぜなぜ分析(CauseAnalysis)の数に制限は無く、
    // 分析ごとに別の原因分類を選べるため、上限が無いとダッシュボードのアラート 1 行が
    // 分類名の羅列で際限なく横に伸びる(§8 の「一覧は必ず上限を持たせる」を 1 行の中にも適用)。
    // 超えた分は件数だけ「ほか N 件」と添えて、分類が他にもあること自体は隠さない。
    // (public にしているのはテストが上限値と同期した件数でシードするため。
    //  MaxAlertCandidateRows と同じ理由)
    public const int MaxPatternCauseNames = 3;

    // コンストラクタ: DI コンテナから IClock が渡ってくる
    public RecurrenceService(IClock clock) { _clock = clock; }

    /// <inheritdoc />
    public async Task<List<Incident>> FindRecurrencesForIncidentAsync(
        Incident incident,
        IQueryable<Incident> scope,
        TimeSpan? within = null,
        CancellationToken ct = default)
    {
        // 対象インシデントの原因分類IDをハッシュ集合にまとめる(判定用)
        var catIds = incident.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
        // 原因分類が1件もなければ再発判定はできないので空リストを返す
        if (catIds.Count == 0) return new List<Incident>();

        // 自分自身を除き、同部署・同種別の候補を取り出すクエリを組み立てる
        var query = scope
            .AsNoTracking()
            .Include(o => o.CauseAnalyses)
            .Where(o => o.Id != incident.Id
                && o.Department == incident.Department
                && o.IncidentType == incident.IncidentType);

        // 時間窓が指定されていれば、その期間に発生したものだけに絞る
        if (within is { } w)
        {
            // 今日から「w」分だけさかのぼった基準日を算出
            var since = _clock.Today - w;
            // 発生日が基準日以降のものに絞り込む
            query = query.Where(o => o.OccurredAt >= since);
        }

        // FindRecurrenceAlertsAsync（ダッシュボード）は同じ「同部署×同種別」候補に
        // MaxAlertCandidateRows の上限を課しているが、こちら（IncidentsController.Details
        // 経由、within が null なら期間無制限）には上限が無く、運用年数が長い病院で
        // ありふれた部署×種別の組み合わせだと、詳細ページを開くたびに該当する
        // インシデントのほぼ全件を CauseAnalyses ごとメモリへ読み込んでしまう
        // （§8「一覧取得は必ず上限を持たせる」違反）。発生日の新しい順に同じ上限で
        // 打ち切る。OccurredAt が同時刻の行は DB が並び順を保証しないため、Id の降順を
        // 第2キーにして打ち切り境界を決定的にする（FindRecurrenceAlertsAsync と同じ対策）。
        // 打ち切りの影響はダッシュボード側と同様「上限を超えた古い候補が漏れる」ことに
        // 限定される（意図的なトレードオフ）
        query = query
            .OrderByDescending(o => o.OccurredAt)
            .ThenByDescending(o => o.Id)
            .Take(MaxAlertCandidateRows);

        // DB から候補をまとめて取得する
        var candidates = await query.ToListAsync(ct);
        // 候補の中から実際に原因分類が重なるものだけを抽出して返す
        return RecurrenceDetector.FindSimilar(incident, candidates);
    }

    /// <inheritdoc />
    public async Task<List<RecurrenceAlert>> FindRecurrenceAlertsAsync(
        IQueryable<Incident> scope,
        TimeSpan recentWindow,
        CancellationToken ct = default)
    {
        // 集計対象の基準日(今日から recentWindow 分さかのぼった日)
        var since = _clock.Today - recentWindow;

        // 最近発生したインシデントを新しい順に取得(原因分類も同時ロード)。
        // /code-review ultra 指摘対応: 以前は上限が無く、下の candidates クエリと違って
        // 運用年数が長い病院で直近 90 日以内のインシデント件数がテーブルの大部分に達すると、
        // Admin/RiskManager がダッシュボードを開くたびに全件をメモリへ読み込んでいた
        // (§8「一覧取得は必ず上限を持たせる」違反)。candidates クエリと同じ
        // MaxAlertCandidateRows・同じ並び順(発生日の新しい順、同時刻は Id 降順で決定的に)
        // で打ち切る。打ち切りの影響は「上限を超えた古いインシデントがアラート対象から
        // 漏れる」ことに限定される(candidates 側と同じ意図的なトレードオフ)。
        // 読み込むのは CauseAnalyses まで。分類マスタ(CauseCategory)はここでは結合しない。
        // 見出し用の分類名は LoadCauseCategoryDisplayNamesAsync が別クエリで引く
        // (理由は同メソッドの remarks。ここに ThenInclude を足すと再発検知そのものが
        //  表示用データの結合可否に左右される)
        var recentList = await scope
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .Where(i => i.OccurredAt >= since)
            .OrderByDescending(i => i.OccurredAt)
            .ThenByDescending(i => i.Id)
            .Take(MaxAlertCandidateRows)
            .ToListAsync(ct);

        // 1件もなければアラート生成処理は不要
        if (recentList.Count == 0) return new List<RecurrenceAlert>();

        // 最近発生した部署のユニーク一覧を作る
        var recentDepts = recentList.Select(i => i.Department).Distinct().ToList();
        // 最近発生したインシデント種別のユニーク一覧を作る
        var recentTypes = recentList.Select(i => i.IncidentType).Distinct().ToList();
        // 最近発生したインシデントに紐づく原因分類IDの集合を作る
        var recentCatIds = recentList
            .SelectMany(i => i.CauseAnalyses.Select(ca => ca.CauseCategoryId))
            .ToHashSet();

        // Over-fetches slightly (superset of dept × type) but collapses the loop's
        // per-iteration queries into one. Final matching is done in-memory below.
        // 候補を1回のクエリでまとめて取得(あとはメモリ上で厳密にマッチング)。
        // 発生日の新しい順に MaxAlertCandidateRows 件で打ち切り、蓄積データが増えても
        // ダッシュボード表示のたびに全期間のインシデントを読み込まないようにする。
        // OccurredAt が同時刻の行は DB が並び順を保証しないため、Id の降順を第2キーに
        // して打ち切り境界を決定的にする(IncidentsController.Index のページングと同じ対策。
        // これが無いとリロードのたびに境界上の候補が入れ替わりアラートが点滅し得る)
        var candidates = recentCatIds.Count == 0
            ? new List<Incident>()
            : await scope
                .AsNoTracking()
                .Include(i => i.CauseAnalyses)
                .Where(i => recentDepts.Contains(i.Department)
                    && recentTypes.Contains(i.IncidentType)
                    && i.CauseAnalyses.Any(ca => recentCatIds.Contains(ca.CauseCategoryId)))
                .OrderByDescending(i => i.OccurredAt)
                .ThenByDescending(i => i.Id)
                .Take(MaxAlertCandidateRows)
                .ToListAsync(ct);

        // 打ち切りで直近ウィンドウ内のインシデントまで候補から漏れると、
        // (1) 同じパターンのアラートが重複生成される(後述の processed による抑止は
        //     候補に載った類似インシデントにしか効かない)、
        // (2) 直近同士のペアの再発を見逃す、
        // という打ち切り前には起きなかった問題が生じる。recentList は candidates とは
        // 独立に(部署・種別・原因分類の絞り込み無しで)発生日の新しい順に取得しているため、
        // 同じ MaxAlertCandidateRows 件でも candidates とは異なるインシデント集合になり得る。
        // recentList に残っている分については Id で重複排除しながら candidates と合流させ、
        // 「recentList に載っている直近インシデントが候補側の打ち切りだけで漏れる」ことを防ぐ。
        // /code-review ultra 指摘対応: recentList 自体にも上限を導入したため、この完全性保証は
        // 「直近ウィンドウ全体」ではなく「recentList 自身の上限内」に限定される。打ち切りの
        // 影響は「上限を超えた古いインシデントが recentList・候補いずれからも漏れる
        // (パターンの相手が上限超過分のみの場合はそのアラートを逃す)」に限定される
        var candidatePool = candidates
            .Concat(recentList)
            .GroupBy(i => i.Id)
            .Select(g => g.First())
            .ToList();

        // 候補を (部署, 種別) のキーでグルーピングして高速検索できるようにする
        var candidatesByKey = candidatePool.ToLookup(i => (i.Department, i.IncidentType));

        // 結果の再発アラートを溜めるリスト
        var alerts = new List<RecurrenceAlert>();
        // アラートごとに「重なった原因分類 ID(重なりの強い順)」を控えておく箱。
        // 見出しの組み立ては分類名の引き当て(DB アクセス)を待つ必要があるため、
        // 巡回中は判定結果だけを持ち、文字列にするのはループを抜けてから行う
        var sharedCategoryIdsByAlert = new List<(RecurrenceAlert Alert, List<int> SharedCategoryIds)>();
        // 重複アラートを防ぐため、すでに処理したインシデントIDを覚えておく集合
        var processed = new HashSet<int>();
        // 新しい順に最近インシデントを巡回
        foreach (var incident in recentList)
        {
            // すでに他アラートで使われたものはスキップ
            if (processed.Contains(incident.Id)) continue;

            // 同じ部署・種別の候補バケットを取得
            var bucket = candidatesByKey[(incident.Department, incident.IncidentType)];
            // バケットから類似(原因分類が重なる)インシデントを抽出
            var similar = RecurrenceDetector.FindSimilar(incident, bucket);

            // 類似が1件以上ある場合のみアラートとして採用
            if (similar.Count > 0)
            {
                // アラートを1件組み立てる(見出しは分類名を引いたあとで入れ直す)
                var alert = new RecurrenceAlert
                {
                    CurrentIncident = incident,
                    SimilarIncidents = similar,
                    // まずは分類名なしの「部署 / 種別」で埋めておく。分類名を引けなかった場合の
                    // 縮退表示(§9 fail-safe)と同じ値なので、この後の差し替えが失敗しても破綻しない
                    PatternDescription = FormatDepartmentAndType(incident)
                };
                // 組み立てたアラートを結果リストに追加する
                alerts.Add(alert);
                // 見出しに使う「重なった原因分類」をこの場で判定して控える
                // (ループを抜けたあとに再判定すると、同じ規則を 2 度走らせることになる)
                sharedCategoryIdsByAlert.Add((alert, RecurrenceDetector.FindSharedCauseCategoryIds(incident, similar)));
                // 処理済みとして記録(以降の巡回で再び採用しないようにする)
                processed.Add(incident.Id);
                // 類似側も処理済み扱いにして重複アラートを防ぐ
                foreach (var s in similar) processed.Add(s.Id);
            }
        }

        // アラートが 1 件も無ければ見出し用の分類名は要らないので、DB アクセスを省いて返す
        if (alerts.Count == 0) return alerts;

        // 見出しに載り得る分類 ID だけを集める(アラートにならなかったインシデントの分類は引かない)
        var neededCategoryIds = sharedCategoryIdsByAlert
            .SelectMany(x => x.SharedCategoryIds)
            .ToHashSet();
        // 分類名を引く範囲を、実際にアラートになったインシデントだけに絞る
        // (件数は最大でも alerts.Count = recentList の件数以下なので、
        //  このファイルの他のクエリと同じく MaxAlertCandidateRows で頭打ちになる)
        var alertIncidentIds = alerts.Select(a => a.CurrentIncident.Id).ToList();
        // 分類 ID → 表示名 の対応表を 1 回のクエリで作る
        var causeCategoryNameById =
            await LoadCauseCategoryDisplayNamesAsync(scope, alertIncidentIds, neededCategoryIds, ct);

        // 控えておいた判定結果と対応表を突き合わせて、各アラートの見出しを確定させる
        foreach (var (alert, sharedCategoryIds) in sharedCategoryIdsByAlert)
        {
            // 「部署 / 種別（重なった原因分類）」の形に組み立て直す。
            // 組み立て規則は BuildPatternDescription が唯一の源(下の private メソッド)
            alert.PatternDescription =
                BuildPatternDescription(alert.CurrentIncident, sharedCategoryIds, causeCategoryNameById);
        }

        // 集まった再発アラートのリストを返す
        return alerts;
    }

    /// <summary>
    /// 指定された原因分類 ID について、見出し用の表示名（「親 &gt; 子」形式）を引く対応表を作る。
    /// </summary>
    /// <remarks>
    /// 分類マスタをインシデント側のクエリに <c>ThenInclude</c> で結合せず、別クエリで引くのは
    /// <b>再発検知そのものを表示用データから切り離すため</b>。<c>CauseAnalysis.CauseCategory</c> は
    /// 必須ナビゲーション（<c>CauseCategoryId</c> が非 null）なので、これを結合すると EF Core が
    /// 内部結合として扱い、分類マスタ側の行が引けない <c>CauseAnalysis</c> は
    /// <b>読み込み結果からまるごと落ちる</b>。落ちた分は原因分類の重なり判定にも使われなくなるため、
    /// 「見出しに分類名を出したかっただけ」の変更が再発アラートの検出漏れに化ける。
    /// 別クエリなら、引けなかったときに縮退するのは見出しの表記だけで済む（§9 fail-safe）。
    /// 読み取り範囲は <paramref name="incidentIds"/>（アラートになったインシデント）に絞る。
    /// <paramref name="scope"/> は呼び出し側が部署スコープを掛けただけの全期間クエリなので、
    /// ここで絞らないと 1 回のダッシュボード表示で全期間の <c>CauseAnalyses</c> を走査してしまい、
    /// このファイルが他のクエリすべてに掛けている行数上限（<see cref="MaxAlertCandidateRows"/>）
    /// だけが素通しになる（§8「一覧取得は必ず上限を持たせる」）。インシデント ID で絞れば
    /// 走査は最大でも同じ上限に収まり、返る行数も原因分類マスタの行数で頭打ちになる。
    /// <paramref name="scope"/> 経由で引くのは、呼び出し側が掛けている
    /// 部署スコープ（認可）の外にあるデータを覗かないため。
    /// </remarks>
    /// <param name="scope">呼び出し側がスコープを絞ったインシデントのクエリ。</param>
    /// <param name="incidentIds">分類名を引く対象のインシデント ID（アラートの基点）。</param>
    /// <param name="categoryIds">表示名が必要な原因分類の ID。</param>
    /// <param name="ct">キャンセル用トークン。</param>
    /// <returns>分類 ID から表示名を引く対応表（引けなかった分類はキーごと存在しない）。</returns>
    private static async Task<Dictionary<int, string>> LoadCauseCategoryDisplayNamesAsync(
        IQueryable<Incident> scope,
        IReadOnlyCollection<int> incidentIds,
        IReadOnlyCollection<int> categoryIds,
        CancellationToken ct)
    {
        // 対象のインシデントか必要な分類が 1 つも無ければ、クエリを投げずに空の対応表を返す
        if (incidentIds.Count == 0 || categoryIds.Count == 0) return new Dictionary<int, string>();

        // 対象インシデントのなぜなぜ分析だけを辿り、必要な分類の名前と親分類名を投影して取り出す。
        // 親は省略可能な関連なので、親を持たない分類では ParentName が null になる
        var rows = await scope
            .AsNoTracking()
            .Where(i => incidentIds.Contains(i.Id))
            .SelectMany(i => i.CauseAnalyses)
            .Where(ca => categoryIds.Contains(ca.CauseCategoryId))
            .Select(ca => new
            {
                ca.CauseCategoryId,
                ca.CauseCategory.Name,
                ParentName = ca.CauseCategory.Parent != null ? ca.CauseCategory.Parent.Name : null
            })
            // 同じ分類を指す分析が何件あっても対応表には 1 行あればよいので DB 側で重複を落とす
            .Distinct()
            .ToListAsync(ct);

        // 分類 ID ごとに 1 行だけ残す（Distinct 済みなので、同じ分類 ID の行は本来 1 行しかない）
        return rows
            .GroupBy(r => r.CauseCategoryId)
            .Select(g => g.First())
            // 「親 > 子」形式の表示名を組み立てて対応表にする
            // (組み立て規則は CauseCategory.FormatFullName が唯一の源。FullName と同じ表記になる)
            .ToDictionary(r => r.CauseCategoryId, r => CauseCategory.FormatFullName(r.ParentName, r.Name));
    }

    /// <summary>
    /// 再発パターンの説明文（ダッシュボードのアラート 1 行に出る見出し）を組み立てる。
    /// 「部署 / 種別（重なった原因分類）」の形にする。
    /// </summary>
    /// <remarks>
    /// 再発の判定条件は「同部署 × 同種別 × 原因分類の重なり」（CLAUDE.md §3 / <see cref="RecurrenceDetector"/>）
    /// なのに、以前の説明文は部署と種別しか含んでいなかった。そのため同じ部署・同じ種別で
    /// 原因分類だけが違う 2 つのパターン（例: 「確認不足」で 3 件、「申し送り漏れ」で 2 件）が
    /// ダッシュボードに同じ文字列で 2 行並び、利用者にはなぜ同じパターンが重複しているのか、
    /// どちらの根本原因を見直すべきかが分からなかった。判定条件の 3 つ目を説明文にも出して
    /// 行同士を区別できるようにする。
    /// 分類名が 1 つも引けないとき（対応表に名前が無い＝分類マスタの行が読めない等）は
    /// 従来どおり「部署 / 種別」だけを返す。表示のためだけの情報が欠けていることで
    /// アラート自体を落とすのは過剰なので、機能を縮退させて続行する（§9 fail-safe）。
    /// 残るトレードオフ: 重なった分類が <see cref="MaxPatternCauseNames"/> 件を超える 2 つの
    /// パターンで、上位の分類が偶然すべて一致すると、打ち切り後の見出しは再び同じ文字列になる。
    /// 見出しの長さに上限を置く以上これは避けられないので、切り捨てるのが「重なりの弱い分類」に
    /// なるよう <see cref="RecurrenceDetector.FindSharedCauseCategoryIds"/> の並び（重なりの強い順）
    /// をそのまま使い、衝突が起きにくい側に倒している。衝突しても各行の類似件数と詳細リンクは
    /// 別なので、見分けが付かなくなるのは見出しだけ。
    /// </remarks>
    /// <param name="incident">アラートの基点インシデント（CurrentIncident）。</param>
    /// <param name="sharedCategoryIds">基点と類似インシデントで重なった原因分類の ID（重なりの強い順）。</param>
    /// <param name="categoryNameById">分類 ID から表示名を引く対応表（<see cref="LoadCauseCategoryDisplayNamesAsync"/> の戻り値）。</param>
    /// <returns>アラート 1 行分の見出し文字列。</returns>
    private static string BuildPatternDescription(
        Incident incident,
        IReadOnlyList<int> sharedCategoryIds,
        IReadOnlyDictionary<int, string> categoryNameById)
    {
        // 「部署 / 種別」の部分(分類名を 1 つも出せないときの縮退表示もこれと同じ)
        var departmentAndType = FormatDepartmentAndType(incident);

        // 重なりの強い順に、名前を引けた分類だけを上限件数まで採る
        var shownNames = sharedCategoryIds
            .Where(categoryNameById.ContainsKey)
            .Take(MaxPatternCauseNames)
            .Select(id => categoryNameById[id])
            .ToList();

        // 名前が 1 つも引けなければ、従来どおり「部署 / 種別」だけを返す
        if (shownNames.Count == 0) return departmentAndType;

        // 載せきれなかった分類の件数。基準は「重なった分類の総数」なので、上限で切り捨てた分だけでなく
        // 名前を引けずに載せられなかった分類もここに数えられる(名前が引けない分を残件から
        // 落とすと、実際には重なっている分類が黙って消えて「これで全部」と誤読させてしまう)
        var hiddenCount = sharedCategoryIds.Count - shownNames.Count;

        // 上限件数までの分類名を「、」で連結する
        var causeText = string.Join("、", shownNames);
        // 載せきれなかった分があれば件数だけ添えて、分類が他にもあることを隠さない。
        // 単位を「分類」と明示するのは、同じアラートパネルに「ほか N 件の再発パターン」
        // (Views/Home/Index.cshtml)と「N 件の類似インシデント」が並ぶため。
        // ここだけ裸の「件」にすると、どれを数えた N なのかが読み手に伝わらない
        if (hiddenCount > 0) causeText = $"{causeText} ほか{hiddenCount}分類";

        // 「部署 / 種別（分類名…）」の形にして返す
        return $"{departmentAndType}（{causeText}）";
    }

    /// <summary>
    /// 再発パターン見出しの「部署 / 種別」部分を組み立てる。
    /// 原因分類を 1 つも出せないときの縮退表示（§9 fail-safe）もこの文字列になる。
    /// </summary>
    /// <remarks>
    /// 種別は enum の英語名ではなく日本語ラベル（<c>IncidentTypeLabel</c>）で表示する。
    /// 生の enum を文字列化すると "Medication" 等が医療現場の日本語 UI に漏れるため、
    /// 既存の計算プロパティ（唯一のラベル変換元）を再利用して表記を統一する。
    /// アラートの仮組み立て時と見出し確定時の 2 か所から使うので、書き写さずここに置く（§6 DRY）。
    /// </remarks>
    /// <param name="incident">アラートの基点インシデント。</param>
    /// <returns>「部署 / 種別」形式の文字列。</returns>
    private static string FormatDepartmentAndType(Incident incident) =>
        // 部署名と日本語のインシデント種別ラベルを「 / 」で連結する
        $"{incident.Department} / {incident.IncidentTypeLabel}";
}
