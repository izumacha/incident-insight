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
                // アラートを1件組み立ててリストに追加
                alerts.Add(new RecurrenceAlert
                {
                    CurrentIncident = incident,
                    SimilarIncidents = similar,
                    // 種別は enum の英語名ではなく日本語ラベル(IncidentTypeLabel)で表示する。
                    // 生の enum を文字列化すると "Medication" 等が医療現場の日本語UIに漏れるため、
                    // 既存の計算プロパティ(唯一のラベル変換元)を再利用して表記を統一する。
                    PatternDescription = $"{incident.Department} / {incident.IncidentTypeLabel}"
                });
                // 処理済みとして記録(以降の巡回で再び採用しないようにする)
                processed.Add(incident.Id);
                // 類似側も処理済み扱いにして重複アラートを防ぐ
                foreach (var s in similar) processed.Add(s.Id);
            }
        }

        // 集まった再発アラートのリストを返す
        return alerts;
    }
}
