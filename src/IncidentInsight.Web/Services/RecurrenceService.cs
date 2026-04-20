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

        // 最近発生したインシデントを新しい順に取得(原因分類も同時ロード)
        var recentList = await scope
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .Where(i => i.OccurredAt >= since)
            .OrderByDescending(i => i.OccurredAt)
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
        // 候補を1回のクエリでまとめて取得(あとはメモリ上で厳密にマッチング)
        var candidates = recentCatIds.Count == 0
            ? new List<Incident>()
            : await scope
                .AsNoTracking()
                .Include(i => i.CauseAnalyses)
                .Where(i => recentDepts.Contains(i.Department)
                    && recentTypes.Contains(i.IncidentType)
                    && i.CauseAnalyses.Any(ca => recentCatIds.Contains(ca.CauseCategoryId)))
                .ToListAsync(ct);

        // 候補を (部署, 種別) のキーでグルーピングして高速検索できるようにする
        var candidatesByKey = candidates.ToLookup(i => (i.Department, i.IncidentType));

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
                    PatternDescription = $"{incident.Department} / {incident.IncidentType}"
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
