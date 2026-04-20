// 部署スコープ拡張メソッド
using IncidentInsight.Web.Authorization;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル一式を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別など)を使う
using IncidentInsight.Web.Models.Enums;
// 時刻源サービス
using IncidentInsight.Web.Services;
// 認可属性
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底
using Microsoft.AspNetCore.Mvc;
// EF Core 拡張
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// 分析画面とグラフ用 JSON API を提供するコントローラ(管理者/リスクマネージャー限定)
[Authorize(Policy = Policies.CanViewAnalytics)]
public class AnalyticsController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // 時刻源(テスト差し替え可能)
    private readonly IClock _clock;

    // コンストラクタ: DI で依存を受け取る
    public AnalyticsController(ApplicationDbContext db, IClock clock)
    {
        _db = db;
        _clock = clock;
    }

    // 分析トップページのビューを返す
    public IActionResult Index() => View();

    // GET /Analytics/MonthlyTrend
    // 過去 12 ヶ月の月別インシデント件数を返す
    public async Task<IActionResult> MonthlyTrend(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        // 今日の日付
        var today = _clock.Today;
        // 12 ヶ月前の月初を計算
        var firstMonthStart = new DateTime(today.Year, today.Month, 1).AddMonths(-11);

        // ベースクエリ(読み取り専用 + 期間フィルタ)
        var query = _db.Incidents.AsNoTracking()
            .Where(i => i.OccurredAt >= firstMonthStart);
        // 部署指定があればさらに絞り込む
        if (!string.IsNullOrEmpty(department)) query = query.Where(i => i.Department == department);

        // 年月ごとに SQL 側でグループ化して件数を取得
        var groups = await query
            .GroupBy(i => new { i.OccurredAt.Year, i.OccurredAt.Month })
            .Select(g => new { g.Key.Year, g.Key.Month, Count = g.Count() })
            .ToListAsync();
        // (年,月) をキーにした辞書へ変換
        var byMonth = groups.ToDictionary(g => (g.Year, g.Month), g => g.Count);

        // Chart.js に渡すラベル配列
        var labels = new List<string>();
        // 件数配列
        var counts = new List<int>();
        // 古い月から順にラベルと件数を詰める(データが無い月は 0)
        for (int i = 11; i >= 0; i--)
        {
            var start = new DateTime(today.Year, today.Month, 1).AddMonths(-i);
            labels.Add(start.ToString("M月"));
            byMonth.TryGetValue((start.Year, start.Month), out var count);
            counts.Add(count);
        }

        // Chart.js が期待する {labels, data} 形状で JSON 返却
        return Json(new { labels, data = counts });
    }

    // GET /Analytics/ByCause
    // 原因分類(親カテゴリ)別の件数を返す
    public async Task<IActionResult> ByCause(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        // なぜなぜ分析テーブルをベースにする
        var query = _db.CauseAnalyses.AsNoTracking().AsQueryable();

        // 部署指定があれば絞る
        if (!string.IsNullOrEmpty(department))
            query = query.Where(ca => ca.Incident.Department == department);
        // 開始日指定があれば絞る
        if (dateFrom.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt >= dateFrom.Value);
        // 終了日指定があれば「翌日 0 時より前」で絞る(その日を含める)
        if (dateTo.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt < dateTo.Value.Date.AddDays(1));

        // GroupBy runs on the server: we pick the parent name when present, otherwise
        // the leaf name, without materializing each CauseAnalysis row.
        // 親カテゴリがあれば親名、なければ自分の名前でグループ化
        var grouped = await query
            .GroupBy(ca => ca.CauseCategory!.Parent != null
                ? ca.CauseCategory.Parent.Name
                : ca.CauseCategory.Name)
            .Select(g => new { label = g.Key ?? "不明", count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        // Chart.js 用にラベル配列とデータ配列を返す
        return Json(new
        {
            labels = grouped.Select(x => x.label),
            data = grouped.Select(x => x.count)
        });
    }

    // GET /Analytics/ByDepartment
    // 部署別のインシデント件数を返す
    public async Task<IActionResult> ByDepartment(DateTime? dateFrom, DateTime? dateTo)
    {
        // 読み取り専用クエリを用意
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        // 開始日で絞り込み
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 終了日で絞り込み(その日を含める)
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

        // 部署でグループ化し、件数の多い順に並べる
        var grouped = await query
            .GroupBy(i => i.Department)
            .Select(g => new { department = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        // Chart.js 用の JSON 形状で返却
        return Json(new
        {
            labels = grouped.Select(x => x.department),
            data = grouped.Select(x => x.count)
        });
    }

    // GET /Analytics/BySeverity
    // 重症度別の件数を返す
    public async Task<IActionResult> BySeverity(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        // 読み取り専用クエリを用意
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        // 部署指定があれば絞る
        if (!string.IsNullOrEmpty(department)) query = query.Where(i => i.Department == department);
        // 開始日指定があれば絞る
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 終了日指定があれば絞る(その日を含める)
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

        // 重症度でグループ化して件数を取得
        var grouped = await query
            .GroupBy(i => i.Severity)
            .Select(g => new { severity = g.Key, count = g.Count() })
            .ToListAsync();

        // enum 定義順に整列。存在しない重症度は 0 件で埋める
        var ordered = Enum.GetValues<IncidentSeverity>()
            .Select(s => new
            {
                label = EnumLabels.Japanese(s),
                count = grouped.FirstOrDefault(g => g.severity == s)?.count ?? 0
            })
            .ToList();

        // Chart.js 用 JSON を返却
        return Json(new
        {
            labels = ordered.Select(x => x.label),
            data = ordered.Select(x => x.count)
        });
    }

    // GET /Analytics/MeasureStatus
    // 対策のステータス(計画/進行/期限超過/完了)の件数を返す
    public async Task<IActionResult> MeasureStatus()
    {
        // IsOverdue is a CLR-only computed property, so we inline its predicate
        // (Status != Completed && DueDate < today) so EF can translate it.
        // 今日の日付(JST)
        var today = _clock.Today;
        // 単一行で 4 種類の件数を一度に集計(SQL 1 本に集約)
        var counts = await _db.PreventiveMeasures.AsNoTracking()
            .GroupBy(_ => 1)
            .Select(g => new
            {
                Planned    = g.Count(m => m.Status == Models.Enums.MeasureStatus.Planned    && m.DueDate >= today),
                InProgress = g.Count(m => m.Status == Models.Enums.MeasureStatus.InProgress && m.DueDate >= today),
                Overdue    = g.Count(m => m.Status != Models.Enums.MeasureStatus.Completed  && m.DueDate <  today),
                Completed  = g.Count(m => m.Status == Models.Enums.MeasureStatus.Completed)
            })
            .FirstOrDefaultAsync();

        // データが無い場合は全て 0 を既定値として使う
        var planned = counts?.Planned ?? 0;
        var inProgress = counts?.InProgress ?? 0;
        var overdue = counts?.Overdue ?? 0;
        var completed = counts?.Completed ?? 0;

        // ラベル・件数・色をひとまとめにして JSON 返却(Chart.js の Doughnut 用)
        return Json(new
        {
            labels = new[] { "計画中", "進行中", "期限超過", "完了" },
            data = new[] { planned, inProgress, overdue, completed },
            colors = new[] { "#ffc107", "#0d6efd", "#dc3545", "#198754" }
        });
    }

    // GET /Analytics/EffectivenessRating
    // 有効性評価(1〜5)ごとの件数と、再発有無の内訳を返す
    public async Task<IActionResult> EffectivenessRating()
    {
        // 評価が入っているレコードだけを評価値でグループ化
        var ratings = await _db.PreventiveMeasures.AsNoTracking()
            .Where(m => m.EffectivenessRating != null)
            .GroupBy(m => m.EffectivenessRating!.Value)
            .Select(g => new { Rating = g.Key, Count = g.Count() })
            .ToListAsync();

        // 評価値をキーにした辞書に変換
        var byRating = ratings.ToDictionary(x => x.Rating, x => x.Count);
        // 1〜5 の順に件数配列を作成(無い評価は 0)
        var counts = Enumerable.Range(1, 5)
            .Select(r => byRating.TryGetValue(r, out var c) ? c : 0)
            .ToList();

        // 再発確認あり件数
        var recurred = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == true);
        // 再発なし件数
        var prevented = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == false);

        // Chart.js 用のラベル・データ + 再発統計を返す
        return Json(new
        {
            labels = new[] { "★1 (効果なし)", "★2", "★3 (普通)", "★4", "★5 (非常に効果あり)" },
            data = counts,
            recurrenceStats = new { recurred, prevented }
        });
    }

    // GET /Analytics/GetSubcategories?parentId=1
    // 親カテゴリに紐づく子カテゴリ一覧を返す(ドロップダウン連動用)
    public async Task<IActionResult> GetSubcategories(int parentId)
    {
        // 子カテゴリを表示順で取得
        var children = await _db.CauseCategories.AsNoTracking()
            .Where(c => c.ParentId == parentId)
            .OrderBy(c => c.DisplayOrder)
            .Select(c => new { c.Id, c.Name })
            .ToListAsync();

        // JSON で返却
        return Json(children);
    }

    // GET /Analytics/ByIncidentType
    // インシデント種別別の件数を返す
    public async Task<IActionResult> ByIncidentType(DateTime? dateFrom, DateTime? dateTo)
    {
        // ベースクエリを用意
        var query = _db.Incidents.AsNoTracking().AsQueryable();
        // 開始日で絞り込み
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 終了日で絞り込み(当日を含める)
        if (dateTo.HasValue) query = query.Where(i => i.OccurredAt < dateTo.Value.Date.AddDays(1));

        // インシデント種別でグループ化し、件数の多い順に並べる
        var grouped = await query
            .GroupBy(i => i.IncidentType)
            .Select(g => new { type = g.Key, count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        // enum を日本語ラベルに変換して JSON 返却
        return Json(new
        {
            labels = grouped.Select(x => IncidentTypeMapping.JapaneseLabel(x.type)),
            data = grouped.Select(x => x.count)
        });
    }
}
