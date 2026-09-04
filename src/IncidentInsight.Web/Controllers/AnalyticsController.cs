// 部署スコープ拡張メソッド
using IncidentInsight.Web.Authorization;
// 共通ヘルパ(日付上限フィルタの安全な排他的上限計算)を使う
using IncidentInsight.Web.Controllers.Internal;
// DbContext を使う
using IncidentInsight.Web.Data;
// モデル一式を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別など)を使う
using IncidentInsight.Web.Models.Enums;
// 絞り込み入力の「空かどうか」の唯一の真実の源(SearchFilter)を使う
using IncidentInsight.Web.Models.Validation;
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

/// <summary>
/// 分析画面とグラフ用 JSON API を提供するコントローラ(管理者/リスクマネージャー限定)。
/// </summary>
/// <remarks>
/// <para><b>発生部署の絞り込みは一覧画面と同じ方式に揃える(issue #204 課題 4)。</b>
/// <c>?department=</c> を受ける 3 つのエンドポイントは、値を
/// <see cref="Internal.DepartmentFilterResolver"/> に通してから使う ——
/// 「実データにあれば補完、無ければ採用しない」。方式の割り当てと理由は
/// <see cref="SearchFilter"/> の表が正本。</para>
///
/// <para><b>採用しなかったことは JSON で知らせる(<c>departmentFilterIgnored</c>)。</b>
/// 以前は <c>SearchFilter.HasValue</c> を通しただけの値をそのまま <c>Where</c> へ渡していたため、
/// 実在しない部署名を指す URL が<b>全 0 のグラフ</b>を注意書き無しで返していた
/// ——「この部署にはインシデントが 0 件だった」と読めるが、実際は「そんな部署は無い」。
/// 方式を揃えるとその URL は<b>絞り込みを外した全件</b>を返すので、黙って返すと今度は
/// 「絞り込んだつもりの全件」になる。どちらの誤読も避けられないので、
/// 採用しなかった事実を必ず添える(<c>/Incidents</c> が画面へ注意書きを出すのと同じ扱い)。</para>
///
/// <para><b>画面に注意書きが無いのは、この画面に部署の絞り込み UI がまだ無いから。</b>
/// <c>Views/Analytics/Index.cshtml</c> は部署のドロップダウンを持たず、
/// <c>Scripts/analytics.ts</c> も <c>?department=</c> を送らない ——現在この入力に
/// 到達できるのは URL を直接叩く経路(ブックマーク・外部の集計)だけなので、
/// 読み手はその JSON の利用側になる。<b>この画面に部署の絞り込みを足す人は、
/// この旗を読んで画面に注意書きを出すこと</b>(足さないと、絞り込みが効いていないグラフを
/// 「絞り込み中」の見た目で見せることになる)。</para>
///
/// <para><b>JSON の <c>{ labels, data }</c> 形状は変えない</b>(CLAUDE.md §3)。
/// 旗は既存の <c>colors</c> / <c>recurrenceStats</c> と同じく<b>足す</b>だけで、
/// 既存の 2 つのキーの意味も並びも動かさない。</para>
/// </remarks>
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

    /// <summary>
    /// <c>?department=</c> を共有リゾルバへ通す薄いラッパ。
    /// </summary>
    /// <remarks>
    /// 3 つのエンドポイントが同じ 2 行(スコープを掛けたクエリを組み立てて渡す)を書き写すと、
    /// スコープの掛け忘れが 1 か所だけ起きうる ——そこだけ Staff が
    /// <c>?department=</c> の総当たりで他部署の有無を推測できる穴になる(§9 最小公開)。
    /// <c>ScopedByUser</c> を通すのは、現在のポリシー(Admin / RiskManager 限定)では
    /// 実質全件になるが、ポリシーが広がったときに自動で安全側へ倒れるようにするため
    /// (§9 fail-safe)。<b>集計本体のクエリはスコープを掛けていない</b>ので、
    /// ポリシーを広げるときはそちらも同じ変更セットで手当てすること。
    /// </remarks>
    private Task<Internal.DepartmentFilterResolver.DepartmentFilterSelection> ResolveDepartmentFilterAsync(
        string? department)
        // 実在確認は「この画面が見せてよい範囲」の中だけで行う(契約は共有リゾルバの解説が正本)
        => Internal.DepartmentFilterResolver.ResolveAsync(
            _db.Incidents.AsNoTracking().ScopedByUser(User), department);

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
        // 部署指定があればさらに絞り込む。判定は一覧画面と同じ共有リゾルバへ寄せる
        // (実データにあれば採用、無ければ採用せず旗を立てる。規則は SearchFilter の表が正本)
        var departmentFilter = await ResolveDepartmentFilterAsync(department);
        // 採用した値だけを絞り込みに使う(採用しなかった場合は null なのでこの節を飛ばす)
        if (departmentFilter.Effective != null)
            query = query.Where(i => i.Department == departmentFilter.Effective);
        // 開始日指定があればさらに絞り込む(他エンドポイントと同様、既定の直近12ヶ月窓をさらに狭める)
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 終了日指定があればさらに絞り込む(その日を含める)
        // 排他的上限(翌日 0 時)は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(i => i.OccurredAt < dateToExclusive);
        }

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

        // Chart.js が期待する {labels, data} 形状で JSON 返却(旗は足すだけで形状は変えない)
        return Json(new { labels, data = counts, departmentFilterIgnored = departmentFilter.Ignored });
    }

    // GET /Analytics/ByCause
    // 原因分類(親カテゴリ)別の件数を返す
    public async Task<IActionResult> ByCause(DateTime? dateFrom, DateTime? dateTo, string? department)
    {
        // なぜなぜ分析テーブルをベースにする
        var query = _db.CauseAnalyses.AsNoTracking().AsQueryable();

        // 部署指定があれば絞る(判定は MonthlyTrend と同じ共有リゾルバ)
        var departmentFilter = await ResolveDepartmentFilterAsync(department);
        // 採用した値を式ツリーの外のローカルへ取り出してから使う
        // (「null でないことの確認」と「式ツリーが捕まえる値」を 1 か所で結び付ける)
        if (departmentFilter.Effective is string effectiveDepartment)
            query = query.Where(ca => ca.Incident.Department == effectiveDepartment);
        // 開始日指定があれば絞る
        if (dateFrom.HasValue)
            query = query.Where(ca => ca.Incident.OccurredAt >= dateFrom.Value);
        // 終了日指定があれば「翌日 0 時より前」で絞る(その日を含める)
        // 排他的上限は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(ca => ca.Incident.OccurredAt < dateToExclusive);
        }

        // 親カテゴリがあれば親名、なければ自分の名前でグループ化（サーバ側 GroupBy で集計）
        var grouped = await query
            .GroupBy(ca => ca.CauseCategory!.Parent != null
                ? ca.CauseCategory.Parent.Name
                : ca.CauseCategory.Name)
            .Select(g => new { label = g.Key ?? "不明", count = g.Count() })
            .OrderByDescending(x => x.count)
            .ToListAsync();

        // Chart.js 用にラベル配列とデータ配列を返す(旗は足すだけで形状は変えない)
        return Json(new
        {
            labels = grouped.Select(x => x.label),
            data = grouped.Select(x => x.count),
            departmentFilterIgnored = departmentFilter.Ignored
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
        // 排他的上限(翌日 0 時)は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(i => i.OccurredAt < dateToExclusive);
        }

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
        // 部署指定があれば絞る(判定は MonthlyTrend と同じ共有リゾルバ)
        var departmentFilter = await ResolveDepartmentFilterAsync(department);
        // 採用した値だけを絞り込みに使う
        if (departmentFilter.Effective != null)
            query = query.Where(i => i.Department == departmentFilter.Effective);
        // 開始日指定があれば絞る
        if (dateFrom.HasValue) query = query.Where(i => i.OccurredAt >= dateFrom.Value);
        // 終了日指定があれば絞る(その日を含める)
        // 排他的上限(翌日 0 時)は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(i => i.OccurredAt < dateToExclusive);
        }

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

        // Chart.js 用 JSON を返却(旗は足すだけで形状は変えない)
        return Json(new
        {
            labels = ordered.Select(x => x.label),
            data = ordered.Select(x => x.count),
            departmentFilterIgnored = departmentFilter.Ignored
        });
    }

    // GET /Analytics/MeasureStatus
    // 対策のステータス(計画/進行/期限超過/完了)の件数を返す
    public async Task<IActionResult> MeasureStatus()
    {
        // 「期限超過」の唯一の定義は PreventiveMeasure.OverdueOn(today)。
        // ただし下の GroupBy 集計は g.Count(...) の射影(式ツリー)内で外部の Expression を
        // 差し込めないため、OverdueOn と同一条件 (Status != Completed && DueDate < today) を
        // インライン展開する。条件を変えるときは OverdueOn と両方を必ず一致させること。
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

        // ラベル・件数・色をひとまとめにして JSON 返却(Chart.js の Doughnut 用)。
        // ラベルは日本語文字列を直書きせず EnumLabels(ラベルの一元管理元)から引く(§6)。
        // 直書きしていた頃は、同じ「計画中 / 進行中 / 完了」が EnumLabels.StatusJa と
        // ここの 2 箇所に存在し、片方だけ表記を変えるとカンバンのバッジと分析グラフで
        // 名前が食い違う状態になりえた。enum に無い派生状態の「期限超過」だけは
        // EnumLabels.MeasureOverdueLabel を唯一の源とする。
        // 色も16進値を直書きせず EnumLabels.Hex(色の一元管理元)から引く(§6。
        // 計画中=warning / 進行中=primary / 期限超過=danger / 完了=success)
        return Json(new
        {
            labels = new[]
            {
                EnumLabels.Japanese(Models.Enums.MeasureStatus.Planned),
                EnumLabels.Japanese(Models.Enums.MeasureStatus.InProgress),
                EnumLabels.MeasureOverdueLabel,
                EnumLabels.Japanese(Models.Enums.MeasureStatus.Completed)
            },
            data = new[] { planned, inProgress, overdue, completed },
            colors = new[]
            {
                EnumLabels.Hex("warning"),
                EnumLabels.Hex("primary"),
                EnumLabels.Hex("danger"),
                EnumLabels.Hex("success")
            }
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
        // 段階の一覧は EffectivenessScale(段階数の唯一の源)から引く。
        // 以前は Enumerable.Range(1, 5) と書いており、段階数を増やしても
        // このグラフだけ 5 本のままになる状態だった(§6)
        var scale = EffectivenessScale.All.ToList();
        // 低い評価から順に件数配列を作成(該当する評価が 1 件も無ければ 0)
        var counts = scale
            .Select(r => byRating.TryGetValue(r, out var c) ? c : 0)
            .ToList();

        // 再発確認あり件数
        var recurred = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == true);
        // 再発なし件数
        var prevented = await _db.PreventiveMeasures.AsNoTracking()
            .CountAsync(m => m.RecurrenceObserved == false);

        // Chart.js 用のラベル・データ + 再発統計を返す。
        // ラベルと配色は EffectivenessScale(語彙と配色の唯一の源)から解決する。
        // 直書きしていた頃は、同じ「効果なし / 普通 / 非常に効果あり」がレビュー画面・詳細画面・
        // ViewModel・ここの 4 箇所に散在し、片方だけ言い回しを変えると画面ごとに食い違った(§6)。
        // 配色を JSON に載せるのは MeasureStatus と同じ方針: JS 側に 16 進値を直書きさせないため
        return Json(new
        {
            labels = scale.Select(EffectivenessScale.ChartLabel),
            data = counts,
            colors = scale.Select(r => EnumLabels.Hex(EffectivenessScale.ColorName(r))),
            recurrenceStats = new { recurred, prevented }
        });
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
        // 排他的上限(翌日 0 時)は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の発生日時だけに絞る
            query = query.Where(i => i.OccurredAt < dateToExclusive);
        }

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
