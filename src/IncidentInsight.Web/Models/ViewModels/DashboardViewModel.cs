// この ViewModel の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// トップダッシュボード画面に渡すモデル(KPI・アラートなどをまとめる)
public class DashboardViewModel
{
    // 集計期間を識別する文字列定数(クエリパラメータ・View のトグル・見出し導出で共用)。
    // HomeController もこの定数を別名参照しており、ここが唯一の真実の源(§6)
    public const string PeriodWeek    = "week";    // 直近 7 日間
    public const string PeriodMonth   = "month";   // 直近 1 か月
    public const string PeriodQuarter = "quarter"; // 直近 3 か月
    public const string PeriodYear    = "year";    // 直近 1 年(既定値)

    // 週表示のトレンドチャートで並べる日数。集計ループ(HomeController)と
    // 見出し(TrendChartTitle)の双方がこの定数から導出され、食い違いを防ぐ
    public const int WeekDays = 7;

    // Period filter ("week" | "month" | "quarter" | "year")
    // 集計期間(週/月/四半期/年)のフィルタ値
    public string Period { get; set; } = PeriodYear;

    // 月別トレンドチャートで並べる月数(month=4, quarter=6, それ以外=12)。
    // 集計バケット数(HomeController)と見出しの双方がこのマッピングを使う
    public static int MonthsFor(string period) => period switch
    {
        PeriodMonth   => 4,  // 月表示: 直近 4 ヶ月
        PeriodQuarter => 6,  // 四半期表示: 直近 6 ヶ月
        _             => 12  // 年表示(既定): 直近 12 ヶ月
    };

    // KPI
    // 累計インシデント数
    public int TotalIncidents { get; set; }
    // 今月に発生したインシデント数
    public int ThisMonthIncidents { get; set; }
    // 未完了の対策件数
    public int OpenMeasures { get; set; }
    // 期限超過の対策件数
    public int OverdueMeasures { get; set; }
    // 完了済みの対策件数
    public int CompletedMeasures { get; set; }

    // 対策の完了率(完了件数 ÷ 全件数 × 100)。対策がなければ 0 を返す
    public double CompletionRate => (OpenMeasures + CompletedMeasures) == 0
        ? 0
        : Math.Round((double)CompletedMeasures / (OpenMeasures + CompletedMeasures) * 100, 1);

    // Recent incidents
    // 最近のインシデント一覧(ダッシュボードに数件表示)
    public List<Incident> RecentIncidents { get; set; } = new();

    // Overdue measures for alert panel
    // 期限超過の対策リスト(アラート表示用)
    public List<PreventiveMeasure> OverdueMeasureList { get; set; } = new();

    // Recurrence alerts: incidents that share same department+type+cause as another recent incident
    // 再発アラート(同じ部署・種別・原因で類似案件があるインシデント)
    public List<RecurrenceAlert> RecurrenceAlerts { get; set; } = new();

    // Monthly trend data for sparkline chart (bucket window varies by Period)
    // トレンドチャート用の件数バケット(期間 Period に応じて日別7件/月別4・6・12件)
    public List<MonthlyCount> MonthlyCounts { get; set; } = new();

    // トレンドチャートの見出し。Period から導出する計算プロパティにすることで、
    // 構築側が設定し忘れて空見出しになる事故を防ぎ、バケット数(WeekDays / MonthsFor)と
    // 見出しの数字が常に一致することを保証する(見出しを View に直書きすると、
    // 週表示なのに「過去12ヶ月」と表示される等の食い違いが起きる)
    public string TrendChartTitle => Period == PeriodWeek
        ? $"日別インシデント発生推移（直近{WeekDays}日間）"
        : $"月別インシデント発生推移（直近{MonthsFor(Period)}ヶ月）";

    // Failed measures: RecurrenceObserved = true
    // 対策後も再発が確認された件数(効果なし対策の数)
    public int FailedMeasures { get; set; }
}

// 再発アラート1件分のデータ
public class RecurrenceAlert
{
    // 今回発生したインシデント(基点)
    public Incident CurrentIncident { get; set; } = null!;
    // 類似する過去インシデントのリスト
    public List<Incident> SimilarIncidents { get; set; } = new();
    // 「同部署+同種別+同原因」など、類似パターンの説明文
    public string PatternDescription { get; set; } = "";
}

// 月別件数1件分のデータ(棒グラフ/折れ線グラフ用)
public class MonthlyCount
{
    // 表示ラベル(例: "2024年3月")
    public string Label { get; set; } = ""; // e.g. "2024年3月"
    // その月の件数
    public int Count { get; set; }
}
