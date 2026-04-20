// この ViewModel の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// トップダッシュボード画面に渡すモデル(KPI・アラートなどをまとめる)
public class DashboardViewModel
{
    // Period filter ("week" | "month" | "quarter" | "year")
    // 集計期間(週/月/四半期/年)のフィルタ値
    public string Period { get; set; } = "year";

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

    // Monthly trend data for sparkline chart (last 12 months)
    // 過去12ヶ月の月別件数(スパークライン用)
    public List<MonthlyCount> MonthlyCounts { get; set; } = new();

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
