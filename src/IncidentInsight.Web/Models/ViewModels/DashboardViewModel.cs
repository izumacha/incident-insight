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
    // 再発アラート(同じ部署・種別・原因で類似案件があるインシデント)。
    // パネルに描画する分だけを保持する。上限件数と並び順(類似件数の多い順)は
    // HomeController.RecurrenceAlertLimit / SelectForAlertPanel が決める。
    // 総数(RecurrenceAlertTotal)と必ず対で更新されるよう、設定経路は
    // SetRecurrenceAlerts だけに絞る(private set)。
    // 型を IReadOnlyList にするのは、private set が防げるのが「差し替え」だけで
    // 「中身の追加・削除」は防げないため。List のまま公開すると
    // RecurrenceAlerts.RemoveAll(...) のような後からの操作で件数だけが動き、
    // HiddenRecurrenceAlertCount が実態とずれる(表示件数と総数の対応が壊れる)
    public IReadOnlyList<RecurrenceAlert> RecurrenceAlerts { get; private set; } = new List<RecurrenceAlert>();

    // 検出された再発パターンの数(表示を上限で絞っても数え落とさないために別に持つ)。
    // 表示分(RecurrenceAlerts)と総数を分ける役割分担は OverdueMeasureList(表示分)と
    // OverdueMeasures(KPI)と同じだが、数え方の厳密さは異なる: OverdueMeasures は DB 側の
    // CountAsync による実数なのに対し、こちらは IRecurrenceService が返したアラート件数
    // そのもので、同サービスが候補読み込みに掛けている上限
    // (RecurrenceService.MaxAlertCandidateRows)の影響を受ける。直近 90 日のインシデントが
    // その上限を超える環境では検出自体が漏れるため、この値は「検出できた範囲での件数」
    // であって全期間の厳密な再発パターン総数ではない
    public int RecurrenceAlertTotal { get; private set; }

    // パネルに載せきれなかった再発パターンの件数。View はこの値が正のときだけ
    // 「ほか N 件」を表示する。差し引きが負になることは SetRecurrenceAlerts の
    // 引数チェックで排除しているが、既定値(どちらも空/0)のときに 0 を返すため Max で下限を切る
    public int HiddenRecurrenceAlertCount => Math.Max(0, RecurrenceAlertTotal - RecurrenceAlerts.Count);

    /// <summary>
    /// 再発アラートの「検出された全件」と「パネルに描画する分」をまとめて設定する。
    /// </summary>
    /// <remarks>
    /// 表示分と総数を別々に代入できる形にしておくと、片方だけ設定した呼び出しで
    /// <see cref="HiddenRecurrenceAlertCount"/> が 0 になり、残件があるのに「ほか N 件」が
    /// 黙って消える(利用者は表示分で全部だと誤解する)。総数を引数から必ず導出することで、
    /// その食い違い自体を起こせなくする。
    /// </remarks>
    /// <param name="allAlerts">検出された再発アラート全件(総数の算出元)。</param>
    /// <param name="displayed">パネルへ描画する分(<paramref name="allAlerts"/> の部分集合)。</param>
    public void SetRecurrenceAlerts(
        IReadOnlyCollection<RecurrenceAlert> allAlerts,
        IEnumerable<RecurrenceAlert> displayed)
    {
        // 引数が null なら、どちらが欠けているかが分かる形で弾く(NullReferenceException にしない)
        ArgumentNullException.ThrowIfNull(allAlerts);
        ArgumentNullException.ThrowIfNull(displayed);

        // 表示分を確定させる(呼び出し側の遅延評価をここで打ち切る)
        var displayedList = displayed.ToList();

        // 表示分が全件を上回るのは引数の取り違え。代入より前に弾き、
        // 例外を握り潰す呼び出し側が現れても ViewModel が矛盾した状態で描画されないようにする
        // (矛盾したまま描画されると HiddenRecurrenceAlertCount が 0 になり、
        //  残件があるのに「ほか N 件」が消えて「表示分で全部」と誤解させる)
        if (displayedList.Count > allAlerts.Count)
        {
            throw new ArgumentException(
                "表示する再発アラートが検出総数を超えています(allAlerts と displayed の取り違え)。",
                nameof(displayed));
        }

        // ここまで来たら整合しているので、表示分と総数をまとめて確定させる
        RecurrenceAlerts = displayedList;
        // 総数は必ず全件側から数える(表示分と食い違わないようにするための唯一の算出元)
        RecurrenceAlertTotal = allAlerts.Count;
    }

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
    // ドリルダウン(チャートのデータ点クリック → インシデント一覧)用の絞り込み開始日("yyyy-MM-dd")。
    // 以前はクライアント側で表示ラベル(「2024年3月」)を正規表現でパースして期間を組み立てていたが、
    // 週表示のラベル("M/d")には年情報がなくパース不能でクリックが無反応になっていた。
    // サーバー側でバケットの実期間をそのまま渡すことで、表示形式に依存せず全期間で動作させる
    public string DateFrom { get; set; } = "";
    // ドリルダウン用の絞り込み終了日("yyyy-MM-dd")。Incidents 一覧の dateTo は「その日を含む」扱い
    public string DateTo { get; set; } = "";
}
