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

    // 集計期間の選択肢(識別子と画面のラベルの対)。<b>期間についての唯一の真実の源</b>で、
    // 許可リスト(Periods)も画面の期間切替ボタンも既定の表示名もここから導く。
    //
    // <b>なぜ対にして 1 本にするのか。</b> 以前は識別子の配列(許可リスト)と、画面に
    // 手書きで並ぶ 4 つのボタンが別々の宣言で、ずれても<b>どちらの向きでも動いてしまう</b>:
    // 許可リストだけに増えた識別子は「押せないのに受け付ける」隠し値になり、ボタンだけに
    // 増えた識別子は<b>押した瞬間に「選べる値ではない」の注意書きが出る</b>
    // (画面が自分で出したリンクを自分で拒否する)。当初はその食い違いをビューのソース走査で
    // 見張っていたが、<b>実測でその走査には穴があった</b> ——リンクをタグヘルパー
    // (asp-route-period)で書いた 5 つ目のボタンは走査の綴りに当たらず、全件緑のまま
    // 上の「自分で出したリンクを自分で拒否する」状態が作れた。
    // 走査に綴りを足していく道は取らず(この repo が繰り返し記録している
    // 「近似である限りどちらかの穴が必ず残る」形)、<b>食い違いが構造的に作れない形</b>へ寄せた
    // ——ビューはこの配列を回してボタンを描くので、2 つ目の宣言そのものが存在しない。
    //
    // 並びはそのまま画面の並び(週 → 月 → 四半期 → 1年)。
    // ラベルもここに持つのは §6「UI 文言は単一の参照元に集約する」に従うため
    // (注意書きが案内する既定の期間名も DefaultPeriodLabel 経由でここを読む)
    public static readonly (string Id, string Label)[] PeriodChoices =
    {
        (PeriodWeek, "週"),
        (PeriodMonth, "月"),
        (PeriodQuarter, "四半期"),
        (PeriodYear, "1年"),
    };

    // 集計期間として受け付ける値の許可リスト(クエリ文字列の ?period= を照合する唯一の源)。
    // 選択肢から導くので、画面に出していない値を受け付ける状態は作れない
    public static readonly string[] Periods =
        PeriodChoices.Select(choice => choice.Id).ToArray();

    // 既定の集計期間の表示名。採用しなかった期間の注意書きが「既定の『◯◯』で集計しています」と
    // 案内するのに使う ——文言を注意書きへ直書きすると、ボタンのラベルを変えたときに
    // 画面に無いボタンを探させる案内が残る(§6 UI 文言の単一参照元)
    public static readonly string DefaultPeriodLabel =
        PeriodChoices.First(choice => choice.Id == PeriodYear).Label;

    // Period filter ("week" | "month" | "quarter" | "year")
    // 集計期間(週/月/四半期/年)のフィルタ値
    public string Period { get; set; } = PeriodYear;

    // 集計期間の値を受け取ったが、選べる値(Periods)に無かったので採用しなかったかどうか
    // (true なら画面で知らせる。issue #220 の規則をこの画面へ適用したもの)。
    //
    // <b>黙って既定へ戻さない理由。</b> ?period=quater のような打ち間違い・古いブックマークは
    // 既定の「1年」へ丸められるが、丸めた事実はどこにも出ない ——利用者は四半期のつもりで
    // 1 年分の KPI・トレンド・完了率を読み、期間切替は「1年」が選択中に見えるので
    // 食い違いにも気付けない。一覧画面が ?severity=99 について注意書きを出すのと
    // まったく同じ出来事(「受け取ったが選べる値ではない」)なので、伝え方もそろえる。
    // 規則の正本は Models/Validation/SearchFilter の表(「採用しなかったなら必ず伝える」に
    // 例外は無い)、判定の正本は Controllers/Internal/ListedValueFilterResolver。
    //
    // 値そのものではなく真偽値なのは、外部由来の文字列をアプリ自身の文章へ埋め込まない
    // 方針が一覧画面と同じだから(理由の正本は IncidentListViewModel.DepartmentFilterIgnored)。
    //
    // <b>この画面だけ「採用しない」では済まない。</b> ダッシュボードには「期間なし」という
    // 状態が無い(常に何らかの窓で集計する)ので、採用しなかったときは既定の期間へ補完する。
    // 方式が一覧画面と違っても旗は同じように立てる —— 方式と伝え方は別の軸(issue #220)
    public bool UnlistedFilterIgnored { get; set; }

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
    // 型を IReadOnlyList にし、中身も ReadOnlyCollection で包むのは、private set が防げるのが
    // 「差し替え」だけで「中身の追加・削除」は防げないため。List のまま公開すると
    // RecurrenceAlerts.RemoveAll(...) のような後からの操作(IReadOnlyList で公開しても
    // List へダウンキャストすれば可能)で件数だけが動き、HiddenRecurrenceAlertCount が
    // 実態とずれる(表示件数と総数の対応が壊れる)
    public IReadOnlyList<RecurrenceAlert> RecurrenceAlerts { get; private set; } =
        new List<RecurrenceAlert>().AsReadOnly();

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

        // 表示分が全件の部分集合になっていなければ引数の取り違え。代入より前に弾き、
        // 例外を握り潰す呼び出し側が現れても ViewModel が矛盾した状態で描画されないようにする
        // (矛盾したまま描画されると HiddenRecurrenceAlertCount が「どの残件も指さない数」になり、
        //  残件があるのに「ほか N 件」が消えたり、実在しない残件数を表示したりする)。
        // 件数の大小だけでなく所属も確かめるのは、別スコープで組み立てた一覧を渡された場合
        // (件数さえ少なければ素通りしてしまう)を弾くため。アラートは同じ検出結果から
        // 組み立てられるので、同一インスタンスかどうか(参照の一致)で判定できる
        var detected = new HashSet<object>(allAlerts, ReferenceEqualityComparer.Instance);
        // 表示分から重複を除いた集合。所属チェックと「同じものを 2 度渡していないか」の
        // 両方をこの 1 つの集合で見る
        var displayedDistinct = new HashSet<object>(displayedList, ReferenceEqualityComparer.Instance);
        if (!displayedDistinct.IsSubsetOf(detected))
        {
            throw new ArgumentException(
                "表示する再発アラートが検出結果に含まれていません(allAlerts と displayed の取り違え)。",
                nameof(displayed));
        }
        // 同じアラートを 2 度渡されると、パネルに同じ行が並んだうえ
        // RecurrenceAlerts.Count が総数を超え、HiddenRecurrenceAlertCount が 0 に丸められて
        // 「ほか N 件」が消える(所属チェックだけでは素通りする)
        if (displayedDistinct.Count != displayedList.Count)
        {
            throw new ArgumentException(
                "表示する再発アラートに同じものが重複して含まれています。",
                nameof(displayed));
        }

        // ここまで来たら整合しているので、表示分と総数をまとめて確定させる。
        // AsReadOnly でラップして、IReadOnlyList へダウンキャストして中身を書き換える経路も塞ぐ
        RecurrenceAlerts = displayedList.AsReadOnly();
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
