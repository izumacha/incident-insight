// ダッシュボードの ViewModel を使うために取り込む
using IncidentInsight.Web.Models;
// ViewModel(DashboardViewModel / RecurrenceAlert)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// DashboardViewModel.SetRecurrenceAlerts の契約テスト。
// 「表示分」と「検出総数」を別々に代入できると、片方の設定漏れや取り違えで
// HiddenRecurrenceAlertCount(「ほか N 件」の表示元)が実態とずれ、残件があるのに
// 「表示されている分で全部」と誤解させる。この唯一の設定経路が持つガードを固定する
// (コントローラ経由の HomeControllerTests では正常系しか通らないため、
//  ガードを外しても気付けない)。
public class DashboardViewModelTests
{
    // 再発アラートを 1 件作るヘルパー(判定に使うのは参照の同一性なので中身は最小限でよい)
    private static RecurrenceAlert MakeAlert(int incidentId) => new()
    {
        CurrentIncident = new Incident { Id = incidentId },
        SimilarIncidents = new List<Incident>(),
        PatternDescription = $"部署{incidentId} / 投薬"
    };

    [Fact]
    public void SetRecurrenceAlerts_DerivesTotalFromAllAlerts_AndExposesRemainderAsHidden()
    {
        // 検出は 4 件、そのうち 2 件だけをパネルに描画する状況を作る
        var all = new[] { MakeAlert(1), MakeAlert(2), MakeAlert(3), MakeAlert(4) };
        var vm = new DashboardViewModel();

        vm.SetRecurrenceAlerts(all, new[] { all[0], all[1] });

        // 表示分は渡した 2 件
        Assert.Equal(2, vm.RecurrenceAlerts.Count);
        // 総数は表示分ではなく検出全件から数える
        Assert.Equal(4, vm.RecurrenceAlertTotal);
        // 残り 2 件が「ほか N 件」として表示される
        Assert.Equal(2, vm.HiddenRecurrenceAlertCount);
    }

    [Fact]
    public void SetRecurrenceAlerts_WithAllAlertsDisplayed_ReportsNoHiddenRemainder()
    {
        // 全件を表示できる(上限に達していない)ケースでは残件表示を出さない
        var all = new[] { MakeAlert(1), MakeAlert(2) };
        var vm = new DashboardViewModel();

        vm.SetRecurrenceAlerts(all, all);

        Assert.Equal(2, vm.RecurrenceAlerts.Count);
        Assert.Equal(0, vm.HiddenRecurrenceAlertCount);
    }

    [Fact]
    public void SetRecurrenceAlerts_WithAlertOutsideDetectedSet_Throws()
    {
        // 別スコープで組み立てた一覧を渡す取り違え。件数だけ見ると素通りしてしまうため、
        // 所属(参照の同一性)まで確かめて弾くことを固定する
        var all = new[] { MakeAlert(1), MakeAlert(2) };
        var foreign = MakeAlert(99);
        var vm = new DashboardViewModel();

        Assert.Throws<ArgumentException>(() => vm.SetRecurrenceAlerts(all, new[] { foreign }));
    }

    [Fact]
    public void SetRecurrenceAlerts_WithDuplicatedDisplayedAlert_Throws()
    {
        // 同じアラートを 2 度渡すと、パネルに同じ行が並んだうえ表示件数が総数を超え、
        // HiddenRecurrenceAlertCount が 0 に丸められて「ほか N 件」が消える。
        // 所属チェックだけでは素通りするため、重複も別途弾く
        var all = new[] { MakeAlert(1), MakeAlert(2) };
        var vm = new DashboardViewModel();

        Assert.Throws<ArgumentException>(() => vm.SetRecurrenceAlerts(all, new[] { all[0], all[0] }));
    }

    [Fact]
    public void SetRecurrenceAlerts_WithNullArguments_Throws()
    {
        // どちらの引数が欠けているのかが分かる形で弾く(NullReferenceException にしない)
        var all = new[] { MakeAlert(1) };
        var vm = new DashboardViewModel();

        Assert.Throws<ArgumentNullException>(() => vm.SetRecurrenceAlerts(null!, all));
        Assert.Throws<ArgumentNullException>(() => vm.SetRecurrenceAlerts(all, null!));
    }

    [Fact]
    public void SetRecurrenceAlerts_RejectsLaterMutationOfTheDisplayedList()
    {
        // 呼び出し側が持っているリストを後から変更しても、ViewModel 側の表示分は動かない
        // (動くと表示件数と総数の対応が壊れ、HiddenRecurrenceAlertCount がずれる)
        var all = new List<RecurrenceAlert> { MakeAlert(1), MakeAlert(2), MakeAlert(3) };
        var displayed = new List<RecurrenceAlert> { all[0] };
        var vm = new DashboardViewModel();

        vm.SetRecurrenceAlerts(all, displayed);
        // 呼び出し側のリストへ後から追加してみる
        displayed.Add(all[1]);

        // ViewModel 側は設定時点の 1 件のままで、残件も 2 件のまま
        Assert.Single(vm.RecurrenceAlerts);
        Assert.Equal(2, vm.HiddenRecurrenceAlertCount);
    }
}
