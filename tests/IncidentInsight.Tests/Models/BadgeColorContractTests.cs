// 配色の一元管理元(EnumLabels)と各尺度を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;
// エンティティの計算プロパティ(StatusColorOn / MeasureTypeColor 等)を呼ぶために取り込む
using IncidentInsight.Web.Models;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// バッジ(<span class="badge bg-@...">)として描画される配色が、
// 実在する Bootstrap のテーマ色に収まっていることを横断的に検査する。
//
// 背景: Bootstrap カラー名 → 16 進の変換表(EnumLabels.BootstrapHexMap)は Chart.js のために
// テーマ色ではない拡張パレット(orange 等)も載せている。そのため「16 進へ解決できるか」だけを
// 見ていると、.bg-orange のような存在しないクラスが選ばれても検査を素通りし、
// 背景色の付かないバッジが静かに描画される。
//
// 優先度尺度についてのみ MeasurePriorityScaleTests でこの検査を入れたが、bg-@ で描画される
// 配色源は他にもある(重症度・対策ステータス・対策種別・監査操作)。1 つの尺度だけ守っても
// 残りが fail-open では意味が薄いため、全ての配色源をここでまとめて固定する。
public class BadgeColorContractTests
{
    [Fact]
    public void SeverityColors_AreAllBadgeUsable()
    {
        // 重症度の全段階について色名を検査する
        foreach (var severity in EnumLabels.AllSeverities)
        {
            // その重症度に割り当てられた色名を引く
            var colorName = EnumLabels.Color(severity);
            // バッジの bg-* クラスとして成立する色名であること
            Assert.True(
                EnumLabels.IsBadgeUsable(colorName),
                $"重症度 {severity} の配色 '{colorName}' は badge の bg-* クラスとして使えない");
        }
    }

    [Fact]
    public void MeasureTypeColors_AreAllBadgeUsable()
    {
        // 対策種別の全ての値について色名を検査する
        foreach (var measureType in Enum.GetValues<MeasureTypeKind>())
        {
            // その種別に割り当てられた色名を引く
            var colorName = EnumLabels.MeasureTypeColor(measureType);
            // バッジの bg-* クラスとして成立する色名であること
            Assert.True(
                EnumLabels.IsBadgeUsable(colorName),
                $"対策種別 {measureType} の配色 '{colorName}' は badge の bg-* クラスとして使えない");
        }
    }

    [Fact]
    public void MeasureStatusColors_AreAllBadgeUsable()
    {
        // 期限内・期限超過の両方を再現するため、期限日を基準日の前後に振った対策を用意する
        foreach (var status in Enum.GetValues<MeasureStatus>())
        {
            // 期限内(期限が明日)のケースと期限超過(期限が昨日)のケースを両方見る。
            // StatusColorOn は期限超過で danger へ切り替わるため、片方だけでは全分岐を通らない
            foreach (var dueDate in new[] { TestFixtures.Today.AddDays(1), TestFixtures.Today.AddDays(-1) })
            {
                // 対象のステータスと期限を持つ対策を組み立てる
                var measure = new PreventiveMeasure { Status = status, DueDate = dueDate };
                // その状態で表示される色名を引く
                var colorName = measure.StatusColorOn(TestFixtures.Today);
                // バッジの bg-* クラスとして成立する色名であること
                Assert.True(
                    EnumLabels.IsBadgeUsable(colorName),
                    $"対策ステータス {status}(期限 {dueDate:yyyy-MM-dd})の配色 '{colorName}' は"
                    + " badge の bg-* クラスとして使えない");
            }
        }
    }

    [Fact]
    public void PriorityColors_AreAllBadgeUsable()
    {
        // 優先度の全段階について色名を検査する(MeasurePriorityScaleTests と重複するが、
        // 「bg-@ で描く配色源の一覧」をこのファイル 1 枚で見渡せるようにするため残す)
        foreach (var priority in MeasurePriorityScale.All)
        {
            // その段階に割り当てられた色名を引く
            var colorName = MeasurePriorityScale.ColorName(priority);
            // バッジの bg-* クラスとして成立する色名であること
            Assert.True(
                EnumLabels.IsBadgeUsable(colorName),
                $"優先度 {priority} の配色 '{colorName}' は badge の bg-* クラスとして使えない");
        }
    }

    [Fact]
    public void AuditOperationColors_AreAllBadgeUsable()
    {
        // 監査ログの操作種別(インターセプタが書き込む 3 種)について色名を検査する
        foreach (var operation in new[] { "Added", "Modified", "Deleted" })
        {
            // その操作に割り当てられた色名を引く
            var colorName = EnumLabels.AuditOperationColor(operation);
            // バッジの bg-* クラスとして成立する色名であること
            Assert.True(
                EnumLabels.IsBadgeUsable(colorName),
                $"監査操作 {operation} の配色 '{colorName}' は badge の bg-* クラスとして使えない");
        }
    }

    [Fact]
    public void BadgeUsableColors_AllResolveToADistinctHex()
    {
        // バッジで使える色は、同じ意味を Chart.js で描くときのために 16 進も引けなければならない。
        // 許可リストにだけ色を足して変換表を直し忘れると、バッジは正しく塗られるのに
        // グラフだけ Hex() のフォールバックでグレーになる、という画面間のズレが生まれる。
        // EnumLabels のコメントが宣言しているこの不変条件を機械的に固定する
        // (Hex は未知の色名を secondary の 16 進へ倒すので、取りこぼしは重複として現れる)。
        var badgeColors = EnumLabels.BadgeUsableColorNamesForTesting.ToList();
        // 各色名を 16 進へ解決する
        var hexes = badgeColors.Select(EnumLabels.Hex).ToList();

        // 変換表に無い色名が混ざっていれば secondary の 16 進と重複してここで落ちる
        Assert.Equal(hexes.Count, hexes.Distinct().Count());
    }
}
