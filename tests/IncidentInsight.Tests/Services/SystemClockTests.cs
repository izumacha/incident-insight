// 時刻源サービス(SystemClock)を使うために取り込む
using IncidentInsight.Web.Services;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Services;

// SystemClock が OS のタイムゾーン設定に依存せず JST を返すことを固定するテスト。
// 以前は DateTime.Now をそのまま返しており「OS が JST」という暗黙の前提があったため、
// UTC 既定の Linux コンテナ / クラウドに配備すると全タイムスタンプが 9 時間ずれていた
// (Issue #31 と同種のバグ)。CI は UTC で動くため、このテスト自体が回帰検知になる。
public class SystemClockTests
{
    [Fact]
    public void Now_ReturnsJst_RegardlessOfHostTimeZone()
    {
        // テスト対象の時計を生成する
        var clock = new SystemClock();
        // 期待値: UTC の現在時刻 + 9 時間(JST はサマータイムが無いので常に +09:00)
        var expected = DateTime.UtcNow.AddHours(9);
        // 実際の値を取得する
        var actual = clock.Now;

        // 呼び出しタイミングの差を考慮して数秒の許容幅で比較する
        Assert.True((actual - expected).Duration() < TimeSpan.FromSeconds(5),
            $"SystemClock.Now は UTC+9(JST)を返すべき。expected≈{expected:O}, actual={actual:O}");
    }

    [Fact]
    public void Today_IsDatePartOfNow()
    {
        // テスト対象の時計を生成する
        var clock = new SystemClock();
        // Today は JST の Now の日付部分(0:00:00)であること。
        // 日付境界をまたいだ瞬間の誤検知を避けるため、前後の Now と突き合わせる
        var before = clock.Now.Date;
        var today = clock.Today;
        var after = clock.Now.Date;

        // Today は取得前後どちらかの日付と一致するはず(通常は両方一致)
        Assert.True(today == before || today == after,
            $"SystemClock.Today は JST の日付を返すべき。before={before:O}, today={today:O}, after={after:O}");
        // 時刻部分は 0:00:00 であること
        Assert.Equal(TimeSpan.Zero, today.TimeOfDay);
    }

    [Fact]
    public void UtcNow_MatchesSystemUtc()
    {
        // テスト対象の時計を生成する
        var clock = new SystemClock();
        // UtcNow は素の UTC を返すこと(外部連携用の契約)
        Assert.True((clock.UtcNow - DateTime.UtcNow).Duration() < TimeSpan.FromSeconds(5));
    }
}
