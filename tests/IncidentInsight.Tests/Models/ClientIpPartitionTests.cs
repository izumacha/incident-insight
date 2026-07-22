// テスト対象の ClientIpPartition / LoginRateLimitOptions を使う
using IncidentInsight.Web.Models.RateLimiting;
// IPAddress を使う
using System.Net;

// テストクラスの名前空間(既存の Models 配下テストと同じ場所)
namespace IncidentInsight.Tests.Models;

/// <summary>
/// レート制限パーティションキー導出の回帰テスト。
/// 特に「IPv6 は /64 プレフィックスに束ねる」仕様を固定する。
/// アドレス全体をキーにすると、/64(一般家庭・VPS の標準割当)内で
/// 送信元を回すだけで制限を回避できてしまうため。
/// </summary>
public class ClientIpPartitionTests
{
    [Fact]
    public void NullAddress_ReturnsSharedUnknownKey()
    {
        // IP が特定できない場合は共有キー(fail-closed)になることを確認する
        Assert.Equal(
            LoginRateLimitOptions.UnknownClientPartitionKey,
            ClientIpPartition.GetPartitionKey(null));
    }

    [Fact]
    public void Ipv4_UsesFullAddress()
    {
        // IPv4 はアドレス全体がそのままキーになることを確認する
        Assert.Equal("203.0.113.7", ClientIpPartition.GetPartitionKey(IPAddress.Parse("203.0.113.7")));
    }

    [Fact]
    public void Ipv4MappedIpv6_NormalizesToIpv4()
    {
        // IPv6 形式に包まれた IPv4(::ffff:203.0.113.7)が素の IPv4 キーへ正規化されることを確認する
        Assert.Equal("203.0.113.7", ClientIpPartition.GetPartitionKey(IPAddress.Parse("::ffff:203.0.113.7")));
    }

    [Fact]
    public void Ipv6_SamePrefix_ShareOnePartition()
    {
        // 同じ /64 内の 2 アドレスが同一キーに束ねられることを確認する
        var key1 = ClientIpPartition.GetPartitionKey(IPAddress.Parse("2001:db8:abcd:12::1"));
        // 下位 64bit だけが異なるアドレスのキーを取得する
        var key2 = ClientIpPartition.GetPartitionKey(IPAddress.Parse("2001:db8:abcd:12:ffff:ffff:ffff:ffff"));

        // 両者が同じパーティション(同じ制限枠)になることを確認する
        Assert.Equal(key1, key2);
        // キーが /64 正規化形式であることも確認する
        Assert.Equal("2001:db8:abcd:12::/64", key1);
    }

    [Fact]
    public void Ipv6_DifferentPrefix_GetSeparatePartitions()
    {
        // /64 プレフィックスが異なるアドレス同士は別キー(正規ユーザーを巻き込まない)ことを確認する
        var key1 = ClientIpPartition.GetPartitionKey(IPAddress.Parse("2001:db8:abcd:12::1"));
        // 別プレフィックスのアドレスのキーを取得する
        var key2 = ClientIpPartition.GetPartitionKey(IPAddress.Parse("2001:db8:abcd:13::1"));

        // 両者が異なるパーティションになることを確認する
        Assert.NotEqual(key1, key2);
    }
}
