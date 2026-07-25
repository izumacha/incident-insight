// IPAddress / AddressFamily を使う
using System.Net;
using System.Net.Sockets;

// この型の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.RateLimiting;

/// <summary>
/// レート制限のパーティションキー(制限の集計単位)をクライアント IP から導出するヘルパー。
///
/// IPv6 をアドレス全体(128bit)でキーにすると、一般家庭や VPS にも /64
/// (2^64 個のアドレス)が割り当てられるため、攻撃者は送信元アドレスを
/// 1 リクエストごとに変えるだけで毎回新しい制限枠を得られてしまう
/// (レート制限の実質的な無効化)。そこで IPv6 は上位 64bit(/64 プレフィックス)に
/// 正規化して 1 つの枠に束ねる。IPv4 は従来どおりアドレス単位。
/// </summary>
public static class ClientIpPartition
{
    // IPv6 アドレスのバイト長(16 バイト = 128bit)
    private const int Ipv6ByteLength = 16;

    // IPv6 のうちパーティションキーとして残す先頭バイト数(8 バイト = 64bit = /64)
    private const int Ipv6PrefixBytes = 8;

    /// <summary>
    /// クライアント IP からレート制限のパーティションキー文字列を導出する。
    /// IP が不明(null)の場合は共有キーを返す(素通しにしない fail-closed)。
    /// </summary>
    public static string GetPartitionKey(IPAddress? remoteIp)
    {
        // IP が取得できない場合は全員共通の 1 バケツで制限を受けさせる(fail-closed)
        if (remoteIp is null)
        {
            // 共有パーティションキーを返す
            return LoginRateLimitOptions.UnknownClientPartitionKey;
        }

        // IPv4 を IPv6 形式に包んだアドレス(::ffff:192.0.2.1)は素の IPv4 に戻して
        // 同一クライアントが表記違いで別バケツにならないようにする
        if (remoteIp.IsIPv4MappedToIPv6)
        {
            // IPv4 表記へ変換したアドレスを文字列にして返す
            return remoteIp.MapToIPv4().ToString();
        }

        // 純粋な IPv6 は /64 プレフィックスへ正規化する
        if (remoteIp.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // アドレスを 16 バイトのバイト列として取り出す
            var bytes = remoteIp.GetAddressBytes();
            // 下位 64bit(後半 8 バイト)をゼロで潰し、/64 単位の代表アドレスにする
            for (var i = Ipv6PrefixBytes; i < Ipv6ByteLength; i++)
            {
                // 該当バイトを 0 にする
                bytes[i] = 0;
            }
            // 「代表アドレス/64」の形式でキー化し、IPv4 のキーと衝突しないようにする
            return new IPAddress(bytes) + "/64";
        }

        // IPv4(またはその他)はアドレス全体をそのままキーにする
        return remoteIp.ToString();
    }
}
