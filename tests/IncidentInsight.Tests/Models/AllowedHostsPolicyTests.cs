// 判定対象を使う
using IncidentInsight.Web.Models.Validation;

// 既存の Models 配下テストと同じ名前空間に置く
namespace IncidentInsight.Tests.Models;

/// <summary>
/// <c>AllowedHosts</c> が「実質すべてのホストを許可する」かの判定を、境界まで固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか。</b> この判定が false を返すと Production の警告ログが出ず、
/// <c>docs/security.md</c> は運用者に<b>その警告が出ていないことを確認する</b>よう案内している。
/// つまり判定が緩むと、絞れていないのに「絞れている」と読める ——
/// そのうえ 307 リダイレクトの <c>Location</c> は要求元の <c>Host</c> をそのまま含むので、
/// キャッシュ抑止の効かない応答に攻撃者の入力が載る状態が残る。</para>
///
/// <para><b>ワイルドカードは <c>*</c> だけではない。</b>
/// <c>HostFilteringMiddleware.IsTopLevelWildcard</c> は <c>*</c> ・ <c>[::]</c> ・ <c>0.0.0.0</c> の
/// いずれかで全許可へ切り替わる。<c>*</c> だけを見ると、
/// <c>"incident.example.com;0.0.0.0"</c> という<b>構造がまったく同じ</b>綴りで同じ穴が残る。</para>
///
/// <para><b>以前は値全体が <c>"*"</c> と一致するかだけを見ていた。</b>
/// <c>"*;incident.example.com"</c>（実ホスト名を「追加」しようとしたときに自然に書く形）は
/// <c>HostFiltering</c> が全ホスト許可として扱うのに、警告が出なかった。</para>
/// </remarks>
public class AllowedHostsPolicyTests
{
    [Theory]
    // 未設定・空・空白は絞り込みが効いていない
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("   ", true)]
    // 出荷時の既定
    [InlineData("*", true)]
    // 前後の空白があっても同じ
    [InlineData("  *  ", true)]
    // <b>実ホスト名を「追加」した形。</b> * が残っている限り全ホスト許可のまま(実測で素通りしていた)
    [InlineData("*;incident.example.com", true)]
    // 並びが逆でも同じ
    [InlineData("incident.example.com;*", true)]
    // 区切りの周りに空白があっても同じ
    [InlineData("incident.example.com; * ", true)]
    // 実ホスト名だけなら絞れている
    [InlineData("incident.example.com", false)]
    // 複数の実ホスト名でも絞れている
    [InlineData("incident.example.com;www.incident.example.com", false)]
    // 空の項目は、<b>空でない項目が残るかぎり</b>絞れている判定を変えない
    [InlineData("incident.example.com;;", false)]
    // <b>1 件も残らない値は全許可。</b> 汎用ホストの既定設定が ["*"] へ落とすため
    // (実測: AllowedHosts=";" は別ホストを 200 で受ける)。
    // テンプレート展開 AllowedHosts=${PRIMARY};${SECONDARY} の両方未定義でこうなる
    [InlineData(";", true)]
    [InlineData(";;", true)]
    [InlineData(";;;", true)]
    // <b>空白入りは別物。</b> " ; " は項目が 2 件残るので既定へ落ちず、許可リストが
    // [" ", " "] になって<b>すべて拒否</b>される(実測で 400)。サイトは落ちるが
    // 「素通り」ではないので permissive ではない
    [InlineData(" ; ", false)]
    // ワイルドカードを含む「部分一致」の綴りは HostFiltering では全許可にならない
    [InlineData("*.example.com", false)]
    // <b>ワイルドカードは * だけではない。</b> Kestrel の IPv6 Any / IPv4 Any も全許可になる
    // (実測で、どちらも別ホストを 200 で受けるのに警告が出なかった)
    [InlineData("[::]", true)]
    [InlineData("0.0.0.0", true)]
    // ASPNETCORE_URLS=http://0.0.0.0:8080 を写して書くと自然に生まれる形
    [InlineData("incident.example.com;0.0.0.0", true)]
    [InlineData("incident.example.com;[::]", true)]
    // 似ているが全許可ではない綴り(実ホストとして扱われる)
    [InlineData("0.0.0.1", false)]
    [InlineData("[::1]", false)]
    // <b>フレームワークは正規化してから判定する。</b> 全角数字・全角読点で書いた 0.0.0.0 は
    // IDNA/NFKC で 0.0.0.0 になり、許可リスト全体が無効になる(実測)
    [InlineData("０.０.０.０", true)]
    [InlineData("0。0。0。0", true)]
    // 1 文字だけ全角でも同じ
    [InlineData("０.0.0.0", true)]
    // 実ホスト名と併記しても同じ
    [InlineData("incident.example.com;０.０.０.０", true)]
    // 正規化できない綴りは判断できないので、警告する側へ倒す(過剰に警告する＝安全側)
    [InlineData("0.0.0.0\t", true)]
    public void IsPermissive_TreatsAnyWildcardEntryAsAllowAll(string? allowedHosts, bool expected)
    {
        // 判定を実行して、期待どおりかを確かめる
        Assert.Equal(expected, AllowedHostsPolicy.IsPermissive(allowedHosts));
    }
}
