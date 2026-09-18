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
/// <para><b>拾うべきなのは「黙って素通りする」形だけ。</b>
/// この判定は <c>HostFilteringMiddleware</c> の挙動をそのまま写しており（規則と理由は
/// <see cref="AllowedHostsPolicy"/> の docstring が正本）、<b>独自に丸めない</b>。
/// 前後の空白を落とすような「親切な」補正を入れると、フレームワークが実際には
/// <b>全拒否</b>している設定まで「全許可」と報告することになる。全拒否はサイトが落ちるので
/// 運用者はすぐ気づく ——見逃してはいけないのは、気づけないほう。</para>
///
/// <para><b>各ケースの期待値は実測値。</b> 同じ値でアプリを起動し、許可リストに無い
/// <c>Host</c> を送ったときの応答（200 ＝素通り / 400 ＝拒否）と突き合わせてある。
/// フレームワーク側の挙動そのものは <c>HostFilteringShortCircuitTests</c> が固定する。</para>
/// </remarks>
public class AllowedHostsPolicyTests
{
    [Theory]
    // --- 全許可（実測で、許可リストに無いホストが 200 で通る）---
    // 未設定なら分割すら行われず既定へ落ちる
    [InlineData(null, true)]
    // 空文字は項目が 1 件も残らないので既定の ["*"] へ落ちる
    [InlineData("", true)]
    // 出荷時の既定
    [InlineData("*", true)]
    // <b>実ホスト名を「追加」した形。</b> * が残っている限り全ホスト許可のまま（実測で素通りしていた）
    [InlineData("*;incident.example.com", true)]
    // 並びが逆でも同じ
    [InlineData("incident.example.com;*", true)]
    // <b>1 件も残らない値は全許可。</b> テンプレート展開
    // AllowedHosts=${PRIMARY};${SECONDARY} の両方未定義でこうなる
    [InlineData(";", true)]
    [InlineData(";;", true)]
    [InlineData(";;;", true)]
    // <b>ワイルドカードは * だけではない。</b> Kestrel の IPv6 Any / IPv4 Any も全許可になる
    // （実測で、どちらも別ホストを 200 で受けるのに警告が出なかった）
    [InlineData("[::]", true)]
    [InlineData("0.0.0.0", true)]
    // ASPNETCORE_URLS=http://0.0.0.0:8080 を写して書くと自然に生まれる形
    [InlineData("incident.example.com;0.0.0.0", true)]
    [InlineData("incident.example.com;[::]", true)]
    // <b>フレームワークは正規化してから判定する。</b> 全角数字・全角読点で書いた 0.0.0.0 は
    // IDNA/NFKC で 0.0.0.0 になり、許可リスト全体が無効になる（実測）
    [InlineData("０.０.０.０", true)]
    [InlineData("0。0。0。0", true)]
    // 1 文字だけ全角でも同じ
    [InlineData("０.0.0.0", true)]
    // 実ホスト名と併記しても同じ
    [InlineData("incident.example.com;０.０.０.０", true)]

    // --- 絞れている（実測で、許可リストに無いホストが 400 で弾かれる）---
    // 実ホスト名だけ
    [InlineData("incident.example.com", false)]
    // 複数の実ホスト名でも同じ
    [InlineData("incident.example.com;www.incident.example.com", false)]
    // 空の項目は、<b>空でない項目が残るかぎり</b>判定を変えない
    [InlineData("incident.example.com;;", false)]
    // ワイルドカードを含む「部分一致」の綴りは HostFiltering では全許可にならない
    [InlineData("*.example.com", false)]
    // 似ているが全許可ではない綴り（実ホストとして扱われる）
    [InlineData("0.0.0.1", false)]
    [InlineData("[::1]", false)]

    // --- 全拒否（サイトは落ちるが「素通り」ではないので警告の対象ではない）---
    // <b>トリムしないのが要点。</b> 空白付きの綴りは正規化しても "*" と一致しないため、
    // 許可リストが [" * "] のまま残り<b>すべて 400</b> になる（実測）。
    // ここを true にすると「全拒否をワイルドカードと呼ぶ」ことになり、規則と食い違う
    [InlineData("  *  ", false)]
    [InlineData("incident.example.com; * ", false)]
    // 空白だけの値も同じ（項目が 1 件残るので既定の ["*"] へは落ちない）
    [InlineData("   ", false)]
    // " ; " は項目が 2 件残るので既定へ落ちず、許可リストが [" ", " "] になる
    [InlineData(" ; ", false)]

    // --- 判断できない綴り（fail-closed で警告する側へ倒す）---
    // <b>実測では、この値はフレームワーク側も例外を投げる</b>
    // （HostFiltering が同じ正規化に失敗し、リクエストが 500 になる）。
    // 200 でも 400 でもないので「絞れている」とは言えず、警告する側へ倒すのが正しい。
    // 過剰に警告する＝安全側（§9 fail-closed）
    [InlineData("0.0.0.0\t", true)]
    // <b>末尾だけではない。</b> 途中に紛れた制御文字でも同じ経路に落ちることを固定する
    // （末尾のケースだけだと、catch を「末尾の空白を落とす」に置き換えても緑のまま通る）
    [InlineData("0.0\t.0.0", true)]
    public void IsPermissive_MirrorsWhetherHostFilteringLetsAnUnlistedHostThrough(
        string? allowedHosts, bool expected)
    {
        // 判定を実行して、期待どおりかを確かめる
        Assert.Equal(expected, AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    [Theory]
    // 未設定・空なら項目そのものが無い
    [InlineData(null, "")]
    [InlineData("", "")]
    // 空白の無いふつうの一覧は 1 件も死んでいない
    [InlineData("incident.example.test", "")]
    [InlineData("incident.example.test;www.example.test", "")]
    // 出荷時の既定(全許可)も、項目としては生きている
    [InlineData("*", "")]
    // <b>本命。</b> 一覧を書くときに自然に入る「区切りのうしろの空白」で、
    // 2 件目だけがどの Host とも一致しなくなる(実測: 1 件目 200 / 2 件目 400)
    [InlineData("incident.example.test; www.example.test", " www.example.test")]
    // 前に空白でも同じ
    [InlineData("incident.example.test ;www.example.test", "incident.example.test ")]
    // 複数が死んでいれば全部挙げる(1 件目だけ直して終わりにさせない)
    [InlineData(" a.example.test ; b.example.test ", " a.example.test | b.example.test ")]
    // ワイルドカードのつもりの綴りも、空白があれば一致しえない
    [InlineData("  *  ", "  *  ")]
    // 空白だけの値も同じ(全ホストが落ちるので、これは運用者も気づける側)
    [InlineData("   ", "   ")]
    // " ; " は項目が 2 件残り、どちらも死んでいる
    [InlineData(" ; ", " | ")]
    // 正規化できない綴りも空白を含むのでここに載る ——
    // IsPermissive 側でも鳴るが、運用者への指示(空白を外せ)は両方で一致する
    [InlineData("0.0.0.0	", "0.0.0.0	")]
    // <b>区切りだけの値は載らない。</b> 空の項目は分割時に落ちるので「死んだ項目」ではなく、
    // 既定の ["*"] へ落ちる別の問題(そちらは IsPermissive が拾う)
    [InlineData(";;", "")]
    public void NeverMatchingEntries_ListsEntriesThatNoHostHeaderCanEverMatch(
        string? allowedHosts, string expectedJoined)
    {
        // 判定を実行する
        var actual = AllowedHostsPolicy.NeverMatchingEntries(allowedHosts);

        // 属性に配列を書けないので、"|" 区切りの 1 本の文字列として突き合わせる
        // (区切りに ";" を使うと、設定値そのものの区切りと見分けが付かなくなる)
        Assert.Equal(expectedJoined, string.Join("|", actual));
    }

    // 2 つの判定が「同じ分割」を使い続けていること。
    //
    // <b>片方だけ規則が動くと、両方とも黙って外れる。</b> たとえば NeverMatchingEntries 側にだけ
    // トリムを足すと死んだ項目が 1 件も挙がらなくなり、IsPermissive 側にだけ足すと
    // 全拒否の設定が「全許可」に化ける ——どちらも警告が出なくなる方向。
    // 分割規則そのものは private なので、観測できる出口から突き合わせる。
    [Fact]
    public void BothChecks_SeeTheSameEntries()
    {
        // 空の項目だけが落ちる(＝トリムされない)ことが両方で成り立つ設定値
        const string allowedHosts = " a.example.test ;; b.example.test ";

        // 死んだ項目は 2 件とも挙がる(空の項目は項目として数えない)
        Assert.Equal(2, AllowedHostsPolicy.NeverMatchingEntries(allowedHosts).Count);
        // 同じ値で、項目が残るので既定の ["*"] へは落ちない(＝全許可ではない)
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }
}
