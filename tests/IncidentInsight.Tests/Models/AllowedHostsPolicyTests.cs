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
/// <para><b>この判定が拾うのは「黙って素通りする」形だけ。</b>
/// <c>HostFilteringMiddleware</c> の挙動をそのまま写しており（規則と理由は
/// <see cref="AllowedHostsPolicy"/> の docstring が正本）、<b>独自に丸めない</b>。
/// 前後の空白を落とすような「親切な」補正を入れると、フレームワークが実際には
/// <b>一致させていない</b>設定まで「全許可」と報告することになる。</para>
///
/// <para><b>「一致しない」側は野放しではない。</b>
/// <see cref="AllowedHostsPolicy.NeverMatchingEntries"/> が別の警告として拾う ——
/// <c>"a.example.test; b.example.test"</c> のような綴りは<b>1 件目が生きたまま
/// 2 件目だけが落ちる</b>ので、「全拒否ならサイトが落ちてすぐ気づく」は成り立たない
/// （その実測は <c>HostFilteringShortCircuitTests</c> が固定している）。
/// 下の表で <c>false</c> になっている空白入りの綴りは、
/// <b>この判定の対象外というだけで、警告の対象ではある</b>。</para>
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

    // --- 一致しない（「素通り」ではないので<b>この判定の</b>対象ではない。
    //     警告そのものは NeverMatchingEntries 側が出す）---
    // <b>トリムしないのが要点。</b> 空白付きの綴りは正規化しても "*" と一致しないため、
    // ワイルドカードとして扱われない（＝許可リスト全体は無効にならない）。
    // ここを true にすると「一致しない項目をワイルドカードと呼ぶ」ことになり、規則と食い違う。
    //
    // <b>判定は 3 つとも同じだが、運用上の症状は残りの項目しだいで変わる。</b>
    // 生きた項目が 1 つも無ければ全ホストが落ち、混ざっていればその 1 件だけが落ちる。
    // <b>帰属は綴りごとに書く</b> ——統合テストの表に実在する行にだけ
    // 「固定されている」と書く（覆っていない綴りまで巻き込むと、
    //  実際には落ちない変異を「落ちるはず」と読ませることになる）
    [InlineData("  *  ", false)]   // すべて 400（HostFilteringShortCircuitTests の表が固定）
    // 空白だけの値も同じ（項目が 1 件残るので既定の ["*"] へは落ちない）。
    // <b>この綴りは統合テストの表には無い</b>ので、固定されているのは判定側だけ
    [InlineData("   ", false)]
    // <b>こちらは部分的に落ちる。</b> 1 件目は生きているので 200 を返し続け、
    // 空白付きの 2 件目だけが一致しない ——警告が拾うべきなのはこの形。
    // 部分的に落ちること自体は、実ホスト名 2 件を使う
    // WhitespaceAfterASeparator_KillsOnlyThatEntry が固定している
    [InlineData("incident.example.com; * ", false)]
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
    // <b>実ホスト名と混ざった形も要る。</b> 上の 2 つは項目が 1 件なので、
    // 「正規化できない項目を先に捨てる」退行を入れても 0 件になって
    // entries.Length == 0 のフォールバックで true のまま通る（実測）。
    // 混ざった形なら、捨てた瞬間に false へ落ちて警告が消えるので検出できる
    [InlineData("incident.example.com;0.0\t.0.0", true)]
    // 並びを入れ替えても同じ（判定は並び順を見ない）
    [InlineData("0.0\t.0.0;incident.example.com", true)]
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
    // <b>正規化できない綴りはここに載せない。</b> 突き合わせる値そのものが作れない以上
    // 「空白のせいで一致しない」とは言えず、この綴りは IsPermissive 側が
    // UnparsableEntry 専用の文面（症状は全拒否ではなく毎リクエストの例外）で拾う。
    // 両方で鳴らすと、同じ項目について原因の違う 2 本が出て取り違えのもとになる
    [InlineData("0.0.0.0\t", "")]

    // --- 正規化で消える文字を持つ綴り（角括弧の IPv6）---
    // <b>生の綴りを Trim() と比べてはいけない。</b> HostString.ToUriComponent() は
    // "]" より後ろを丸ごと捨てるので、実測では "[::1] " → "[::1]"・"[::] " → "[::]" となり、
    // フレームワークはこれらを<b>一致させる</b>（"[::] " に至っては全ホスト許可になる）。
    // 生の綴りで見ていた頃は、200 で受けている項目を「消してよい」と案内していた ——
    // 従うと IPv6 のクライアントが一斉に 400 になる（こちらが障害を作る側）
    [InlineData("incident.example.test;[::1] ", "")]
    [InlineData("[::] ", "")]
    // 捨てられるのは "]" の直後が :port でないときだけ。ポートが続けば空白は残るので、
    // こちらは従来どおり死んだ項目として名指しする（実測: "[fe80::1]:8080 " はそのまま）
    [InlineData("incident.example.test;[fe80::1]:8080 ", "[fe80::1]:8080 ")]
    // <b>かつての「残っている境界」が閉じた（issue #269）。</b> 素の IPv6 を書くと
    // HostString が括弧を補うので、実測では "::1 " → "[::1 ]" となり空白が<b>内側</b>へ入る。
    // 正規化後の前後には空白が無いので「前後の空白」としては拾えないが、
    // 「Host ヘッダーが運べない文字（空白・%）を含む項目は死んでいる」を足したことで
    // 名指しできるようになった（理由は WhitespaceInsideEntry。下の Theory が固定する）
    // ——実測でも本物の Kestrel は Host: [::1 ] を 400 で弾く
    [InlineData("incident.example.test;::1 ", "::1 ")]
    // <b>区切りだけの値は載らない。</b> 空の項目は分割時に落ちるので「死んだ項目」ではなく、
    // 既定の ["*"] へ落ちる別の問題(そちらは IsPermissive が拾う)
    [InlineData(";;", "")]

    // --- ポートを含む綴り（issue #256）---
    // <b>本命。</b> HostString.MatchesAny はリクエスト側の値から<b>ポートを落として</b>から
    // 許可リストの項目と<b>そのまま</b>比べるので、ポート付きの項目はどの Host とも一致しない
    // （実測: Host: incident.example.test:8080 を送っても 400）。
    // ASPNETCORE_URLS からホスト名を写すとポートごと持ってくるのは自然な形
    [InlineData("incident.example.test:8080", "incident.example.test:8080")]
    // 実ホスト名と混ざると「サイトは生きたまま特定のホスト名だけが静かに 400」になる
    [InlineData("a.example.test;b.example.test:8080", "b.example.test:8080")]
    // ポート部が数値として読めない綴りも同じく一致しえない
    // （HostString.Port は null を返すので、Port を見る判定では取りこぼす）
    [InlineData("a.example.test:abc", "a.example.test:abc")]
    [InlineData("a.example.test:", "a.example.test:")]
    // 角括弧の IPv6 にポートが付いた形も拾う
    [InlineData("[fe80::1]:8080", "[fe80::1]:8080")]

    // --- コロンを含むがポートではない綴り（ここを拾うと障害を作る側に回る）---
    // <b>「コロンがあるか」で判定してはいけない。</b> 角括弧の IPv6 リテラルは
    // コロンを含むがポートを持たず、実測では Host: [::1] と正しく一致する
    [InlineData("[::1]", "")]
    // 全許可のワイルドカードでもある [::] も、ポートは持たないので名指ししない
    [InlineData("[::]", "")]
    public void NeverMatchingEntries_ListsEntriesThatNoHostHeaderCanEverMatch(
        string? allowedHosts, string expectedJoined)
    {
        // 判定を実行する
        var actual = AllowedHostsPolicy.NeverMatchingEntries(allowedHosts);

        // 属性に配列を書けないので、"|" 区切りの 1 本の文字列として突き合わせる
        // (区切りに ";" を使うと、設定値そのものの区切りと見分けが付かなくなる)
        Assert.Equal(expectedJoined, string.Join("|", actual));
    }

    [Theory]
    // --- 消す対象が無い ---
    [InlineData(null, AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]
    [InlineData("incident.example.test", AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]
    [InlineData("*", AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]

    // --- 消してよい（残るのが実ホスト名だけ）---
    // テンプレート展開 AllowedHosts=incident.example.test; ${SECONDARY} で
    // SECONDARY が未定義だとこうなる。死んだ項目 " " には書き換える先が無いので、
    // 消す以外に直しようが無い ——無条件に「消すな」と案内すると手詰まりになる
    [InlineData("incident.example.test; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe)]
    [InlineData("incident.example.test; www.example.test", AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe)]

    // --- 消すと全ホスト許可になる: 経路 (a) 項目が 0 件になる ---
    [InlineData("   ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    [InlineData(" ; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    [InlineData("  *  ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    [InlineData(" ;; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]

    // --- 消すと全ホスト許可になる: 経路 (b) 残った項目自体がワイルドカード ---
    // <b>0 件にならなくても危ない。</b>「生きた項目が 1 件でも残るか」で判定すると
    // ここを取りこぼし、削除してよいと案内した結果が全ホスト許可になる
    [InlineData("*; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    [InlineData("[::]; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    // ASPNETCORE_URLS=http://0.0.0.0:8080 を写して書くと自然に生まれる形
    [InlineData("incident.example.test;0.0.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    // 全角で書いた 0.0.0.0 も正規化で全許可になるので同じ
    [InlineData("incident.example.test;０.０.０.０; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]

    // --- 判断できない（残る項目に正規化できない綴りがあり、そこへ実際に到達する）---
    // <b>並び順で結果が変わるので断定してはいけない。</b> 実測では
    //   "0.0<TAB>.0.0;0.0.0.0" → 例外（どの Host も受け付けない）
    //   "0.0.0.0;0.0<TAB>.0.0" → 200（どの Host も受け付ける）
    // TryProcessHosts が宣言順に正規化し、最初のワイルドカードで打ち切るため。
    // bool で答えるとどちらかの並びで必ず事実と逆の案内になる
    [InlineData("0.0\t.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]
    // 壊れた項目が<b>先</b>にあるので、フレームワークはそこで例外になる＝断定できない
    [InlineData("0.0\t.0.0;0.0.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]

    // --- 壊れた項目があっても、そこへ到達しないなら結果は確定している ---
    // <b>「壊れた項目があるか」を Any で畳んではいけない。</b> この並びは 1 件目の
    // ワイルドカードで打ち切られるので 2 件目は評価されず、実測でも 200（全許可）で確定する
    // （UnparsableEntry_ChangesTheOutcomeDependingOnItsPositionInTheList が
    //  "0.0.0.0;0.0<TAB>.0.0" を 200 として固定している）。
    // Unknown に倒すと「消した結果は予測できない」としか言えず、運用者は
    // <b>本当に必要な「ワイルドカードの項目も消せ」という案内を受け取れない</b>
    [InlineData("0.0.0.0;0.0\t.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    public void ClassifyDeadEntryDeletion_SaysWhatDeletingWouldActuallyDo(
        string? allowedHosts, AllowedHostsPolicy.DeadEntryDeletionOutcome expected)
    {
        // 分類を実行して、期待どおりかを確かめる
        Assert.Equal(expected, AllowedHostsPolicy.ClassifyDeadEntryDeletion(allowedHosts));
    }

    // 「死んだ項目を消したあとに何が残るか」を、手で書いた期待値で固定する。
    //
    // <b>以前ここに置いていた「IsPermissive と一致すること」の検査は恒真だった。</b>
    // 本体もテストも同じ Wildcards / SplitEntries を読んでいたため、
    // 判定が狭まれば両辺が同じだけ狭まる
    // ——Wildcards を ["*"] に狭めても全行が緑のまま通る。CLAUDE.md が繰り返し
    // 禁じている「同じ判定でガードを書く」形そのもの。
    //
    // そこで<b>手がかりを変える</b>: 判定の途中結果（消したあとに残る項目）を
    // 文字列で直接書き下す。ここが合っていれば、あとは残った項目を
    // ワイルドカードと突き合わせるだけで、その突き合わせは上の表が期待値付きで固定する。
    [Theory]
    // 死んだ項目だけ ——消すと 1 件も残らない
    [InlineData("   ", "")]
    [InlineData(" ; ", "")]
    // 生きた実ホスト名が残る
    [InlineData("incident.example.test; ", "incident.example.test")]
    [InlineData("incident.example.test; www.example.test", "incident.example.test")]
    // <b>残るのがワイルドカードの形</b>（件数だけを見る判定が取りこぼしていた）
    [InlineData("*; ", "*")]
    [InlineData("incident.example.test;0.0.0.0; ", "incident.example.test;0.0.0.0")]
    // 空の項目は分割の時点で落ちるので、残る一覧には現れない
    [InlineData("incident.example.test;; ", "incident.example.test")]
    public void NeverMatchingEntries_LeaveExactlyTheseEntriesBehind(
        string allowedHosts, string expectedSurvivors)
    {
        // その設定で「一致しえない」と判定された項目を取り出す
        var dead = AllowedHostsPolicy.NeverMatchingEntries(allowedHosts);

        // 死んだ項目を実際に取り除いた設定値を組み立てる（運用者が「消した」状態）
        var survivors = string.Join(
            ";",
            allowedHosts.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Where(entry => !dead.Contains(entry, StringComparer.Ordinal)));

        // 残る項目が、手で書いた期待値と一致すること
        Assert.Equal(expectedSurvivors, survivors);
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
        // 空の項目だけが落ちる(＝トリムされない)ことが両方で成り立つ設定値。
        // <b>2 件目を空白付きのワイルドカードにしてあるのが要点</b> ——ここをただの
        // ホスト名にすると、IsPermissive 側にだけトリムを足す変異でも
        // 「ワイルドカードが無い」ままなので false が返り、<b>この検査が緑で通る</b>
        // (実測。守っていると書いた変異を実際には 1 つも捕まえていなかった)
        const string allowedHosts = " a.example.test ;; * ";

        // 死んだ項目は 2 件とも挙がる(空の項目は項目として数えない)。
        // NeverMatchingEntries 側にだけトリムを足すと、ここが 0 件になって落ちる
        Assert.Equal(2, AllowedHostsPolicy.NeverMatchingEntries(allowedHosts).Count);
        // 同じ値で、空白付きの "*" はワイルドカードとして扱われない(＝全許可ではない)。
        // IsPermissive 側にだけトリムを足すと、ここが true になって落ちる
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    // 分類すべてに、固有の案内が用意されていること。
    //
    // <b>switch の _ は足し忘れを黙って飲む。</b> 実測で、分類に 5 つ目の値を足しても
    // ビルドは 0 Warning / 0 Error だった（CS8509 は _ があるぶん出ず、この repo は
    // 警告をエラーにもしていない）。だから<b>enum から導いて</b>照合する ——
    // 一覧を手で書くと、値を足した人が表とコードの両方を直し忘れたときに
    // 「登録済みどうしは一致し続ける」ので全件緑のまま通る。
    //
    // <b>既定の文面は 1 つだけ許す。</b> NothingToDelete は「名指しする項目が無い」
    // ＝専用の案内が要らない唯一の分類なので、ここだけが既定と同じでよい。
    // 2 つ目が既定へ落ちたら、それは案内の足し忘れ。
    [Fact]
    public void DeadEntryFixAdvice_GivesEveryOutcomeItsOwnAdvice()
    {
        // 分類の一覧を enum そのものから取り出す（手で書かない）
        var outcomes = Enum.GetValues<AllowedHostsPolicy.DeadEntryDeletionOutcome>();

        // 見るべき分類が 1 つも無い状態で緑にしない（fail-closed）
        Assert.NotEmpty(outcomes);

        // 分類ごとの案内を集める
        var advice = outcomes.ToDictionary(
            outcome => outcome,
            AllowedHostsPolicy.DeadEntryFixAdvice);

        // どの案内も空でないこと（空だと警告が直し方を示さないまま出る）
        Assert.All(advice.Values, text => Assert.False(string.IsNullOrWhiteSpace(text)));

        // 既定（＝専用の案内が無い分類）へ落ちているものを数える。
        // <b>照合の相手が関数の外の定数であることが要点</b>（理由は
        // AllowedHostsPolicy.FallbackFixAdvice の docstring が正本）
        var fallback = AllowedHostsPolicy.FallbackFixAdvice;
        var fellBack = advice
            .Where(pair => string.Equals(pair.Value, fallback, StringComparison.Ordinal))
            .Select(pair => pair.Key)
            .ToList();

        // 既定へ落ちてよいのは NothingToDelete だけ
        var expected = new[] { AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete };

        // <b>落ち方が 2 通りあるので、文言も分ける。</b> 同じ文言にすると、
        // 「arm を足したら『arm を足してください』と言われる」ことになり、
        // いちばん安く赤を消す手が「検査を緩める」になってしまう
        Assert.True(
            fellBack.SequenceEqual(expected),
            fellBack.Except(expected).Any()
                // 専用の案内が無い分類がある（＝分類を足したのに arm を忘れた）
                ? "専用の案内が無い分類があります: "
                    + string.Join(", ", fellBack.Except(expected))
                    + "。AllowedHostsPolicy.DeadEntryFixAdvice に arm を足してください"
                    + "（switch の _ はコンパイルエラーにならないので、ここでしか気付けません）"
                // 既定へ落ちる分類が減った（＝NothingToDelete に専用の arm を足した）
                : "NothingToDelete が既定の文面を使わなくなりました"
                    + "（専用の arm を足したはずです）。"
                    + "この検査の期待値も同じ変更セットで更新してください ——"
                    + "更新せずに放置すると、既定の文面を誰も使わなくなり、"
                    + "次に分類を足した人の arm 忘れを検出できなくなります");
    }

    // いちばん危ない分岐が、削除を戒める向きのままであること。
    //
    // <b>文面そのものを固定する数少ない箇所。</b> 通常この repo は文面を固定しないが、
    // ここは「消してよい／いけない」という<b>向きが反転すると穴になる</b>案内で、
    // かつ Program.cs へ書いていた頃はテストから 1 行も走らなかった
    // （実測で、反対の意味へ差し替えても全件緑のまま通った）。
    [Fact]
    public void DeadEntryFixAdvice_TellsOperatorsNotToDeleteWhenDeletingWouldOpenUp()
    {
        // 消すと全ホスト許可になる分類の案内を取り出す
        var advice = AllowedHostsPolicy.DeadEntryFixAdvice(
            AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost);

        // 削除を戒めていること（向きが反転したらここで落ちる）
        Assert.Contains("Do NOT simply delete", advice, StringComparison.Ordinal);
        // 何を消すべきかも示していること（名指しの項目だけでは直らない）
        Assert.Contains("remove any wildcard entry", advice, StringComparison.Ordinal);
    }
    // 全許可になる原因を、実測した扱いのとおりに分類できること。
    //
    // <b>並び順のある行が要点。</b> フレームワークは項目を宣言順に正規化しながら走査し、
    // 最初のワイルドカードで打ち切るので、正規化できない項目と同居すると結果が並び順で
    // 変わる（実測は HostFilteringShortCircuitTests が固定）。前から 1 件ずつ見る形を
    // Any へ畳み直す退行は、この 2 行が無いと通ってしまう。
    [Theory]
    // --- 絞れている ---
    [InlineData("incident.example.test", AllowedHostsPolicy.PermissiveReason.NotPermissive)]
    [InlineData("a.example.test;b.example.test", AllowedHostsPolicy.PermissiveReason.NotPermissive)]
    // 前後に空白がある項目は「死んでいる」だけで、全許可にはしない（警告 2 の担当）
    [InlineData("a.example.test; b.example.test", AllowedHostsPolicy.PermissiveReason.NotPermissive)]
    // --- 1 件も残らない（既定の ["*"] へ落ちる）---
    [InlineData(null, AllowedHostsPolicy.PermissiveReason.NoEntriesLeft)]
    [InlineData("", AllowedHostsPolicy.PermissiveReason.NoEntriesLeft)]
    [InlineData(";", AllowedHostsPolicy.PermissiveReason.NoEntriesLeft)]
    [InlineData(";;", AllowedHostsPolicy.PermissiveReason.NoEntriesLeft)]
    // --- ワイルドカード ---
    [InlineData("*", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    [InlineData("[::]", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    [InlineData("0.0.0.0", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    // 実ホスト名を「足した」つもりの綴り（issue #64 で踏んだ形）
    [InlineData("*;incident.example.test", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    // 正規化（IDNA / NFKC）を通してから突き合わせること
    [InlineData("０.０.０.０", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    // トリムしないので、前後に空白がある "*" はワイルドカードにならない（＝死んだ項目）
    [InlineData("  *  ", AllowedHostsPolicy.PermissiveReason.NotPermissive)]
    // --- 正規化できない綴り ---
    [InlineData("0.0\t.0.0", AllowedHostsPolicy.PermissiveReason.UnparsableEntry)]
    // 実ホスト名と混ざっても、原因は「読めない項目」のまま
    [InlineData("incident.example.test;0.0\t.0.0", AllowedHostsPolicy.PermissiveReason.UnparsableEntry)]
    // --- 並び順で答えが変わること（フレームワークの短絡と同じ）---
    [InlineData("0.0\t.0.0;0.0.0.0", AllowedHostsPolicy.PermissiveReason.UnparsableEntry)]
    [InlineData("0.0.0.0;0.0\t.0.0", AllowedHostsPolicy.PermissiveReason.WildcardEntry)]
    public void ClassifyPermissive_NamesWhyTheListAcceptsEveryHost(
        string? allowedHosts,
        AllowedHostsPolicy.PermissiveReason expected)
    {
        // 設定値から原因を求める
        var actual = AllowedHostsPolicy.ClassifyPermissive(allowedHosts);

        // 実測した扱いと一致すること
        Assert.Equal(expected, actual);
    }

    // 警告を出すかどうか（bool）と、その原因（enum）が食い違わないこと。
    //
    // <b>片方だけを直す変更を落とすための検査。</b> IsPermissive が原因の判定から
    // 導かれていないと、「警告は出るのに文面は『絞れている』のまま」や、その逆が書ける。
    // 期待値は<b>enum から導く</b>（NotPermissive 以外はすべて警告する側、と決めてある）。
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(";")]
    [InlineData("*")]
    [InlineData("０.０.０.０")]
    [InlineData("0.0\t.0.0")]
    [InlineData("incident.example.test")]
    [InlineData("a.example.test; b.example.test")]
    [InlineData("  *  ")]
    public void IsPermissive_AgreesWithTheReasonItWouldReport(string? allowedHosts)
    {
        // 原因を求める
        var reason = AllowedHostsPolicy.ClassifyPermissive(allowedHosts);

        // 「絞れている」以外はすべて警告する側、という取り決めをそのまま期待値にする
        var expected = reason != AllowedHostsPolicy.PermissiveReason.NotPermissive;

        // bool 側が同じ答えを返すこと
        Assert.Equal(expected, AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    // 原因ごとに専用の説明があること（＝分類を足したのに文面を足し忘れていないこと）。
    //
    // <b>この検査が無いと足し忘れは検出できない。</b> switch の _ は
    // コンパイルエラーにならず、警告レベルにもならない。しかも文面を使うのは
    // Program.cs の if (!IsDevelopment()) の中なので、統合テストからも走らない。
    // 既定へ落ちてよいのは NotPermissive だけ ——説明すべき原因が無い唯一の値。
    [Fact]
    public void PermissiveCauseMessage_GivesEveryReasonItsOwnExplanation()
    {
        // 原因の一覧を enum そのものから取り出す（手で書かない）
        var reasons = Enum.GetValues<AllowedHostsPolicy.PermissiveReason>();

        // 見るべき原因が 1 つも無い状態で緑にしない（fail-closed）
        Assert.NotEmpty(reasons);

        // 原因ごとの説明を集める
        var messages = reasons.ToDictionary(
            reason => reason,
            AllowedHostsPolicy.PermissiveCauseMessage);

        // どの説明も空でないこと（空だと警告が原因を示さないまま出る）
        Assert.All(messages.Values, text => Assert.False(string.IsNullOrWhiteSpace(text)));

        // 既定（＝専用の説明が無い原因）を数える。
        // <b>照合の相手が関数の外の定数であることが要点</b>（理由は
        // AllowedHostsPolicy.FallbackPermissiveCauseMessage の docstring が正本）
        var fallback = AllowedHostsPolicy.FallbackPermissiveCauseMessage;
        var fellBack = messages
            .Where(pair => string.Equals(pair.Value, fallback, StringComparison.Ordinal))
            .Select(pair => pair.Key)
            .ToList();

        // 既定へ落ちてよいのは NotPermissive だけ
        var expected = new[] { AllowedHostsPolicy.PermissiveReason.NotPermissive };

        // 落ち方が 2 通りあるので、文言も分ける（DeadEntryFixAdvice の検査と同じ理由）
        Assert.True(
            fellBack.SequenceEqual(expected),
            fellBack.Except(expected).Any()
                // 専用の説明が無い原因がある（＝原因を足したのに arm を忘れた）
                ? "専用の説明が無い原因があります: "
                    + string.Join(", ", fellBack.Except(expected))
                    + "。AllowedHostsPolicy.PermissiveCauseMessage に arm を足してください"
                    + "（switch の _ はコンパイルエラーにならないので、ここでしか気付けません）"
                // 既定へ落ちる原因が減った（＝NotPermissive に専用の arm を足した）
                : "NotPermissive が既定の文面を使わなくなりました"
                    + "（専用の arm を足したはずです）。"
                    + "この検査の期待値も同じ変更セットで更新してください ——"
                    + "更新せずに放置すると、既定の文面を誰も使わなくなり、"
                    + "次に原因を足した人の arm 忘れを検出できなくなります");
    }

    // 原因ごとに<b>違う</b>ことを言っていること。
    //
    // <b>足し忘れの検査だけでは足りない。</b> あちらは「既定と同じでないこと」しか見ないので、
    // 3 つの arm すべてに同じ 1 文（たとえば元の「'*' か '[::]' か '0.0.0.0' を消せ」）を
    // 書いても緑のまま通る ——それはこの変更が直したはずの状態そのもの。
    [Fact]
    public void PermissiveCauseMessage_DoesNotSendOperatorsLookingForSomethingElse()
    {
        // 説明すべき原因（NotPermissive 以外）の説明を集める
        var messages = Enum.GetValues<AllowedHostsPolicy.PermissiveReason>()
            .Where(reason => reason != AllowedHostsPolicy.PermissiveReason.NotPermissive)
            .Select(AllowedHostsPolicy.PermissiveCauseMessage)
            .ToList();

        // 見るべき原因が 1 つも無い状態で緑にしない（fail-closed）
        Assert.NotEmpty(messages);

        // すべて別々の文であること（同じ文を使い回したらここで落ちる）
        Assert.Equal(messages.Count, messages.Distinct(StringComparer.Ordinal).Count());

        // ワイルドカードの 3 綴りを名指しするのは、実際にそれが原因のときだけ。
        // <b>これが元の不具合そのもの</b> ——値に無いものを探させてはいけない
        Assert.DoesNotContain(
            "'[::]'",
            AllowedHostsPolicy.PermissiveCauseMessage(
                AllowedHostsPolicy.PermissiveReason.UnparsableEntry),
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "'[::]'",
            AllowedHostsPolicy.PermissiveCauseMessage(
                AllowedHostsPolicy.PermissiveReason.NoEntriesLeft),
            StringComparison.Ordinal);
    }

    // 「どの原因が警告に値するか」の規則が 1 か所に保たれていることを固定する。
    //
    // <b>WarrantsWarning は Program.cs と IsPermissive の両方が使う。</b>
    // 片方が自前で reason != NotPermissive と書き直すと規則の写しが増え、
    // 「警告に値しない原因」を足したときに片方だけが古い判断のまま残る。
    // ここで両者が必ず一致することを見ておけば、その食い違いが落ちる。
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(";")]
    [InlineData("*")]
    [InlineData("[::]")]
    [InlineData("0.0.0.0")]
    [InlineData("[::] ")]
    [InlineData("０.０.０.０")]
    [InlineData("*;incident.example.test")]
    [InlineData("0.0\t.0.0")]
    [InlineData("incident.example.test")]
    [InlineData("incident.example.test;www.example.test")]
    [InlineData("  *  ")]
    [InlineData("incident.example.test; www.example.test")]
    public void WarrantsWarning_AgreesWithIsPermissive(string? allowedHosts)
    {
        // 原因を求める
        var reason = AllowedHostsPolicy.ClassifyPermissive(allowedHosts);

        // 「警告に値するか」と「全許可か」は同じ 1 つの規則から出ること
        Assert.Equal(
            AllowedHostsPolicy.IsPermissive(allowedHosts),
            AllowedHostsPolicy.WarrantsWarning(reason));
    }

    // 注: ここには InspectNeverMatchingEntries_MatchesTheIndividualQueries があった。
    // 3 つの公開 API が<b>同じ振り分けを読むようになった時点で反証不能</b>になったので外した ——
    // 実測でも、振り分けの述語を潰す変異に対して 6 行すべて緑のまま通る（3 つが一緒に動くため）。
    // 緑のままの検査が「守られている」と読めてしまうのは、この PR が他の箇所で潰した形そのもの。
    // 個別の API の値は、それぞれの Theory
    // （NeverMatchingEntries_ListsEntriesThatNoHostHeaderCanEverMatch /
    //  ClassifyDeadEntryDeletion_SaysWhatDeletingWouldActuallyDo）が引き続き固定する。

    // まとめて受け取る入口が返す (名指し, 分類) の組を、行ごとに固定する。
    //
    // <b>この検査が保証しないこと（先に書く）。</b> 「名指しと分類が<b>同じ振り分け</b>から
    // 来ている」ことは<b>外から観測できない</b>ので、ここでは固定していない ——
    // 実測でも、実装を以前の「2 つの公開 API を別々に呼ぶ」形へ戻すと、
    // 値はすべて同じなので<b>全件緑のまま通る</b>。2 つの述語が一致しているあいだは
    // 1 回の振り分けと 2 回の振り分けに差が出ないからで、それはまさにこの検査が
    // 生き延びるべき場面そのもの。<b>構造の保証はコードの形（PartitionEntries が唯一の
    // 振り分け）とレビューが持つ</b>。ここに書いてあると、機械が見ていると誤解される。
    //
    // <b>この検査が保証すること。</b> 行ごとの (名指し, 分類) の値。空白付きの項目・
    // 残りがワイルドカード・正規化できない綴り・全部死ぬ、の 4 つを覆う
    // （実測: 振り分けの述語を潰すと 7 行中 4 行が落ちる）。
    // 以前は「名指しが 0 件 ⇔ NothingToDelete」だけを見ており、それは今の実装では
    // <b>構造上つねに真</b>（分類の入口が Dead.Length == 0 で、どの分岐も NothingToDelete を
    // 返さない）なので、振り分けを丸ごと潰しても緑のまま通っていた ——行を並べたぶんだけ
    // 正規化・並び順を覆っているように読めて、実際には 1 つも覆っていなかった。
    [Theory]
    // 一致しえない項目が無い設定（分類は NothingToDelete でなければならない）
    [InlineData(null, "", AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]
    [InlineData("incident.example.test", "", AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]
    [InlineData("incident.example.test;www.example.test", "", AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete)]
    // 空白付きの項目だけが死に、実ホスト名が残る＝消してよい
    [InlineData("incident.example.test; ", " ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe)]
    // 残るほうにワイルドカードがあるので、消すと全許可になる
    [InlineData("incident.example.test;0.0.0.0; ", " ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    // 残るほうに正規化できない綴りがあるので、消した結果は並び順しだい＝断定しない
    [InlineData("0.0\t.0.0; ", " ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]
    // 全部死ぬので、消すと 0 件になって既定の ["*"] へ落ちる
    [InlineData("   ", "   ", AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost)]
    public void InspectNeverMatchingEntries_NamesEntriesExactlyWhenItSaysThereIsSomethingToDelete(
        string? allowedHosts,
        string expectedDeadEntries,
        AllowedHostsPolicy.DeadEntryDeletionOutcome expectedOutcome)
    {
        // 名指しする項目と分類を、1 度の呼び出しで受け取る
        var (entries, outcome) = AllowedHostsPolicy.InspectNeverMatchingEntries(allowedHosts);

        // 期待する名指しを、書きやすいように '|' 区切りの 1 つの文字列から組み立てる
        // （項目そのものが空白なので、区切りには空白以外の文字を使う）
        var expected = expectedDeadEntries.Length == 0
            ? []
            : expectedDeadEntries.Split('|');

        // 名指しする項目が、並びまで含めて期待どおりであること
        // （理由は別の検査が見るので、ここでは綴りだけを突き合わせる）
        Assert.Equal(expected, entries.Select(dead => dead.Value));

        // 分類が期待どおりであること
        Assert.Equal(expectedOutcome, outcome);

        // 2 つが噛み合っていること（名指しが 0 件のときだけ「消す対象が無い」）。
        // <b>実装に対しては構造上つねに真</b>なので、これが見ているのは実装ではなく
        // <b>上の行</b>——行を足した人が噛み合わない組を書いてしまうのを防ぐためだけに置く
        Assert.Equal(
            entries.Count == 0,
            outcome == AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete);
    }

    // 「消してよい」の案内が、削除を<b>同列の選択肢として</b>勧めていないことを固定する。
    //
    // <b>Safe が保証するのは「絞り込みが開かないこと」だけ。</b> 名指しされる典型は
    // "incident.example.com; www.example.com" の 2 件目＝その配備先が実際に使う
    // ホスト名なので、消すと「静かに 400」が「意図して 400」へ変わるだけで、
    // 警告が暴いたはずの障害が固定される。案内は空白を外す側を先に置く。
    [Fact]
    public void DeadEntryFixAdvice_LeadsWithFixingNotDeleting()
    {
        // 「消してよい」ときの案内を取り出す
        var advice = AllowedHostsPolicy.DeadEntryFixAdvice(
            AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe);

        // 直し方（項目を書き直す）が先に案内されていること。
        // <b>ここで原因（空白）を名指ししない。</b> 一致しえない理由は 1 つではなく、
        // 案内の側が 1 つの原因を名乗ると、別の理由（ポート付き。issue #256）で
        // 名指しされた項目について<b>事実と違うこと</b>を言い出す。
        // 原因は項目ごとに DeadEntryCauseMessage が添える
        Assert.Contains("Fix each listed entry", advice, StringComparison.Ordinal);

        // 削除には条件が添えられていること（無条件の「消してよい」にしない）
        Assert.Contains("Only delete an entry if", advice, StringComparison.Ordinal);
    }

    // 既定の文面が、原因を断定していないことを固定する。
    //
    // <b>PermissiveCauseMessage は public なので、NotPermissive を渡す呼び出し側が
    // 将来現れうる。</b> 以前の既定は「絞れていない」と断定していたため、
    // そのとき正しい設定に対して事実と逆の説明を出すことになっていた。
    [Fact]
    public void FallbackPermissiveCauseMessage_DoesNotAssertTheListIsPermissive()
    {
        // 既定の文面（関数を呼ばずに定数を見る。理由は定数側の docstring）
        var fallback = AllowedHostsPolicy.FallbackPermissiveCauseMessage;

        // 「絞れていない」と断定していないこと
        Assert.DoesNotContain("is not narrowed down", fallback, StringComparison.Ordinal);

        // 正しく絞れている設定へ渡しても、事実と逆にならない文面であること
        Assert.Equal(
            fallback,
            AllowedHostsPolicy.PermissiveCauseMessage(
                AllowedHostsPolicy.PermissiveReason.NotPermissive));
    }

    // <b>ログへ出す値は、目に見えない文字を見えるようにしてから載せる。</b>
    // UnparsableEntry という分類がある時点で、この値には制御文字が入りうる
    // （"0.0\t.0.0" のような綴りのためにある）。CR / LF がそのまま載ると
    // 1 本の警告がログ上は複数のレコードに見え、docs/security.md が案内する
    // 「警告が出ていないことの確認」が偽の継続行で破れる（issue #258）。
    [Theory]
    // タブは \uXXXX の形で見えるようになる
    [InlineData("0.0\t.0.0", "0.0\\u0009.0.0")]
    // CR / LF が残らない＝レコードが分断されない（この 2 つが本命）
    [InlineData("a.test\r\nb.test", "a.test\\u000D\\u000Ab.test")]
    // 逆斜線も置き換える（そうしないと「\u0009 と書いた値」とタブ 1 文字が同じ見た目になる）
    [InlineData("a\\test", "a\\\\test")]
    // 置き換えるものが無い普通の値は、1 文字も変えずにそのまま出す
    [InlineData("incident.example.test;www.example.test", "incident.example.test;www.example.test")]
    // 前後の空白は制御文字ではないので触らない（"[ ]" の囲みが見せる役目を持つ）
    [InlineData(" a.test", " a.test")]
    // <b>NEL（U+0085）は char.IsControl が true なので、以前から置き換えられていた。</b>
    // 下の 2 つと並べてあるのは、この 3 文字が「同じ役割なのに判定だけが違う」組だから ——
    // 条件を char.IsControl へ畳み戻す変異は、この行を通したまま下の 2 行で落ちる
    [InlineData("a.test\u0085b.test", "a.test\\u0085b.test")]
    // <b>本命（issue #263）。</b> U+2028 / U+2029 は行区切りとして扱われうるのに
    // char.IsControl が false なので、条件を「制御文字か」にしていると生のまま載る
    [InlineData("a.test\u2028b.test", "a.test\\u2028b.test")]
    [InlineData("a.test\u2029b.test", "a.test\\u2029b.test")]
    // <b>行区切り以外にも「字として現れない」文字がある（レビュー指摘）。</b>
    // U+200B（幅ゼロ空白）は<b>一致しえない項目を健全な項目と見分けられなくし</b>、
    // U+202E（書字方向の上書き）は<b>警告の行の残りを逆順に描かせる</b>ので、
    // 運用者が読む 1 行を別の内容に見せられる ——どちらも Format カテゴリで、
    // char.IsControl も行区切りの 2 文字も拾わなかった
    [InlineData("a.test\u200Bb.test", "a.test\\u200Bb.test")]
    [InlineData("a.test\u202Eb.test", "a.test\\u202Eb.test")]
    // 普通の空白と、幅のある空白（U+00A0）は触らない ——
    // 空白として見えるぶん危険が小さく、カテゴリごと可視化すると普通の値が読めなくなる
    [InlineData("a.test\u00A0b.test", "a.test\u00A0b.test")]
    // 私用領域（U+E000）と未割り当て（U+FDD0）も可視化する ——
    // どちらも表示がフォント任せで、多くの環境では空白か豆腐になる。
    // <b>未割り当ての例に非文字（U+FDD0）を選ぶ（レビュー指摘）。</b>
    // Greek ブロックの空き（U+0378 など「まだ割り当てられていないだけ」の位置）は
    // 将来の Unicode で<b>実際に埋まりうる</b>ので、期待値を固定すると
    // ランタイム（ICU / CharUnicodeInfo の表）を上げただけで、
    // <b>壊れていないのに赤くなる</b>。U+FDD0 は Unicode が<b>恒久的に</b>
    // 文字を割り当てないと定めた範囲（noncharacter）なので、カテゴリ Cn が動かない
    [InlineData("a.test\uE000b.test", "a.test\\uE000b.test")]
    [InlineData("a.test\uFDD0b.test", "a.test\\uFDD0b.test")]
    // <b>BMP の外の「見えない文字」も可視化する（レビュー指摘）。</b> 符号単位で見ると
    // サロゲートの片割れになり、カテゴリは必ず Surrogate になるので Format の判定を
    // すり抜けていた ——U+E0001（Unicode Tags。見えない文字を紛れ込ませる代表的な綴り）が
    // 生のまま載っていた。コードポイント単位で見て、8 桁の形で出す
    [InlineData("a.test\U000E0001b.test", "a.test\\U000E0001b.test")]
    // BMP の外でも、字として現れるものはそのまま（絵文字・追加漢字など）
    [InlineData("a.test\U0001F600b.test", "a.test\U0001F600b.test")]
    public void DescribeValueForLog_MakesInvisibleCharactersVisible(string value, string expected)
    {
        // 可視化した綴りが期待どおりであること
        Assert.Equal(expected, AllowedHostsPolicy.DescribeValueForLog(value));
    }

    // <b>対になっていないサロゲートも必ず可視化する。</b> それ自体が不正な綴りで、
    // 描画は環境任せ（多くは空白か置換文字）なので、生で出すと読み手が値を誤解する。
    //
    // <b>[InlineData] では表せない。</b> xUnit は Theory の引数を直列化して配るため、
    // 対になっていないサロゲートは途中で置換文字（U+FFFD）へ化ける ——
    // 実測で、化けた値は「字として現れる」ので可視化されず、検査が空振りした。
    // 文字列をテストの中で組み立てれば、その経路を通らない。
    [Fact]
    public void DescribeValueForLog_MakesLoneSurrogatesVisible()
    {
        // 対になっていない上位サロゲートを挟んだ値を、テストの中で組み立てる
        var value = "a.test" + (char)0xD800 + "b.test";

        // 4 桁のコードポイントとして可視化されること
        Assert.Equal("a.test" + @"\uD800" + "b.test", AllowedHostsPolicy.DescribeValueForLog(value));
    }

    // <b>未設定は「空文字を設定した」と区別して名乗る。</b> 構造化ログの既定は
    // null を "(null)" と描くが、運用者にとってこの 2 つは別の出来事。
    [Fact]
    public void DescribeValueForLog_NamesAnUnsetValue()
    {
        // 未設定のときだけ専用の綴りを返すこと
        Assert.Equal(AllowedHostsPolicy.UnsetValueForLog, AllowedHostsPolicy.DescribeValueForLog(null));

        // 空文字は「設定したが空」なので、未設定の綴りへ畳まないこと
        Assert.NotEqual(AllowedHostsPolicy.UnsetValueForLog, AllowedHostsPolicy.DescribeValueForLog(""));
    }

    // <b>項目の一覧は「囲み＋可視化＋その項目の理由」で出す。</b> 囲み（"[ ]"）と可視化を
    // 2 本の警告で書き写すと片方だけ直る形になり（issue #258）、理由を 1 文に決め打つと
    // 混在した一覧で<b>名指しした項目について事実と違うこと</b>を言い出す（issue #256）。
    [Fact]
    public void DescribeEntriesForLog_WrapsEachEntryAndNamesItsOwnReason()
    {
        // 一致しえない 2 種類が混ざった設定値を、判定側に振り分けさせる
        // （理由を手で書くと「振り分けが付けた理由が載る」ことを検査できない）
        var (entries, _) = AllowedHostsPolicy.InspectNeverMatchingEntries(
            "incident.example.test; www.example.test;api.example.test:8080");

        // その結果をそのままログの形へ直す
        var described = AllowedHostsPolicy.DescribeEntriesForLog(entries);

        // 理由の綴りは判定側の関数から取る（文面をテストへ書き写さないため）
        var whitespace = AllowedHostsPolicy.DeadEntryCauseMessage(
            AllowedHostsPolicy.DeadEntryReason.SurroundingWhitespace);
        var port = AllowedHostsPolicy.DeadEntryCauseMessage(
            AllowedHostsPolicy.DeadEntryReason.PortSuffix);

        // 1 件ずつ "[ ]" で囲まれ、<b>その項目自身の</b>理由が添えられ、", " でつながること
        Assert.Equal(
            $"[ www.example.test] ({whitespace}), [api.example.test:8080] ({port})",
            described);
    }

    // <b>可視化の規則は 1 か所だけに置く。</b> 2 つの入口が別の規則を持つと、
    // 片方の警告だけがレコードを分断する状態へ静かに戻れてしまう。
    [Fact]
    public void DescribeEntriesForLog_AgreesWithDescribeValueForLog()
    {
        // 同じ綴りを 2 つの入口へ通す。
        // 理由は可視化とは無関係なので、ここでは任意の 1 つを添えるだけでよい
        const string entry = "a\r\nb";
        var dead = new AllowedHostsPolicy.DeadEntry(
            entry, AllowedHostsPolicy.DeadEntryReason.SurroundingWhitespace);

        // 項目側の出力が、囲みの内側で値側とまったく同じ綴りを使っていること
        // （＝同じ可視化規則を通っている）。うしろに添う理由はここでは見ない
        Assert.StartsWith(
            $"[{AllowedHostsPolicy.DescribeValueForLog(entry)}]",
            AllowedHostsPolicy.DescribeEntriesForLog([dead]),
            StringComparison.Ordinal);
    }


    // 理由ごとに専用の説明があること（＝理由を足したのに文面を足し忘れていないこと）。
    //
    // <b>この検査が無いと足し忘れは検出できない。</b> switch の _ は
    // コンパイルエラーにならず、警告レベルにもならない。しかも文面を使うのは
    // Program.cs の if (!IsDevelopment()) の中なので、統合テストからも走らない。
    // <b>既定へ落ちてよい理由は 1 つも無い</b> ——DeadEntryReason の値はどれも
    // 「一致しえない項目に添える説明」で、説明すべきでない値が存在しないため
    // （PermissiveReason の NotPermissive にあたるものが無い）。
    [Fact]
    public void DeadEntryCauseMessage_GivesEveryReasonItsOwnExplanation()
    {
        // 理由の一覧を enum そのものから取り出す（手で書かない）
        var reasons = Enum.GetValues<AllowedHostsPolicy.DeadEntryReason>();

        // 見るべき理由が 1 つも無い状態で緑にしない（fail-closed）
        Assert.NotEmpty(reasons);

        // 理由ごとの説明を集める
        var messages = reasons.ToDictionary(
            reason => reason,
            AllowedHostsPolicy.DeadEntryCauseMessage);

        // どの説明も空でないこと（空だと項目に理由が添わないまま警告が出る）
        Assert.All(messages.Values, text => Assert.False(string.IsNullOrWhiteSpace(text)));

        // 既定（＝専用の説明が無い理由）を数える。
        // 照合の相手は関数の外の定数にする（自分自身との照合にしないため。
        // 理由は AllowedHostsPolicy.FallbackDeadEntryCauseMessage の docstring が正本）
        var fallback = AllowedHostsPolicy.FallbackDeadEntryCauseMessage;
        var fellBack = messages
            .Where(pair => string.Equals(pair.Value, fallback, StringComparison.Ordinal))
            .Select(pair => pair.Key)
            .ToList();

        // 1 つでも既定へ落ちていたら、arm の足し忘れとして落とす
        Assert.True(
            fellBack.Count == 0,
            "専用の説明が無い理由があります: "
                + string.Join(", ", fellBack)
                + "。AllowedHostsPolicy.DeadEntryCauseMessage に arm を足してください"
                + "（switch の _ はコンパイルエラーにならないので、ここでしか気付けません）");
    }

    // 理由ごとに<b>違う</b>ことを言っていること。
    //
    // <b>足し忘れの検査だけでは足りない。</b> あちらは「既定と同じでないこと」しか見ないので、
    // すべての arm に同じ 1 文（たとえば元の「前後の空白が残っている」）を書いても緑のまま
    // 通る ——それは issue #256 が名指しした「名指しした項目について事実と違うことを言う」
    // 状態そのもの。
    [Fact]
    public void DeadEntryCauseMessage_DoesNotDescribeEveryEntryTheSameWay()
    {
        // 理由ごとの説明を集める
        var messages = Enum.GetValues<AllowedHostsPolicy.DeadEntryReason>()
            .Select(AllowedHostsPolicy.DeadEntryCauseMessage)
            .ToList();

        // 説明がすべて異なること（使い回しがあれば件数が減る）
        Assert.Equal(
            messages.Count,
            messages.Distinct(StringComparer.Ordinal).Count());
    }


    // <b>名指しした項目に添う理由が、その項目の事実と合っていること。</b>
    // 理由を取り違えると、警告は「出ている」のに運用者は違うところを直す ——
    // 存在しないものを探させる案内（1 本目の警告が PermissiveReason を持つ理由）と同じ形。
    // <b>数え上げを打ち切ったときは「判断できない」ので警告する側へ倒すこと。</b>
    // 上限（256）は実測の最大（46 通り）に対して十分な余裕があり、実在しうる綴りでは
    // 1 度も通らない ——つまり本物の項目を並べたテストでは、ここを「見つからなかった」側へ
    // 書き換えても全件緑のままになる。だから判定を純粋関数として直接固定する。
    // 見つからなかった扱いにすると、上限に届くような綴りだけが<b>ワイルドカードの注意を
    // 持たない文面</b>になり、運用者が案内どおり直すと全ホスト許可（issue #64）——
    // <b>上限そのものが fail-open の口</b>になる。
    [Theory]
    // ワイルドカードに当たれば、打ち切りかどうかに関係なく true
    [InlineData(new[] { "a.example.test", "0.0.0.0" }, 8, true)]
    [InlineData(new[] { "a.example.test", "[::]" }, 2, true)]
    [InlineData(new[] { "*" }, 1, true)]
    // 当たらず、上限にも届かずに数え終わったなら false（＝ふつうの「死んだ項目」）
    [InlineData(new[] { "a.example.test", "b.example.test" }, 8, false)]
    [InlineData(new string[0], 8, false)]
    // 当たらないまま上限に達したなら、判断できないので true（警告する側へ倒す）
    [InlineData(new[] { "a.example.test", "b.example.test" }, 2, true)]
    [InlineData(new[] { "a.example.test" }, 1, true)]
    public void RepairsToWildcard_TreatsATruncatedSearchAsUndecided(
        string[] repairedSpellings,
        int limit,
        bool expected)
    {
        // 合成した候補の並びと上限で、判定そのものを呼ぶ
        var actual = AllowedHostsPolicy.RepairsToWildcard(repairedSpellings, limit);

        // 期待どおりに倒れているか（打ち切りは「見つからなかった」ではない）
        Assert.Equal(expected, actual);
    }

    [Theory]
    // 区切りのうしろの空白（一覧を書くときに自然に入る形）
    [InlineData("a.example.test; b.example.test", AllowedHostsPolicy.DeadEntryReason.SurroundingWhitespace)]
    // ポート付き（ASPNETCORE_URLS を写すと自然に生まれる形。issue #256）
    [InlineData("a.example.test;b.example.test:8080", AllowedHostsPolicy.DeadEntryReason.PortSuffix)]
    // 角括弧を書かない IPv6 リテラル ——Host ヘッダー側は必ず角括弧付きで届くので一致しない。
    // <b>ポートは 1 つも無いので、ここを PortSuffix と名乗ってはいけない</b>
    [InlineData("a.example.test;fe80::1", AllowedHostsPolicy.DeadEntryReason.UnbracketedIpv6Literal)]
    [InlineData("a.example.test;::1", AllowedHostsPolicy.DeadEntryReason.UnbracketedIpv6Literal)]
    // <b>コロンが 2 つ以上あるだけの綴りは IPv6 ではない（issue #269）。</b>
    // HostString のホスト部の切り出しは IPv6 かどうかを問わず角括弧で包むので、
    // 「角括弧を足されたか」だけで決めると、この末尾コロンのタイプミスが
    // 「角括弧で囲め」と案内される ——従うと警告だけが消えて 400 は残る
    [InlineData("a.example.test;b.example.test:8080:", AllowedHostsPolicy.DeadEntryReason.NotABareHostname)]
    // <b>逆側の取り違え。</b> 角括弧を足されない綴りを一律 PortSuffix と名乗ると、
    // ポートを 1 つも含まない項目に「ポートを外せ」と案内することになる
    [InlineData("a.example.test;b]c.test", AllowedHostsPolicy.DeadEntryReason.NotABareHostname)]
    // <b>スコープ付き IPv6 を「角括弧で囲め」と案内しない。</b> 本物の Kestrel は
    // Host: [fe80::1%eth0] を 400 で弾くので、囲んでも一致するようにはならない
    [InlineData("a.example.test;fe80::1%eth0", AllowedHostsPolicy.DeadEntryReason.PercentSignInEntry)]
    // <b>角括弧の中身に「Host ヘッダーが運べない文字」があれば、囲んであっても死んでいる。</b>
    // HostString は ] を含む値を中身を問わずホスト部として受け取るので、この判定が無いと
    // 警告が 1 本も出ない（実測値は ContainsSpellingAHostHeaderCannotCarry の docstring が正本）
    [InlineData("a.example.test;[fe80::1%eth0]", AllowedHostsPolicy.DeadEntryReason.PercentSignInEntry)]
    [InlineData("a.example.test;[::1%25eth0]", AllowedHostsPolicy.DeadEntryReason.PercentSignInEntry)]
    // <b>% は角括弧の外でも運べない（レビュー指摘）。</b> 「普通のホスト名では
    // percent-encoding として合法だから」と角括弧の中だけを見ていた頃は、この形が
    // 警告 2 本とも出ないまま 400 になっていた（実測で Kestrel は Host: www.example%2Ecom を
    // 400 で弾く。比較のため a_b.test ・ a~b.test ・ xn--bcher-kva.test は 200）
    [InlineData("a.example.test;www.example%2Ecom", AllowedHostsPolicy.DeadEntryReason.PercentSignInEntry)]
    // <b>直すとワイルドカードになる形</b>。空白でもポートでも、まずこちらを名乗る
    [InlineData("a.example.test; 0.0.0.0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;0.0.0.0:8080", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test; *", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;::", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>空白が角括弧の内側へ移っても、ワイルドカードの警告から外れないこと（レビュー指摘）。</b>
    // 正規化は括弧を補うので " ::" は "[ ::]" になる。直した結果を Trim() だけで見ていた頃は
    // 内側の空白が残って [::] と一致せず、この項目だけが<b>ごく普通の「実ホスト名へ直せ」</b>の
    // 案内になっていた ——従って空白を外すと :: ＝全ホスト許可（issue #64）で、
    // <b>空白 1 つで専用警告が有害な案内に入れ替わる</b>形だった
    [InlineData("a.example.test; ::", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;[ ::]", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;[:: ]", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>角括弧が無くても、途中の空白は運べない（レビュー指摘）。</b>
    // 以前は角括弧の中だけを見ていたため "0.0.0 .0" は無警告のままで、
    // 運用者がタイプミスの空白を外すと 0.0.0.0 ＝全許可（issue #64）になっていた
    [InlineData("a.example.test;0.0.0 .0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // ワイルドカードにならない側も、黙らずに名指しされること
    // （前後の空白の警告に従って直した先が、無警告のまま 400 になるのを防ぐ）。
    // <b>理由は空白専用のものを名乗る（レビュー指摘）</b> ——NotABareHostname の文面は
    // 「角括弧で囲んでも直らない」と案内するので、空白が原因の項目に付けると事実と逆になる
    [InlineData("a.example.test;www.example .test", AllowedHostsPolicy.DeadEntryReason.WhitespaceInsideEntry)]
    // <b>% の手前がワイルドカードの形も、「そのまま直すな」の側で名乗ること（レビュー指摘）。</b>
    // 運用者が読めない末尾（%20）を削ると 0.0.0.0 ＝全許可（issue #64）になる。
    // 空白について閉じた穴が % 側に残っており、しかも "[::]%20" は括弧のおかげで
    // 当たっていたので非対称でもあった
    [InlineData("a.example.test;0.0.0.0%20", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;[::]%20", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>「% を抜く」側の直し方でもワイルドカードになる形（レビュー指摘）。</b>
    // 文面は「'%' を書くな」と案内するので運用者はこちらをしうるのに、
    // 「% 以降を削る」モデルしか見ていないと専用警告から外れていた
    [InlineData("a.example.test;%0.0.0.0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>アドレスバーから URL ごと貼った形が黙らないこと（レビュー指摘）。</b>
    // ポート付きの URL は正規化で "[https://…:8443]" になり「正規化後の綴り＝ホスト部」に
    // 化けるので、"/" を運べない文字に入れないと警告 2 本とも出ないまま 400 になる。
    // <b>理由は URL 専用のものを名乗る</b> ——ポートを書かない形は "https:" が
    // ポート区切りに見えるため、分けないと「ポートを外せ」と事実と違う案内になる
    [InlineData("a.example.test;https://b.example.test:8443", AllowedHostsPolicy.DeadEntryReason.UrlInsteadOfHostname)]
    [InlineData("a.example.test;https://b.example.test", AllowedHostsPolicy.DeadEntryReason.UrlInsteadOfHostname)]
    // <b>URL / CIDR の形でも、直すとワイルドカードになるなら専用警告のほうが勝つこと
    // （レビュー指摘）。</b> これが無いと、ASPNETCORE_URLS をそのまま貼った形のほうが
    // スキームを外した "0.0.0.0:5000" より弱い案内になるという逆転が起きる
    [InlineData("a.example.test;http://0.0.0.0:5000", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;http://0.0.0.0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;0.0.0.0/0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;::/0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>直し方が 2 つ以上要る綴りも、専用警告のほうが勝つこと（レビュー指摘）。</b>
    // 1 つずつ別々に当てていた頃は、これらが WildcardOnceRepaired から外れ、
    // <b>ワイルドカードの注意を持たない文面</b>が付いていた（従うと全許可）
    [InlineData("a.example.test; ::%20", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;http://0.0.0.0%20", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;%0.0.0.0/0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;//0.0.0.0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>正規化で空白が角括弧の内側へ移った形も同じ理由で名乗る。</b>
    // " ::1" は "[ ::1]" になる ——正しい直し方は「空白を外して [::1] と書く」ことなので、
    // 「角括弧で囲んでも直らない」と言ってはいけない
    [InlineData("a.example.test; ::1", AllowedHostsPolicy.DeadEntryReason.WhitespaceInsideEntry)]
    [InlineData("a.example.test;::1 ", AllowedHostsPolicy.DeadEntryReason.WhitespaceInsideEntry)]
    // <b>コロンが 2 つ以上ある形でも、専用警告のほうが勝つこと（レビュー指摘）。</b>
    // ホスト部の切り出しはコロンが 2 つ以上ある値を<b>丸ごと</b>角括弧で包むので、
    // ComparableSpelling だけではポートが 1 つも落ちず、これらは NotABareHostname に
    // なっていた ——その文面「ポートも余分なコロンも書くな」に従うと 0.0.0.0 ＝
    // 全ホスト許可（issue #64）。コロンが 1 つの "0.0.0.0:8080" は正しく警告されており、
    // <b>非対称</b>でもあった
    [InlineData("a.example.test;0.0.0.0:8080:", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;0.0.0.0::", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;0.0.0.0:8080:9090", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>"//" を打ち損ねた URL も同じ（レビュー指摘）。</b> "http:0.0.0.0" はホスト部が
    // "http" になるため URL 用の直し方（"://" と "/" を見る）では届かず、
    // 「ポートを外してホスト名だけを書け」という案内に従うと 0.0.0.0 になっていた
    [InlineData("a.example.test;http:0.0.0.0", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;https:*", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>逆に、ごく普通の host:port をスキームと読み違えないこと。</b>
    // コロンの手前が英字だけのときしかスキームと見なさないので、ドット・数字・ハイフンを
    // 含む綴りは頭を落とされず、これまでどおりポートの理由で名乗る
    [InlineData("a.example.test;192.168.0.1:80", AllowedHostsPolicy.DeadEntryReason.PortSuffix)]
    [InlineData("a.example.test;https:b.example.test", AllowedHostsPolicy.DeadEntryReason.PortSuffix)]
    // <b>スキームの判定を広げると、ごく普通のホスト名が「直すとワイルドカードになる」と
    // 名指しされる。</b> "b.example.test:0.0.0.0" の正しい直し方は "b.example.test" で、
    // ワイルドカードにはならない ——英字だけという条件を外すとここが
    // WildcardOnceRepaired へ倒れる（条件そのものを固定するための境界のケース。
    // 実測でも、条件を外した変異はこの 1 件が無いと全件緑のまま通った）
    [InlineData("a.example.test;b.example.test:0.0.0.0", AllowedHostsPolicy.DeadEntryReason.PortSuffix)]
    [InlineData("a.example.test;192.168.0.1:0.0.0.0", AllowedHostsPolicy.DeadEntryReason.PortSuffix)]
    // <b>直し方は「順番を決め打った組み合わせ」ではなく閉包で当てること（レビュー指摘）。</b>
    // "http:0.0.0.0:8080:" は「スキームを外す」→「コロンから先を落とす」の<b>順</b>が要る。
    // 決め打ちの順番で数え上げていた頃はここが NotABareHostname になり、その文面
    // 「ポートも余分なコロンも書くな」に従うと 0.0.0.0 ＝全ホスト許可（issue #64）だった
    [InlineData("a.example.test;http:0.0.0.0:8080:", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    [InlineData("a.example.test;http:0.0.0.0::", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // <b>末尾のポートだけを外す直し方も要る（レビュー指摘）。</b> ":::8080" は
    // netstat が IPv6 の待受を表示する形で、最初のコロンで切る直し方では届かない
    [InlineData("a.example.test;:::8080", AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired)]
    // 逆に、素の IPv6 リテラル（"::1" ・ "fe80::1"）の末尾をポートと読み違えないことは、
    // 上の UnbracketedIpv6Literal のケースがそのまま固定している（重複して書かない）
    public void InspectNeverMatchingEntries_NamesWhyEachEntryCannotMatch(
        string allowedHosts, AllowedHostsPolicy.DeadEntryReason expectedReason)
    {
        // 振り分けを実行する
        var (entries, _) = AllowedHostsPolicy.InspectNeverMatchingEntries(allowedHosts);

        // 死んでいる項目はどのケースも 1 件だけ（2 件目が混ざると検査の意味が変わる）
        var dead = Assert.Single(entries);

        // その 1 件に添う理由が、期待どおりであること
        Assert.Equal(expectedReason, dead.Reason);
    }

    // <b>角括弧の扱いを厳しくした代償で、生きている項目を巻き込んでいないこと。</b>
    //
    // 角括弧の項目に「中身に空白か % があれば死んでいる」を足したので、
    // <b>本当に一致する綴りまで「消してよい」と案内していないか</b>を対で押さえる
    // ——生きている項目を名指しするのは、見逃しより重い誤り（このクラスの docstring が正本）。
    // 並べた綴りはいずれも、本物の Kestrel が Host ヘッダーとして 200 で受け付けることを
    // 実測してある（実測値は AllowedHostsPolicy.ContainsSpellingAHostHeaderCannotCarry の
    // docstring が正本。そこには「IPv6 として正しいかとは無関係」だった実測も載せてある）。
    [Theory]
    // 短縮形のループバック
    [InlineData("[::1]")]
    // リンクローカル（スコープ無し）
    [InlineData("[fe80::1]")]
    // IPv4 射影アドレス
    [InlineData("[::ffff:192.168.0.1]")]
    // 省略しない書き方
    [InlineData("[0:0:0:0:0:0:0:1]")]
    public void BracketedPlainIpv6Literals_AreStillTreatedAsLive(string entry)
    {
        // 実ホスト名と併記する（片方が生きている、いちばん紛らわしい形）
        var allowedHosts = $"a.example.test;{entry}";

        // どの項目も「一致しえない」と名指しされないこと
        Assert.Empty(AllowedHostsPolicy.NeverMatchingEntries(allowedHosts));

        // 全許可でもないこと（絞り込みは効いている）
        Assert.False(AllowedHostsPolicy.IsPermissive(allowedHosts));
    }

    // <b>いちばん危ない形: 案内どおりに直すと全ホスト許可になる項目（レビュー指摘）。</b>
    //
    // "incident.example.test;0.0.0.0:8080" は ASPNETCORE_URLS を写すと自然に生まれる。
    // 消せば実ホスト名だけが残るので<b>削除の分類は Safe</b> ——ところが 2 本目の警告が
    // 実際に勧めるのは「書き直す」ほうで、案内どおりポートを外すと 0.0.0.0 になり
    // <b>ホスト名の絞り込みが丸ごと無効になる</b>（issue #64 へ移る）。
    // 前後の空白でも同じで、こちらは issue #256 以前から同じ形だった。
    [Fact]
    public void DeadEntryThatWouldBecomeAWildcard_IsNotPresentedAsASimpleRepair()
    {
        // 消すだけなら安全だが、直すと全許可になる設定値
        const string allowedHosts = "incident.example.test;0.0.0.0:8080";

        // 振り分けと分類を受け取る
        var (entries, outcome) = AllowedHostsPolicy.InspectNeverMatchingEntries(allowedHosts);

        // <b>削除の分類は Safe のまま</b>（消す操作についての事実は変わらない）
        Assert.Equal(AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe, outcome);

        // <b>本命。</b> その項目には「直すとワイルドカードになる」理由が添うこと ——
        // ここが PortSuffix のままだと「ポートを外せばよい」と読めてしまう
        Assert.Equal(
            AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired,
            Assert.Single(entries).Reason);

        // 文面が、そのまま直すことを<b>止めて</b>いること（読み手が踏む一歩を封じる）
        var cause = AllowedHostsPolicy.DeadEntryCauseMessage(
            AllowedHostsPolicy.DeadEntryReason.WildcardOnceRepaired);
        Assert.Contains("do NOT", cause, StringComparison.Ordinal);
        Assert.Contains("Replace it with a real hostname", cause, StringComparison.Ordinal);
    }

}
