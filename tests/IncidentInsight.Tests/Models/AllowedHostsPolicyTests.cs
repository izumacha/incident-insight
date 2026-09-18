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
    [InlineData("0.0.0.0\t", "0.0.0.0\t")]
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

    // --- 判断できない（残る項目に正規化できない綴りがある）---
    // <b>並び順で結果が変わるので断定してはいけない。</b> 実測では
    //   "0.0<TAB>.0.0;0.0.0.0" → 例外（どの Host も受け付けない）
    //   "0.0.0.0;0.0<TAB>.0.0" → 200（どの Host も受け付ける）
    // TryProcessHosts が宣言順に正規化し、最初のワイルドカードで打ち切るため。
    // bool で答えるとどちらかの並びで必ず事実と逆の案内になる
    [InlineData("0.0\t.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]
    [InlineData("0.0\t.0.0;0.0.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]
    [InlineData("0.0.0.0;0.0\t.0.0; ", AllowedHostsPolicy.DeadEntryDeletionOutcome.Unknown)]
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

        // 既定（＝専用の案内が無い分類）へ落ちているものを数える
        var fallback = AllowedHostsPolicy.DeadEntryFixAdvice(
            AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete);
        var fellBack = advice
            .Where(pair => string.Equals(pair.Value, fallback, StringComparison.Ordinal))
            .Select(pair => pair.Key)
            .ToList();

        // 既定へ落ちてよいのは NothingToDelete だけ
        Assert.True(
            fellBack.SequenceEqual([AllowedHostsPolicy.DeadEntryDeletionOutcome.NothingToDelete]),
            "専用の案内が無い分類があります: "
                + string.Join(", ", fellBack)
                + "。AllowedHostsPolicy.DeadEntryFixAdvice に arm を足してください"
                + "（switch の _ はコンパイルエラーにならないので、ここでしか気付けません）");
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
}
