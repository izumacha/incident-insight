// テスト対象(並び順の受け付け規則)を使う
using IncidentInsight.Web.Models.Validation;

namespace IncidentInsight.Tests.Models;

/// <summary>
/// <c>/Incidents</c> の並び順 <c>?sortBy=</c> の受け付け規則を固定する
/// (規則の正本は <see cref="IncidentSortOrder"/> の解説。issue #209)。
///
/// <para>ここが見るのは<b>純粋な規則</b>だけ。実際にコントローラとビューが
/// この規則を通しているかは <c>Controllers.IncidentSortOrderPolicyTests</c> が見る
/// ——規則が正しくても配線されていなければ画面は元の壊れ方のままなので、
/// 両方を別々に固定する。</para>
/// </summary>
public class IncidentSortOrderTests
{
    // --- Adopted: 採用した値だけを返す ----------------------------------------

    // 選択肢に載っている値はそのまま採用する(利用者が選んだ結果として URL に残す)。
    // 定数を直接渡さず「URL に現れる綴り」で書くのは、定数の値を書き換えたときに
    // ここが追随してしまって外部から見える契約の変化を見逃さないようにするため
    [Theory]
    // 既定の並び順を明示的に選んだ場合
    [InlineData("latest")]
    // 重症度の高い順
    [InlineData("severity")]
    // 未完了の期限超過対策あり優先
    [InlineData("overdue")]
    public void Adopted_KeepsAValueTheScreenOffers(string requested)
    {
        // 受け付ける値なので、受け取った文字列がそのまま返る(加工もしない)
        Assert.Equal(requested, IncidentSortOrder.Adopted(requested));
    }

    // 受け付けない値は画面へ返さない。返すとページャのリンクが全部その値を運ぶ
    // (?search=%20 とまったく同じ壊れ方。issue #204 課題 2 / #209)
    [Theory]
    // 未指定(クエリ文字列にそもそも無い)
    [InlineData(null)]
    // 空文字(?sortBy= だけを付けた場合)
    [InlineData("")]
    // 空白のみ
    [InlineData("   ")]
    // 綴り違い・URL の改ざん
    [InlineData("bogus")]
    // 大文字小文字違い。序数比較なので受け付けない
    // (受け付けないこと自体は画面と食い違わない —— <select> も既定の「最新順」を指す)
    [InlineData("Severity")]
    [InlineData("LATEST")]
    // 前後に空白が付いた値(コピー&ペーストで起きる)。値は加工しないので採用しない
    [InlineData(" severity")]
    public void Adopted_DropsAValueTheScreenDoesNotOffer(string? requested)
    {
        // 並び替えに使っていない値なので null に潰す
        Assert.Null(IncidentSortOrder.Adopted(requested));
    }

    // --- Effective: 実際に適用する並び順 --------------------------------------

    // 受け付ける値はそのまま適用する
    [Theory]
    [InlineData("latest")]
    [InlineData("severity")]
    [InlineData("overdue")]
    public void Effective_AppliesAValueTheScreenOffers(string requested)
    {
        // 適用する並び順は受け取った値そのもの
        Assert.Equal(requested, IncidentSortOrder.Effective(requested));
    }

    // 受け付けない値・未指定は既定(最新順)へ倒す。
    // 「null を返す」ではなく必ず 1 つに決まることが要点 ——並び替えは
    // 「掛けない」という選択肢が無い(必ず何らかの順で並ぶ)ため
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bogus")]
    [InlineData("Severity")]
    public void Effective_FallsBackToTheDefault(string? requested)
    {
        // 既定は発生日の新しい順
        Assert.Equal(IncidentSortOrder.Latest, IncidentSortOrder.Effective(requested));
    }

    // --- 選択肢の一覧そのものが満たすべき不変条件 -----------------------------

    // 選択肢の先頭は必ず既定の並び順にする。?sortBy= 未指定のときはどの <option> にも
    // selected が付かず、ブラウザは先頭を選ぶ ——先頭が既定でなければ、画面の表示
    // (先頭の項目)と実際の並び(既定)が食い違う
    [Fact]
    public void Options_StartWithTheDefaultSortOrder()
    {
        // 先頭の選択肢が既定の並び順であること
        Assert.Equal(IncidentSortOrder.Latest, IncidentSortOrder.Options[0].Value);
    }

    // 選択肢に載せた値は必ず採用される(＝画面に出しているのに選ぶと無視される項目が無い)。
    // Adopted は Options から導いているので当たり前に見えるが、判定を
    // 「定数 3 つとの比較」のような別の書き方へ変えたときに、この対応が崩れたことを
    // ここが落とす ——崩れると「メニューにあるのに選んでも効かない」項目が生まれる
    [Fact]
    public void Options_AreAllAdoptable()
    {
        // すべての選択肢について、その値がそのまま採用されること
        Assert.All(IncidentSortOrder.Options, option =>
            Assert.Equal(option.Value, IncidentSortOrder.Adopted(option.Value)));
    }

    // 選択肢の値が重複していない。重複すると同じ値の <option> が 2 つ並び、
    // どちらにも selected が付いてブラウザの挙動が実装依存になる
    [Fact]
    public void Options_HaveNoDuplicateValues()
    {
        // 値の一覧を取り出す
        var values = IncidentSortOrder.Options.Select(option => option.Value).ToList();
        // 重複を除いた件数が元の件数と一致すること
        Assert.Equal(values.Count, values.Distinct(StringComparer.Ordinal).Count());
    }

    // 選択肢のラベルが空でない。空だと画面に高さゼロの選べない項目が出る
    // (値だけ足してラベルを書き忘れたときにここで落ちる)
    [Fact]
    public void Options_AllHaveALabel()
    {
        // どの選択肢もラベルを持つこと
        Assert.All(IncidentSortOrder.Options, option =>
            Assert.False(string.IsNullOrWhiteSpace(option.Label),
                $"並び順 {option.Value} の日本語ラベルが空。画面に選べない項目が出る。"));
    }
}
