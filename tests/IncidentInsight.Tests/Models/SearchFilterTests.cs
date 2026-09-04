// 検証対象(絞り込み入力の空判定の唯一の真実の源)を取り込む
using IncidentInsight.Web.Models.Validation;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

/// <summary>
/// 一覧画面の絞り込み入力の空判定 <see cref="SearchFilter.HasValue"/> の規則を固定するテスト。
///
/// <para>各コントローラ側にも「空白のみの入力で全件が返ること」を確かめるテストがあるが、
/// それらは<b>呼び出し側が実際にこの関数を通っているか</b>を押さえるためのもの。ここでは
/// <b>規則そのもの</b>(どの入力を「未入力」とみなすか)を独立に固定する。両方が要るのは、
/// 片方だけだと退行を取り逃すため:</para>
/// <list type="bullet">
///   <item>この関数の規則を <c>string.IsNullOrEmpty</c> へ緩めると、コントローラ側の
///     テストは落ちるが「どこが壊れたか」は分からない(3 画面が一斉に落ちる)。</item>
///   <item>逆に、あるコントローラだけ呼び出しを素の <c>IsNullOrEmpty</c> へ戻すと、
///     この関数のテストは緑のまま通る(だからコントローラ側のテストも要る)。</item>
/// </list>
///
/// <para>issue #187 の回帰: 空判定が画面ごとに書かれていて、カンバンだけが
/// <c>IsNullOrEmpty</c> だった。空白のみの入力で絞り込みが実際に走り、日本語の氏名・部署名に
/// 一致しないため盤面が空になっていた。</para>
/// </summary>
public class SearchFilterTests
{
    // 「未入力」として扱うべき入力。空白の種類を並べているのは、規則が
    // char.IsWhiteSpace ベース(= 全角スペースやタブも含む)であることまで固定するため。
    // ここを ASCII の半角スペースだけに絞ると、IME 由来の全角スペースが素通りする退行を見逃す
    [Theory]
    [InlineData(null)]          // 未指定(クエリ文字列にキーが無い)
    [InlineData("")]            // 空文字(入力欄を空のまま送信)
    [InlineData(" ")]           // 半角スペース 1 つ
    [InlineData("   ")]         // 半角スペース複数(貼り付け時に混入しやすい)
    [InlineData("\t")]          // タブ
    [InlineData("\n")]          // 改行
    [InlineData("　")]          // 全角スペース(IME の確定ミスで入りやすい)
    [InlineData(" 　\t ")]      // 半角・全角・タブの混在
    public void HasValue_BlankInput_ReturnsFalse(string? blankInput)
    {
        // 空・空白のみは「絞り込み無し」なので false を返すこと
        Assert.False(SearchFilter.HasValue(blankInput));
    }

    // 「入力あり」として扱うべき入力。空白を含んでいても、空白以外の文字が
    // 1 つでもあれば絞り込みを適用する(前後の空白を取り除く判断はしない = 値は加工しない)
    [Theory]
    [InlineData("看護部")]      // 通常の日本語入力
    [InlineData("a")]           // 1 文字
    [InlineData(" 看護部")]     // 前に空白が付いた入力
    [InlineData("看護部 ")]     // 後ろに空白が付いた入力(貼り付けで混入しやすい)
    [InlineData("看護 部")]     // 語中に空白を含む入力
    public void HasValue_MeaningfulInput_ReturnsTrue(string input)
    {
        // 空白以外の文字を含むなら絞り込みを適用するので true を返すこと
        Assert.True(SearchFilter.HasValue(input));
    }

    // 「絞り込みに使わなかった入力は画面へ返さない」側の規則(issue #204 課題 2)。
    // 上の HasValue と同じ空判定を使うので、入力の並びもそのまま同じものを使う
    // ——別の一覧にすると、空白の種類を足したときに片方だけが古くなる
    [Theory]
    [InlineData(null)]          // 未指定(クエリ文字列にキーが無い)
    [InlineData("")]            // 空文字(入力欄を空のまま送信)
    [InlineData(" ")]           // 半角スペース 1 つ
    [InlineData("   ")]         // 半角スペース複数(貼り付け時に混入しやすい)
    [InlineData("\t")]          // タブ
    [InlineData("\n")]          // 改行
    [InlineData("　")]          // 全角スペース(IME の確定ミスで入りやすい)
    [InlineData(" 　\t ")]      // 半角・全角・タブの混在
    public void Adopted_BlankInput_ReturnsNull(string? blankInput)
    {
        // 絞り込みに使っていない値は画面へ戻さない(null に潰す)
        Assert.Null(SearchFilter.Adopted(blankInput));
    }

    // 採用した値は<b>加工せずそのまま</b>返す。前後の空白を落とすのは検索の一致範囲を
    // 変える別の判断なので、この関数はしない(HasValue の解説と同じ扱い)
    [Theory]
    [InlineData("看護部")]      // 通常の日本語入力
    [InlineData("a")]           // 1 文字
    [InlineData(" 看護部")]     // 前に空白が付いた入力
    [InlineData("看護部 ")]     // 後ろに空白が付いた入力(貼り付けで混入しやすい)
    [InlineData("看護 部")]     // 語中に空白を含む入力
    public void Adopted_MeaningfulInput_ReturnsItUnchanged(string input)
    {
        // 受け取った文字列と同一のものが返ること(トリミング等の加工をしない)
        Assert.Equal(input, SearchFilter.Adopted(input));
    }
}
