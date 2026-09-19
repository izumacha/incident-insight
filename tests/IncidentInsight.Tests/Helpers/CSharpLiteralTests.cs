
// このテストが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// ソースを走査する検査が共有するリテラルの読み取り（<see cref="CSharpLiteral"/>）の境界。
/// </summary>
/// <remarks>
/// <b>利用側ごしにしか見ていない境界を、ここで直に固定する。</b> このヘルパーは
/// 2 つの走査から使われるが、どちらも「今このリポジトリに現れる書き方」しか通さないので、
/// 現れない書き方の扱いを変えても利用側のテストは緑のままになる
/// （実測: 改行の扱いを外しても全件緑だった）。
/// </remarks>
public class CSharpLiteralTests
{
    // ふつうの "…" は改行をまたげないので、閉じないまま改行に出会ったら読み取り不能を返すこと。
    //
    // <b>なぜ要るのか（静かな fail-open）。</b> 打ち切らないと、位置がずれた走査が
    // <b>次の行以降の引用符</b>を終端として拾い、あいだの実コードが丸ごとリテラルの中身として
    // 潰される。ModelState 側の走査は潰した範囲を空白で埋めるので、そこにある
    // StartsWith( の検査漏れが<b>報告されなくなる</b> ——まさにその漏れを捕まえるための走査が、
    // 自分で見えなくしてしまう。姉妹の FindCharLiteralEnd は同じ理由で既に打ち切っている。
    [Fact]
    public void FindStringLiteralEnd_StopsAtANewline_ForLiteralsThatCannotSpanLines()
    {
        // 1 行目に閉じない " があり、2 行目に別の " があるソース
        const string source = "var a = \"閉じない\nif (k.StartsWith(\"A\")) { }";
        // 1 行目の開き引用符の位置を求める
        var openingQuote = source.IndexOf('"');

        // 改行で打ち切るので読み取り不能（2 行目の引用符を終端として拾わない）
        Assert.Equal(-1, CSharpLiteral.FindStringLiteralEnd(source, openingQuote));

        // 姉妹の文字リテラル側も同じ規則であること（片方だけ直す変更を防ぐ）
        Assert.Equal(-1, CSharpLiteral.FindCharLiteralEnd("var a = '閉じない\nvar b = 'x';", 8));

        // <b>行末が \ の形も、姉妹そろって打ち切ること。</b> ここを「エスケープが無い形」
        // だけで確かめていたため、文字リテラル側に同じ穴が残っているのを見落としていた
        // （実測: 次の行のアポストロフィを終端として拾っていた）
        Assert.Equal(-1, CSharpLiteral.FindCharLiteralEnd("var a = 'x\\\nvar b = 'y';", 8));
    }

    // 行末が <c>\</c> で終わるリテラルでも、改行の打ち切りが効くこと。
    //
    // <b>なぜ別に要るのか（実測）。</b> 改行の検査をエスケープの検査より<b>後ろ</b>に置くと、
    // 「次の 1 文字を飛ばす」が改行そのものを食べてしまい、打ち切りが一度も効かない
    // ——次の行の引用符を終端として拾い、あいだの実コードが丸ごと潰される。
    // 正しい C# では通常のリテラルが行末を <c>\</c> で終えることは無いが、
    // この走査は <c>.cshtml</c> の地の文（<c>"</c> が HTML の属性の区切りでもある）も読む。
    [Fact]
    public void FindStringLiteralEnd_StopsAtANewline_EvenWhenTheLineEndsWithABackslash()
    {
        // 1 行目が \ で終わり、2 行目に別の " があるソース
        const string source = "var a = \"abc\\\nif (k.StartsWith(\"A\")) { }";

        // エスケープが改行を食べずに打ち切ること
        Assert.Equal(-1, CSharpLiteral.FindStringLiteralEnd(source, 8));
    }

    // 改行をまたげるリテラルは、改行の先まで読んで正しい終端を返すこと。
    //
    // 上の打ち切りを「全部のリテラル」へ広げると、逐語的リテラルと生文字列が
    // 読めなくなる（どちらも改行をまたぐのが正しい書き方）。
    [Theory]
    // 逐語的リテラルは改行をまたぐ
    [InlineData("var a = @\"1 行目\n2 行目\";", 9)]
    // 生文字列リテラルも改行をまたぐ
    [InlineData("var a = \"\"\"\n本文\n\"\"\";", 8)]
    public void FindStringLiteralEnd_ReadsPastNewlines_ForLiteralsThatCanSpanLines(
        string source, int openingQuote)
    {
        // 終端が見つかること（改行の手前で打ち切っていないこと）
        var end = CSharpLiteral.FindStringLiteralEnd(source, openingQuote);

        // 読み取れていること
        Assert.True(end > openingQuote, $"終端を読み取れませんでした（戻り値 {end}）。");

        // 終端が改行より後ろにあること（＝またげている）
        Assert.True(
            end > source.IndexOf('\n'),
            "改行の手前で打ち切っています。逐語的リテラルと生文字列は改行をまたげます。");

        // <b>返すのは閉じ引用符「の」位置（その次ではない）。</b> 利用側はこの規約に
        // 合わせて +1 したり、そのまま位置として使ったりしている ——1 つずれると
        // 片方はリテラルの外を 1 文字飛ばし、もう片方は閉じ引用符を潰す。
        // ここを押さえないと、その off-by-one がこのファイルでは緑のまま通る
        Assert.Equal('"', source[end]);
        Assert.Equal(source.LastIndexOf('"'), end);
    }

    // CR だけで改行するソースでも、またげないリテラルを打ち切ること。
    //
    // <b>\n だけを見ると効かない。</b> CRLF は \r の次が \n なので \n だけでも止まるが、
    // CR だけのファイルは止まらず、<b>次の行の引用符を終端として拾う</b>（実測）。
    // 姉妹（文字リテラル側）も同じなので、両方を押さえる。
    [Fact]
    public void FindLiteralEnd_StopsAtALoneCarriageReturn()
    {
        // 文字列リテラル側
        Assert.Equal(-1, CSharpLiteral.FindStringLiteralEnd("a = \"x\ry = \"z\";", 4));

        // 文字リテラル側（片方だけ直す変更を防ぐ）
        Assert.Equal(-1, CSharpLiteral.FindCharLiteralEnd("a = 'x\ry = 'z';", 4));
    }

    // 接頭辞の遡り方が、「逐語的か」と「補間か」で同じであること。
    //
    // <b>@$" は両方に当てはまる。</b> 遡り方を片方だけ直すと、この綴りの扱いが
    // 2 つの答えに割れ、エスケープの規則をどちらで読むかがずれる。
    [Theory]
    // どちらでもない
    [InlineData("x = \"a\"", 4, false, false)]
    // 逐語的だけ
    [InlineData("x = @\"a\"", 5, true, false)]
    // 補間だけ
    [InlineData("x = $\"a\"", 5, false, true)]
    // 両方（順序を変えても同じ）
    [InlineData("x = @$\"a\"", 6, true, true)]
    [InlineData("x = $@\"a\"", 6, true, true)]
    public void IsVerbatimAndIsInterpolated_ReadTheSamePrefix(
        string source, int quoteIndex, bool expectedVerbatim, bool expectedInterpolated)
    {
        // 逐語的かの判定
        Assert.Equal(expectedVerbatim, CSharpLiteral.IsVerbatim(source, quoteIndex));

        // 補間かの判定（同じ接頭辞を同じ遡り方で読む）
        Assert.Equal(expectedInterpolated, CSharpLiteral.IsInterpolated(source, quoteIndex));
    }

    // 接頭辞を遡って逐語的かを判定すること（直前 1 文字だけ見る版に戻さない）。
    [Theory]
    // 素の逐語的リテラル
    [InlineData("x = @\"a\"", 5, true)]
    // 補間つき（順序の違う 2 通り）
    [InlineData("x = @$\"a\"", 6, true)]
    [InlineData("x = $@\"a\"", 6, true)]
    // 補間だけなら逐語的ではない
    [InlineData("x = $\"a\"", 5, false)]
    // 接頭辞が無ければ逐語的ではない
    [InlineData("x = \"a\"", 4, false)]
    public void IsVerbatim_LooksBackThroughThePrefix(string source, int quoteIndex, bool expected)
    {
        // 接頭辞を遡った判定が期待どおりであること
        Assert.Equal(expected, CSharpLiteral.IsVerbatim(source, quoteIndex));
    }
}
