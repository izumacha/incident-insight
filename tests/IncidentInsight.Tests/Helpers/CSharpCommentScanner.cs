// 字句解析の結果(トリビア)を読むために Roslyn の共通型を使う
using Microsoft.CodeAnalysis;
// C# として解析するための入り口
using Microsoft.CodeAnalysis.CSharp;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// C# のソースを<b>本物の字句解析</b>で読み、コメントだけを取り除いた実コードを行ごとに返す。
/// </summary>
/// <remarks>
/// <para><b>なぜ自前の走査をやめたのか。</b> ソースを 1 文字ずつ見てコメントとリテラルを
/// 分ける自前の走査は、<b>綴りの前後から「ここはリテラルの開きか」を当てる</b>形にならざるを
/// 得ない。その当て方は C# の文法を近似しているだけなので、外れると静かに壊れる。
/// 実際に 2 つの fail-open が出た。
/// <list type="bullet">
///   <item>issue #249 … 開きと見なす直前の文字を集合で持っていたため、
///     <c>return "…"</c> ・ <c>=&gt; "…"</c> ・ <c>case "…":</c> がリテラルとして読まれず、
///     中身の <c>//</c>（URL がこの形）で<b>その行の残りが走査から落ちた</b>。</item>
///   <item>issue #252 … 改行をまたぐリテラル（逐語的 <c>@"…"</c> ・ 生文字列 <c>"""…"""</c>）の
///     状態を行をまたいで持ち越さなかったため、2 行目以降が素の実コードとして読まれ、
///     そこに <c>/*</c> があると閉じ綴りがリテラルの中にしか無いので
///     <b>以降のファイル全体がコメント扱い</b>になった。</item>
/// </list>
/// どちらも「PHI を返す応答に <c>Cache-Control: public</c> を直接書いても検査に載らない」
/// 向き＝<b>見逃す側</b>。そして<b>綴りを 1 つずつ足す直し方は筋が悪い</b> ——
/// <c>&gt;</c> を「開きに見える文字」へ足すと、今度は Razor の地の文
/// （<c>&lt;p&gt;"レベル3 以上&lt;/p&gt;</c>）が開きと判定されて<b>正しいコードで赤くなる</b>。
/// 向きを逆に踏み直すだけで、近似であることは変わらない。</para>
///
/// <para><b>だから C# は C# のパーサに読ませる。</b> CLAUDE.md と
/// <c>CSharpLiteral.FindStringLiteralEnd</c> の解説が揃って
/// 「次に穴が出たら、綴りを 1 つずつ足すのではなく本物のパーサへ移すこと」と書いており、
/// 穴が 2 つ出たのでその指示に従う。<c>.github/dependabot.yml</c> を
/// インデントの数え上げではなく YAML パーサで読むようにしたのと同じ形の対処。</para>
///
/// <para><b><c>.cshtml</c> はここでは読まない。</b> Razor は C# ではなく、
/// マークアップの地の文に閉じない引用符（<c>Bob's</c>）が普通に現れる ——
/// C# として解析すると、その 1 文字から先の解釈が総崩れになる。ビューは引き続き
/// 利用側の走査（直前の文字を見る近似）が読む。<b>近似が要るのは Razor だけ</b>に
/// なったので、issue #249 の形（<c>return "…//…"</c>）が残るのもビューの中だけになる。</para>
///
/// <para><b>リテラルの中身は実コードとして残す。</b> 取り除くのは<b>コメントだけ</b>。
/// ヘッダー名は文字列キーとして書かれる（<c>Response.Headers["Cache-Control"] = …</c>）ので、
/// リテラルごと読み飛ばすと本命を取り落とす。</para>
/// </remarks>
public static class CSharpCommentScanner
{
    /// <summary>
    /// C# のソースを、<b>元の行</b>と<b>コメントを取り除いた実コード</b>の対で返す。
    /// </summary>
    /// <remarks>
    /// 行番号は 1 始まりで、<c>File.ReadAllLines</c> と同じ数え方になる。
    /// 解析に失敗する（文法として壊れた）ソースでも、Roslyn はエラーを含む木を返し
    /// トリビアの分類は行うので、例外にはならない。
    /// </remarks>
    /// <param name="source">C# のソース全体。</param>
    /// <returns>行番号(1 始まり)・元の行(前後の空白を落としたもの)・実コードの組。</returns>
    public static List<(int LineNumber, string Text, string Code)> CodeLines(string source)
    {
        // C# として解析する(壊れたソースでもエラーノード付きの木が返る)
        var tree = CSharpSyntaxTree.ParseText(source);
        // 行の区切りを解析器と同じ規則で扱うため、解析器が持つテキストを使う
        var text = tree.GetText();

        // 各文字が「コメントの一部か」を持つ印(既定はすべて実コード)
        var isComment = new bool[source.Length];

        // 木の中のトリビア(空白・コメント・プリプロセッサ)を、入れ子も含めてすべて見る
        foreach (var trivia in tree.GetRoot().DescendantTrivia(descendIntoTrivia: true))
        {
            // コメント以外のトリビア(空白・改行・無効化された領域)は実コード側に残す
            if (!IsComment(trivia.Kind())) continue;

            // そのコメントが占める範囲
            var span = trivia.Span;

            // 範囲の文字に「コメント」の印を付ける
            for (var i = span.Start; i < span.End && i < isComment.Length; i++)
            {
                // この 1 文字はコメントなので実コードから外す
                isComment[i] = true;
            }
        }

        // 結果を貯める
        var result = new List<(int, string, string)>(text.Lines.Count);

        // 1 行ずつ、元の行とコメントを除いた実コードを組にする
        foreach (var line in text.Lines)
        {
            // 改行を含まない、その行の範囲
            var span = line.Span;
            // コメントを除いた文字だけを貯める入れ物
            var code = new System.Text.StringBuilder(span.Length);

            // 範囲の文字を順に見て、コメントでないものだけを残す
            for (var i = span.Start; i < span.End; i++)
            {
                // コメントの印が付いている文字は飛ばす
                if (isComment[i]) continue;
                // 実コードの 1 文字として貯める
                code.Append(source[i]);
            }

            // 行番号(1 始まり)・元の行・実コードを記録する
            result.Add((line.LineNumber + 1, source.Substring(span.Start, span.Length).Trim(), code.ToString().Trim()));
        }

        // 全行を返す
        return result;
    }

    /// <summary>そのトリビアが<b>コメント</b>かどうかを返す。</summary>
    /// <remarks>
    /// <b>プリプロセッサで無効化された領域(<c>#if false</c> の中)はコメントに数えない。</b>
    /// そこに書かれた指示は条件次第で有効になりうるので、実コードとして残す
    /// ——取りこぼす側ではなく<b>多く報告する側</b>へ倒す(この走査はもともと過剰報告を
    /// 織り込んでおり、見逃しだけが織り込めない)。
    /// </remarks>
    /// <param name="kind">トリビアの種類。</param>
    /// <returns>コメントなら true。</returns>
    private static bool IsComment(SyntaxKind kind) =>
        // C# のコメントは 4 種類(行・ブロックと、それぞれのドキュメントコメント)
        kind is SyntaxKind.SingleLineCommentTrivia
            or SyntaxKind.MultiLineCommentTrivia
            or SyntaxKind.SingleLineDocumentationCommentTrivia
            or SyntaxKind.MultiLineDocumentationCommentTrivia;
}
