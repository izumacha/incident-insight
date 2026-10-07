// 字句解析の結果(トリビア)を読むために Roslyn の共通型を使う
using Microsoft.CodeAnalysis;
// C# として解析するための入り口
using Microsoft.CodeAnalysis.CSharp;
// 行の区切りを解析器と同じ規則で扱うための表現
using Microsoft.CodeAnalysis.Text;

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
    /// 行番号は 1 始まりで、区切りの規則は <see cref="SplitLines"/> が持つ
    /// (ビュー側の走査と同じ規則を使う)。
    /// 解析に失敗する（文法として壊れた）ソースでも、Roslyn はエラーを含む木を返し
    /// トリビアの分類は行うので、例外にはならない。
    /// </remarks>
    /// <param name="source">C# のソース全体。</param>
    /// <returns>行番号(1 始まり)・元の行(前後の空白を落としたもの)・実コードの組。</returns>
    public static List<(int LineNumber, string Text, string Code)> CodeLines(string source)
    {
        // 各文字が「コメントの一部か」を持つ印(既定はすべて実コード)
        var isComment = new bool[source.Length];
        // コメントの範囲に印を付ける(#if で無効化された領域の中もたどる)
        MarkComments(source, offset: 0, isComment);

        // 行の区切りは共有の規則で決める(ビュー側の走査と数え方をそろえるため)
        var lines = SourceLines(source);
        // 結果を貯める
        var result = new List<(int, string, string)>(lines.Count);

        // 1 行ずつ、元の行とコメントを除いた実コードを組にする
        foreach (var line in lines)
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

    /// <summary>
    /// ソースを行に分ける(<c>.cs</c> と <c>.cshtml</c> の走査で<b>同じ規則</b>を使うための入り口)。
    /// </summary>
    /// <remarks>
    /// <b>2 つの経路で数え方をそろえるために公開している。</b> 同じ 1 つの検査が
    /// <c>.cs</c> と <c>.cshtml</c> の両方を読み、どちらも「ファイル:行番号」で名指しする。
    /// 片方を <c>File.ReadAllLines</c>(<c>\r\n</c> ・ <c>\r</c> ・ <c>\n</c> だけで分ける)、
    /// もう片方を解析器の規則(それらに加えて <c>U+0085</c> ・ <c>U+2028</c> ・ <c>U+2029</c> でも分ける)で
    /// 数えると、<b>その文字を含むファイルでだけ行番号が静かにずれる</b> ——
    /// 名指しされた行を開いても目的のコードが無い、という読み手が直しようのない状態になる。
    /// </remarks>
    /// <param name="source">分けるソース全体。</param>
    /// <returns>行の一覧(0 始まりの <c>LineNumber</c> を持つ)。</returns>
    public static IReadOnlyList<string> SplitLines(string source) =>
        // 行の範囲から中身を切り出して返す
        SourceLines(source).Select(line => source.Substring(line.Span.Start, line.Span.Length)).ToList();

    /// <summary>行の区切りを解析器と同じ規則で求める。</summary>
    /// <param name="source">分けるソース全体。</param>
    /// <returns>行の範囲の一覧。</returns>
    private static IReadOnlyList<TextLine> SourceLines(string source) =>
        // 解析器が使うテキスト表現に行分割を任せる
        SourceText.From(source).Lines.ToList();

    /// <summary>
    /// ソースの中のコメントの範囲に印を付ける(<c>#if</c> で無効化された領域の中もたどる)。
    /// </summary>
    /// <remarks>
    /// <para><b>無効化された領域の中も見るのが要点。</b> 解析器は
    /// <c>#if DEBUG</c> … <c>#endif</c> のうち<b>成立しない側</b>を丸ごと
    /// <c>DisabledTextTrivia</c> として扱い、その中の <c>//</c> をコメントとして分類しない。
    /// 印を付けずに実コードとして残すと、<b>§5 が求める日本語コメントがそのまま
    /// 「キャッシュ指示の直接の書き込み」として報告される</b> ——しかも書いた人にできるのは
    /// 「規約が求めるコメントを消す」ことだけで、<b>直しようの無い指示</b>になる(実測)。</para>
    ///
    /// <para><b>解析の記号を決め打ちしない。</b> 「どの記号が定義されているか」を渡す形にすると、
    /// 成立する側が入れ替わるだけで<b>反対側の領域が同じ穴になる</b>。どちらの側であっても
    /// コメントはコメントなので、無効化された領域を<b>もう一度ソースとして読み直す</b>。</para>
    /// </remarks>
    /// <param name="source">走査する範囲のソース。</param>
    /// <param name="offset">この範囲が元のソースの何文字目から始まるか。</param>
    /// <param name="isComment">印を書き込む配列(元のソースの長さ)。</param>
    private static void MarkComments(string source, int offset, bool[] isComment)
    {
        // C# として解析する(壊れたソースでもエラーノード付きの木が返る)
        var tree = CSharpSyntaxTree.ParseText(source);

        // 木の中のトリビア(空白・コメント・プリプロセッサ)を、入れ子も含めてすべて見る
        foreach (var trivia in tree.GetRoot().DescendantTrivia(descendIntoTrivia: true))
        {
            // #if で無効化された領域は、その中をもう一度ソースとして読み直す
            if (trivia.IsKind(SyntaxKind.DisabledTextTrivia))
            {
                // 無効化された領域の中身
                var disabled = trivia.ToFullString();
                // 中身が無ければたどるものは無い(空の領域で再帰が止まらないのを防ぐ)
                if (disabled.Length == 0) continue;
                // 元のソースの中での開始位置をずらしてたどる
                MarkComments(disabled, offset + trivia.SpanStart, isComment);
                // この領域の処理は済んだ
                continue;
            }

            // コメント以外のトリビア(空白・改行・プリプロセッサ指令)は実コード側に残す
            if (!IsComment(trivia.Kind())) continue;

            // そのコメントが占める範囲
            var span = trivia.Span;

            // 範囲の文字に「コメント」の印を付ける(元のソースでの位置へずらす)
            for (var i = span.Start + offset; i < span.End + offset && i < isComment.Length; i++)
            {
                // この 1 文字はコメントなので実コードから外す
                isComment[i] = true;
            }
        }
    }

    /// <summary>そのトリビアが<b>コメント</b>かどうかを返す。</summary>
    /// <remarks>
    /// <b>プリプロセッサで無効化された領域そのものはコメントに数えない。</b>
    /// そこに書かれた指示は条件次第で有効になりうるので、実コードとして残す
    /// ——取りこぼす側ではなく<b>多く報告する側</b>へ倒す(この走査はもともと過剰報告を
    /// 織り込んでおり、見逃しだけが織り込めない)。ただし<b>その中のコメントは
    /// コメントとして扱う</b>(<see cref="MarkComments"/> が読み直す)。
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
