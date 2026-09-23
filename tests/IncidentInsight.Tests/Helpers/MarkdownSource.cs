// 文書を読むために使う
using System.IO;

// テストの共有ヘルパー置き場
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// <c>docs/</c> 配下の Markdown を読むテストが共有する、<b>近似の走査</b>。
/// </summary>
/// <remarks>
/// <b>なぜ 1 か所に集めるのか（レビュー指摘）。</b> この repo は既に
/// <c>CSharpCommentScanner</c> ・ <c>RazorSource</c> ・ <c>ModelStateKeyPrefixMatchTests.Neutralize</c> と
/// 似た近似の走査を抱えており、CLAUDE.md は「近似である限り穴は必ず残るので、
/// 共有できる場所へ置け」と記録している。テストクラスの private に置くと、
/// 次に Markdown を読むテストが<b>写しを作り、穴を直す前に複製する</b>。
///
/// <para><b>ここに置くのは「Markdown の形」だけ</b>で、何を探すかは利用側に残す
/// （§6「単一責務」。キャッシュ指示の綴りはこのクラスの関心ではない）。</para>
/// </remarks>
internal static class MarkdownSource
{
    /// <summary>コードブロックの囲いを始める最小の綴り。</summary>
    private const string CodeFence = "```";

    /// <summary>Markdown を読み、改行を LF へそろえて返す。</summary>
    /// <remarks>
    /// <b>読み口を共有するのが要点（レビュー指摘）。</b> パスだけを共有して
    /// 読み方を各自で書くと、正規化を足した側だけが直り、もう片方は
    /// <b>Windows のチェックアウトでだけ壊れる</b>状態が黙って残る。
    /// この repo に <c>.gitattributes</c> は無いので、Windows の既定では CRLF になる。
    /// </remarks>
    /// <param name="path">読むファイルのパス。</param>
    /// <returns>改行を LF へそろえた文書全体。</returns>
    internal static string Read(string path) =>
        // 読んでから改行をそろえる
        File.ReadAllText(path).Replace("\r\n", "\n");

    /// <summary>その位置を含む行の先頭位置を返す。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">含めたい位置。</param>
    /// <returns>行の先頭位置。</returns>
    internal static int LineStart(string doc, int index) =>
        // <b>先頭はそのまま 0 を返す（レビュー指摘）。</b> 以前は 0 へ丸めてから探していたため、
        // 改行で始まる文書の先頭を聞くと<b>問い合わせた位置より後ろ</b>の 1 を返し、
        // 囲みの数え上げや箇条書きの遡りが黙って別の行を見る
        index <= 0 ? 0 : doc.LastIndexOf('\n', index - 1) + 1;

    /// <summary>その位置がコードの囲み（バッククォート）の中かを見る。</summary>
    /// <remarks>
    /// 囲みは 1 行の中で閉じるので、<b>行頭からその位置までのバッククォートの個数が
    /// 奇数なら中、偶数なら外</b>と数えれば足りる。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">見たい位置。</param>
    /// <returns>囲みの中なら <c>true</c>。</returns>
    internal static bool IsInsideCodeSpan(string doc, int index)
    {
        // その位置を含む行の先頭
        var lineStart = LineStart(doc, index);

        // 行頭からその位置までのバッククォートを数える
        var backticks = 0;
        // 1 文字ずつ見る
        for (var at = lineStart; at < index; at++)
        {
            // バッククォートなら 1 つ数える
            if (doc[at] == '`') backticks++;
        }

        // 奇数なら囲みの中にいる
        return backticks % 2 == 1;
    }

    /// <summary>その位置がコードブロック（``` で囲んだ領域）の中かを見る。</summary>
    /// <remarks>
    /// <b>囲いは「行の頭」にあるものだけを数える（レビュー指摘）。</b>
    /// 文書中のどこに現れた ``` も数える形だと、<b>地の文で綴りに言及しただけで
    /// 個数の偶奇が反転し、それ以降の文書全体が「ブロックの中」になる</b>
    /// ——利用側がブロックを逃す実装だと、それ以降の検査が丸ごと黙る（実測）。
    /// 囲いの数が奇数（閉じていない）かどうかは <see cref="FencesAreBalanced"/> で別に見る。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">見たい位置。</param>
    /// <returns>コードブロックの中なら <c>true</c>。</returns>
    internal static bool IsInsideFencedBlock(string doc, int index) =>
        // その位置より前の囲いの行が奇数なら、まだ閉じていない
        CountFenceLines(doc, index) % 2 == 1;

    /// <summary>文書全体で、コードブロックの囲いが閉じているかを見る。</summary>
    /// <remarks>
    /// 囲いの数が奇数の文書は、末尾まで「ブロックの中」になる。
    /// 読み手がブロックを逃す実装だと<b>黙って検査が外れる</b>ので、
    /// 利用側はこれを fail-closed で見ること。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <returns>閉じていれば <c>true</c>。</returns>
    internal static bool FencesAreBalanced(string doc) =>
        // 文書の末尾まで数えて偶数か
        CountFenceLines(doc, doc.Length) % 2 == 0;

    /// <summary>文書全体にある、囲いの行の数を返す。</summary>
    /// <remarks>
    /// 利用側の<b>空振り検出</b>のために公開している ——囲いを 1 つも見つけられないと
    /// <see cref="IsInsideFencedBlock"/> も <see cref="FencesAreBalanced"/> も、違反 0 件で
    /// <b>両方とも黙って死ぬ</b>（実測。字下げの上限を置いていた版がその状態だった）。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <returns>囲いの行の数。</returns>
    internal static int FenceLineCount(string doc) =>
        // 末尾まで数える
        CountFenceLines(doc, doc.Length);

    /// <summary>指定位置より前にある、囲いの行の数を数える。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">ここより前を数える。</param>
    /// <returns>囲いの行の数。</returns>
    private static int CountFenceLines(string doc, int index)
    {
        // これまでに見つけた囲いの行の数
        var fences = 0;

        // 文書の先頭の行から順に見る
        for (var lineStart = 0; lineStart < index; )
        {
            // その行が囲いなら 1 つ数える
            if (IsFenceLine(doc, lineStart)) fences++;

            // 次の改行を探す
            var next = doc.IndexOf('\n', lineStart);
            // 見つからなければ最後の行だったので終わり
            if (next < 0) break;

            // 次の行の先頭へ
            lineStart = next + 1;
        }

        // 数えた件数を返す
        return fences;
    }

    /// <summary>その行がコードブロックの囲いかを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="lineStart">行の先頭位置。</param>
    /// <returns>囲いの行なら <c>true</c>。</returns>
    private static bool IsFenceLine(string doc, int lineStart)
    {
        // <b>字下げの上限を置かない（レビュー指摘）。</b> CommonMark の「3 桁まで」は
        // <b>最上位の規則</b>で、番号付きリストの中の囲いはその項目の本文位置から数える。
        // docs/security.md の囲いは実際に 5 桁字下げされており、上限を置いた版では
        // <b>1 つも数えられず、ブロックを逃す処理も偶奇の検査も両方とも死んでいた</b>（実測）。
        // 本文位置を正しく数えるにはリストの入れ子を読む必要があり、
        // それはこの repo が繰り返し避けている「近似を育てる」道なので、
        // <b>行頭の空白を桁数を問わず読み飛ばす</b>（行の途中の ``` は引き続き数えない）
        var at = lineStart;
        // 行頭の空白の間だけ進む
        while (at < doc.Length && doc[at] is ' ' or '\t') at++;

        // そこから ``` で始まっているか
        return string.CompareOrdinal(doc, at, CodeFence, 0, CodeFence.Length) == 0;
    }

    /// <summary>指定位置を含む箇条書きの範囲（開始・終了の文字位置）を求める。</summary>
    /// <remarks>
    /// <b>箇条書きの境目の規則はここ 1 か所に置く。</b> 同じ規則
    /// （行頭の <c>"- "</c> で区切る）を 2 か所へ書き写すと、文書が別の記号の
    /// 箇条書きへ変わったときに片方だけが直り、もう片方は<b>無関係な範囲</b>を
    /// 見たまま静かに誤分類する（§6 DRY）。
    /// 箇条書きの外（地の文）にある位置は、その行だけを範囲として返す。
    /// </remarks>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">含めたい位置。</param>
    /// <returns>箇条書きの開始位置と、終了位置（終端は含まない）。</returns>
    internal static (int Start, int End) BulletBounds(string doc, int index)
    {
        // その位置を含む行の先頭を探す
        var lineStart = LineStart(doc, index);

        // <b>上へたどってよいのは「継続行」の間だけ。</b>
        // 条件を付けずに直前の "- " まで遡ると、<b>箇条書きの外にある地の文</b>が
        // 手前の箇条書きの一部として扱われ、「箇条書きの中にあること」の検査が
        // <b>原理的に落ちなくなる</b>（実測で、無関係な箇条書きの指示が
        // 静的アセットの名乗りとして照合され、全件緑のまま通った）。
        var start = lineStart;
        // 箇条書きの先頭に当たるまで、継続行の間だけ遡る
        while (start > 1 && !IsBulletStart(doc, start) && IsContinuationLine(doc, start))
        {
            // 1 つ前の行の先頭へ
            start = doc.LastIndexOf('\n', start - 2) + 1;
        }

        // 箇条書きの外（地の文）なら、その行だけを範囲にする。
        // <b>下へも伸ばさない（レビュー指摘）。</b> 以前は上への探索だけを止めて
        // 下へは継続行をたどっており、<b>docstring が約束した「その行だけ」と食い違っていた</b> ——
        // 約束を信じた 2 人目の利用者が、意図していない字下げのブロックまで読む
        if (!IsBulletStart(doc, start))
        {
            // その行の終わりを探す
            var proseEnd = doc.IndexOf('\n', index);

            // 行 1 本だけを範囲として返す
            return (lineStart, proseEnd < 0 ? doc.Length : proseEnd);
        }

        // 次の行から順に、箇条書きの続きでなくなるところまで進める
        var end = doc.IndexOf('\n', index);
        // 継続行の間は同じ箇条書き（次の "- " も、字下げの無い地の文もここで止まる）
        while (end >= 0 && end + 1 < doc.Length && IsContinuationLine(doc, end + 1))
        {
            // さらに次の改行へ
            end = doc.IndexOf('\n', end + 1);
        }

        // 改行が見つからなければ文書の末尾まで
        return (start, end < 0 ? doc.Length : end);
    }

    /// <summary>その行が、直前の箇条書きの続き（字下げされた行）かを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">行の先頭位置。</param>
    /// <returns>継続行なら <c>true</c>。</returns>
    internal static bool IsContinuationLine(string doc, int index) =>
        // 行頭が空白（かつ改行ではない）なら、前の行の続き
        index < doc.Length && doc[index] != '\n' && char.IsWhiteSpace(doc[index]);

    /// <summary>その位置が箇条書きの先頭（行頭の <c>"- "</c>）かを見る。</summary>
    /// <param name="doc">文書全体。</param>
    /// <param name="index">行の先頭位置。</param>
    /// <returns>箇条書きの先頭なら <c>true</c>。</returns>
    internal static bool IsBulletStart(string doc, int index) =>
        // 行頭が "- " で始まっているか
        index + 1 < doc.Length && doc[index] == '-' && doc[index + 1] == ' ';
}
