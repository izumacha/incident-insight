// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// C# のソースを走査する検査が共有する、リテラル（<c>'…'</c> ・ <c>"…"</c>）の読み取り。
/// </summary>
/// <remarks>
/// <para><b>なぜ共有するのか。</b> 「アポストロフィから閉じのアポストロフィまでを、
/// <c>\</c> のエスケープを踏まえて読む」処理を必要とする検査が 2 つある
/// （ビューの中の呼び出しの引数を解析する <c>Views.ModelStateKeyPrefixMatchTests</c> と、
/// キャッシュ指示の直接書き込みを探す <c>Middleware.ResponseCacheAttributePolicyTests</c>。
/// <b>どちらも <c>.cshtml</c> を読む</b> ——「片方は C# のソースだけを読むので
/// 地の文のアポストロフィの心配が無い」というのは誤りなので、そう書かないこと）。
/// 書き写すと、<b>エスケープの扱いを直したときに片方だけが直る</b> ——
/// この repo が <c>RepositoryPaths</c> ・ <c>AuditedEntities</c> で繰り返し記録している形
/// （CLAUDE.md §6 DRY）。</para>
///
/// <para><b>「中身の長さで縛る」引数は置かない。</b> 一度そうしかけたが誤りだった:
/// Razor のビューでは <c>'</c> が属性の引用符にもなるので、
/// <c>src='https://cdn.example.com/x.js'</c> のような長い値がリテラルとして読めなくなり、
/// 中の <c>//</c> が行コメントの開始と解釈されて<b>その行の残りが走査から丸ごと落ちた</b>
/// （実測。キャッシュ指示の書き込みが同じ行にあると見逃す＝fail-open）。
/// 地の文のアポストロフィを別扱いするのに必要なのは長さではなく
/// <b>直前の文字と「その行の中で閉じているか」</b>で、それは利用側が判断する。
/// どちらの利用側も使わない引数を「将来のために」残さない（§6）。</para>
/// </remarks>
public static class CSharpLiteral
{
    /// <summary>
    /// 単一引用符の位置から、<b>閉じ引用符の位置</b>を返す（見つからなければ <c>-1</c>）。
    /// </summary>
    /// <remarks>
    /// <c>'\''</c> のようなエスケープを考慮する。文字リテラルは改行をまたげないので、
    /// 改行に出会ったら誤検出として打ち切る。
    /// </remarks>
    /// <param name="source">走査するソース。</param>
    /// <param name="quoteIndex">開きの単一引用符の位置。</param>
    /// <returns>閉じ引用符の位置。読めなければ <c>-1</c>。</returns>
    public static int FindCharLiteralEnd(string source, int quoteIndex)
    {
        // 開き引用符の次の文字から探し始める
        for (var i = quoteIndex + 1; i < source.Length; i++)
        {
            // エスケープなら次の 1 文字を読み飛ばす
            if (source[i] == '\\') { i++; continue; }
            // 単一引用符に出会ったらそこが閉じ位置
            if (source[i] == '\'') return i;
            // 文字リテラルは改行をまたがないので、改行に出会ったら誤検出として打ち切る
            if (source[i] == '\n') return -1;
        }

        // 閉じ引用符が見つからなかった
        return -1;
    }

    /// <summary>
    /// 生文字列リテラルの開始と見なす、引用符の連なりの最小の長さ。
    /// </summary>
    public const int RawStringFenceLength = 3;

    /// <summary>
    /// その引用符が<b>逐語的リテラル</b>（<c>@"</c> ・ <c>@$"</c> ・ <c>$@"</c>）の開きかを返す。
    /// </summary>
    /// <remarks>
    /// 直前の接頭辞を<b>遡って</b>見る。<c>@"</c> だけでなく <c>@$"</c> / <c>$@"</c> もあり、
    /// 直前 1 文字だけ見る版は <c>@$"</c> を取り違えてバックスラッシュをエスケープ扱いし、
    /// <b>末尾のバックスラッシュで閉じ引用符を飲み込んで暴走した</b>。
    /// </remarks>
    /// <param name="source">走査するソース。</param>
    /// <param name="quoteIndex">開きの二重引用符の位置。</param>
    /// <returns>逐語的リテラルの開きなら <c>true</c>。</returns>
    public static bool IsVerbatim(string source, int quoteIndex)
    {
        // 接頭辞（@ と $ の並び）を遡って見る
        for (var k = quoteIndex - 1; k >= 0 && (source[k] == '@' || source[k] == '$'); k--)
            // @ が含まれていれば逐語的リテラル
            if (source[k] == '@') return true;

        // 接頭辞に @ が無いので逐語的ではない
        return false;
    }

    /// <summary>
    /// その位置から続く二重引用符の<b>連なりの長さ</b>を返す。
    /// </summary>
    /// <remarks>
    /// <b>「フェンスかどうか」の規則を 1 か所に置くために公開している。</b>
    /// 行単位で読む利用側は「閉じなかったときにどう振る舞うか」を自分で決める必要があり
    /// （複数行にまたがる生文字列は、1 行しか見ていなければ必ず閉じないため）、
    /// その判断に連なりの長さが要る。ここを持たないと、利用側が数え直す写しを持つことになる。
    /// </remarks>
    /// <param name="source">走査するソース。</param>
    /// <param name="index">数え始める位置。</param>
    /// <returns>その位置から続く二重引用符の数（その位置が引用符でなければ 0）。</returns>
    public static int QuoteRunLength(string source, int index)
    {
        // 連なりの長さを数える
        var length = 0;
        // 引用符が続くあいだ進める
        while (index + length < source.Length && source[index + length] == '"') length++;
        // 数えた長さを返す
        return length;
    }

    /// <summary>
    /// 二重引用符の位置から、<b>閉じ引用符の位置</b>を返す（読めなければ <c>-1</c>）。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ共有するのか（実測した取り違え 2 件）。</b> この処理はかつて 2 か所に
    /// 別々の実装で存在し、片方だけが次の 2 つを扱えていた ——そして前者のコメントは、
    /// <b>その 2 つがまさに過去に踏んだ不具合である</b>と明記していた。
    /// <list type="bullet">
    ///   <item><c>@$"…"</c> / <c>$@"…"</c> … 直前 1 文字だけを見る版はこれを逐語的リテラルと
    ///     判定できず、バックスラッシュをエスケープ扱いして<b>末尾のバックスラッシュで
    ///     閉じ引用符を飲み込み、走査が暴走した</b>。その先の <c>@* … *@</c>（§5 が求める
    ///     Razor コメント）まで飲み込まれ、<b>規約どおりのコメントが違反として報告されうる</b>。</item>
    ///   <item>生文字列 <c>"""…"""</c> … 扱えない版は開始フェンスを「空のリテラル＋余った
    ///     引用符」と読むため、本文の行が<b>実コードとして走査に載り</b>、存在しない違反を報告する。</item>
    /// </list>
    /// どちらも<b>正しいコードで赤くなる</b>側の壊れ方で、そういう検出網はいずれ緩められる。
    /// 写しを持つ限り「片方だけが直っている」状態が戻るので、1 か所に置く（CLAUDE.md §6 DRY）。</para>
    ///
    /// <para>扱うのは C# の 3 つの書き方。
    /// <list type="bullet">
    ///   <item>通常の <c>"…"</c> … バックスラッシュがエスケープになる。</item>
    ///   <item>逐語的 <c>@"…"</c> … バックスラッシュはエスケープ<b>ではなく</b>、
    ///     引用符を重ねた <c>""</c> が引用符 1 つを表す。</item>
    ///   <item>生文字列 <c>"""…"""</c> … 開始と同じ数の引用符が終端になる。</item>
    /// </list></para>
    ///
    /// <para><b>補間文字列の穴（<c>$"…{式}…"</c> の <c>{式}</c>）は追わない。</b>
    /// 穴の中にさらに文字列が入る形まで見るには専用の走査が要る。必要な利用側は
    /// 自分でそこへ回す（呼ぶ前に補間の開始かを判定する）。ここは
    /// <b>「増やしたことに気付く」ための網であって証明ではない</b> ——
    /// これ以上の穴が出たら、綴りを 1 つずつ塞ぐのではなく本物のパーサへ移すこと。</para>
    /// </remarks>
    /// <param name="source">走査するソース（行単位で呼んでもよい）。</param>
    /// <param name="quoteIndex">開きの二重引用符の位置。</param>
    /// <returns>閉じ引用符の位置。閉じないまま終端に達すれば <c>-1</c>。</returns>
    public static int FindStringLiteralEnd(string source, int quoteIndex)
    {
        // 逐語的リテラルかどうかは 1 か所の規則で判定する（規則は IsVerbatim が持つ）
        var isVerbatim = IsVerbatim(source, quoteIndex);

        // 引用符が 3 つ以上続いていれば生文字列リテラル。ただし逐語的リテラルの
        // @"""..." は「引用符を重ねて 1 つを表す」書き方なので生文字列とは別物——
        // 先に逐語的かを見てから判定しないと、終端の意味を取り違えて暴走する
        var fenceLength = QuoteRunLength(source, quoteIndex);
        if (!isVerbatim && fenceLength >= RawStringFenceLength)
        {
            // 開始と同じ数の引用符が並ぶ位置が終端になる
            var fence = new string('"', fenceLength);
            // 開始フェンスの直後から終端フェンスを探す
            var close = source.IndexOf(fence, quoteIndex + fenceLength, StringComparison.Ordinal);
            // 見つからなければ読み取り不能、見つかればフェンス末尾の位置を返す
            return close < 0 ? -1 : close + fenceLength - 1;
        }

        // 改行をまたげるのは逐語的リテラルだけ（生文字列は上で処理済み）
        var canSpanLines = isVerbatim;

        // 開き引用符の次の文字から探し始める
        for (var i = quoteIndex + 1; i < source.Length; i++)
        {
            // 通常のリテラルだけバックスラッシュをエスケープとして扱う
            if (!isVerbatim && source[i] == '\\') { i++; continue; }
            // <b>ふつうの "…" は改行をまたげないので、改行に出会ったら誤検出として打ち切る。</b>
            // 姉妹の FindCharLiteralEnd が同じ理由で同じことをしている ——打ち切らないと、
            // 位置がずれた走査が<b>次の行以降の引用符</b>を終端として拾い、あいだの実コードが
            // 丸ごとリテラルの中身として潰される（ModelState 側は潰した範囲を空白で埋めるので、
            // そこにある StartsWith( の検査漏れが報告されなくなる＝静かな fail-open）
            if (!canSpanLines && source[i] == '\n') return -1;
            // 引用符に出会った場合の扱いはリテラルの種類で違う
            if (source[i] == '"')
            {
                // 逐語的リテラルでは "" が引用符 1 つを表すので、2 つ続くなら本文の一部
                if (isVerbatim && i + 1 < source.Length && source[i + 1] == '"') { i++; continue; }
                // それ以外はここが閉じ位置
                return i;
            }
        }

        // 閉じ引用符が見つからなかった
        return -1;
    }
}
