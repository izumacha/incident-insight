// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// C# のソースを走査する検査が共有する、<b>文字リテラル</b>（<c>'…'</c>）の読み取り。
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
/// <para><b>長さの上限は引数で受けるが、いまはどちらの利用側も
/// <see cref="NoInnerLengthLimit"/> を渡す。</b> 一度「中身が 8 文字まで」で縛る形にしたが、
/// <b>それは誤りだった</b>: Razor のビューでは <c>'</c> が属性の引用符にもなるので、
/// <c>src='https://cdn.example.com/x.js'</c> のような長い値がリテラルとして読めなくなり、
/// 中の <c>//</c> が行コメントの開始と解釈されて<b>その行の残りが走査から丸ごと落ちた</b>
/// （実測。キャッシュ指示の書き込みが同じ行にあると見逃す＝fail-open）。
/// 地の文のアポストロフィを別扱いするのに必要だったのは長さではなく
/// <b>「その行の中で閉じているか」</b>だけで、そちらは上限と無関係に効く。
/// 引数自体を残してあるのは、将来ほんとうに上限が要る利用側が出たときに
/// 判定を書き写さずに済ませるため。</para>
/// </remarks>
public static class CSharpLiteral
{
    /// <summary>長さで縛らないことを表す上限（C# のソースを読む側が使う）。</summary>
    public const int NoInnerLengthLimit = int.MaxValue;

    /// <summary>
    /// 単一引用符の位置から、<b>閉じ引用符の位置</b>を返す（見つからなければ <c>-1</c>）。
    /// </summary>
    /// <remarks>
    /// <c>'\''</c> のようなエスケープを考慮する。文字リテラルは改行をまたげないので、
    /// 改行に出会ったら誤検出として打ち切る。
    /// </remarks>
    /// <param name="source">走査するソース。</param>
    /// <param name="quoteIndex">開きの単一引用符の位置。</param>
    /// <param name="maxInnerLength">
    /// 中身として許す最大の長さ。これを超えたら「文字リテラルではない」として <c>-1</c> を返す。
    /// 縛らない場合は <see cref="NoInnerLengthLimit"/> を渡す。
    /// </param>
    /// <returns>閉じ引用符の位置。読めなければ <c>-1</c>。</returns>
    public static int FindCharLiteralEnd(string source, int quoteIndex, int maxInnerLength)
    {
        // 開き引用符の次の文字から探し始める
        for (var i = quoteIndex + 1; i < source.Length; i++)
        {
            // 中身がここまでに何文字あったか（開きの次から数えた長さ）
            if (i - quoteIndex - 1 > maxInnerLength) return -1;
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
}
