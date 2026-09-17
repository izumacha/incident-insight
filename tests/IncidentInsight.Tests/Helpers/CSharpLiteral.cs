// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// C# のソースを走査する検査が共有する、<b>文字リテラル</b>（<c>'…'</c>）の読み取り。
/// </summary>
/// <remarks>
/// <para><b>なぜ共有するのか。</b> 「アポストロフィから閉じのアポストロフィまでを、
/// <c>\</c> のエスケープを踏まえて読む」処理を必要とする検査が 2 つある
/// （ビューの引数を解析する <c>Views.ModelStateKeyPrefixMatchTests</c> と、
/// キャッシュ指示の直接書き込みを探す <c>Middleware.ResponseCacheAttributePolicyTests</c>）。
/// 書き写すと、<b>エスケープの扱いを直したときに片方だけが直る</b> ——
/// この repo が <c>RepositoryPaths</c> ・ <c>AuditedEntities</c> で繰り返し記録している形
/// （CLAUDE.md §6 DRY）。</para>
///
/// <para><b>2 つの利用側で違うのは「長さの上限」だけ</b>なので、そこを引数にして
/// 本体を 1 つにしてある。上限が要るのは Razor のビューを読む側で、
/// 地の文のアポストロフィ（<c>It's</c> ・ <c>It's Bob's</c>）を文字リテラルと
/// 読み違えないための歯止めになる。C# のソースの引数リストを読む側にその心配は無いので
/// <see cref="NoInnerLengthLimit"/> を渡す。</para>
/// </remarks>
public static class CSharpLiteral
{
    /// <summary>長さで縛らないことを表す上限（C# のソースを読む側が使う）。</summary>
    public const int NoInnerLengthLimit = int.MaxValue;

    /// <summary>
    /// C# の文字リテラルが書ける最大の中身の長さ（<c>'\uFFFF'</c> の 6 文字ぶん）に
    /// 少し余裕を持たせた上限。
    /// </summary>
    /// <remarks>
    /// これを超える「引用符から引用符まで」は文字リテラルではありえないので、
    /// マークアップの地の文にアポストロフィが 2 つある形（<c>It's Bob's</c>）を
    /// リテラルと読み違えないための歯止めになる。
    /// </remarks>
    public const int MaxCharLiteralInnerLength = 8;

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
