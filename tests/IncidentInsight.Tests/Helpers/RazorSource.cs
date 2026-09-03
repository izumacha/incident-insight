// Razor のコメントと foreach の対象を取り出すのに正規表現・文字列走査を使う
using System.Text.RegularExpressions;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// Razor のソースを「コントローラの結論を表示側が実際に使っているか」という観点で
/// 走査するときの共通部品。
/// </summary>
/// <remarks>
/// <para><b>なぜ共有するのか。</b> この repo には「コントローラが決めた選択肢を
/// ビューが本当に回しているか」を Razor のソースから確かめる検査が複数ある
/// (一覧の絞り込み: <c>Controllers.UnlistedFilterValuePolicyTests</c> /
/// 登録・編集フォームの発生部署: <c>Controllers.UnlistedDepartmentSavePolicyTests</c>)。
/// どちらも同じ 3 つの部品を必要とする ——コメントを落とす・<c>foreach</c> が回している
/// 対象を取り出す・名前を<b>識別子として</b>照合する。2 つ目の利用側が出た時点で
/// 共通化する(§6 の「2〜3 箇所目で共通化」)。</para>
///
/// <para><b>ここに置くのは「複数の検査が使う部品」だけ。</b> 1 か所しか使わない走査
/// (<c>@if</c> の本体を切り出す・ループ本体を取り出す・HTML 属性の値を集める など)は
/// 使う側のテストクラスに private のまま残してある ——将来を見越して先回りで集めると、
/// 実在しない事情のために部品が増える(§6 の「過度な抽象化を避ける」)。
/// <b>3 つ目の利用側が同じものを必要としたときに、そのとき移すこと。</b></para>
///
/// <para><b>走査を正規表現の一発勝負にしない理由</b>(取り違えると検査が黙って無力化される、
/// 括弧やコメントの扱いで実際に空振りした実測がある)は、各メソッドの解説に書いてある。</para>
/// </remarks>
public static class RazorSource
{
    /// <summary>
    /// Razor のコメント(<c>@* ... *@</c>)。改行をまたぐので <c>Singleline</c> を付ける。
    /// 入れ子は Razor 側が許さないので最短一致で足りる。
    /// </summary>
    /// <remarks>
    /// 検査の前にコメントを落とすのは、コメントで検査を満たしたり破ったりできないようにするため。
    /// 実測では、対象ブロックに <c>@* TODO: Model.XxxOptions へ移行 *@</c> と書くだけで
    /// 「必要な文字列を含むか」の検査を満たせた。
    /// </remarks>
    public static readonly Regex Comment =
        new(@"@\*.*?\*@", RegexOptions.Singleline | RegexOptions.Compiled);

    /// <summary>
    /// Razor のコメントを取り除いたソースを返す。
    /// </summary>
    /// <param name="source">Razor ファイルの中身(またはその一部)。</param>
    /// <returns>コメントを空文字へ置き換えたソース。</returns>
    public static string StripComments(string source) => Comment.Replace(source, string.Empty);

    /// <summary>
    /// <paramref name="text"/> が <paramref name="identifier"/> を<b>識別子として</b>含むか。
    /// </summary>
    /// <remarks>
    /// 素の部分文字列検査だと、期待する名前が別の名前の<b>前置詞</b>のときに素通りする
    /// (<c>Model.Department</c> は <c>Model.DepartmentOptions</c> に含まれる)。
    /// 直後が識別子を構成する文字(英数字・アンダースコア)なら別の名前とみなす。
    /// 直前は見ない —— <c>Model.Department</c> のように区切り文字込みで指定するため。
    /// </remarks>
    /// <param name="text">走査する文字列。</param>
    /// <param name="identifier">探す名前(区切り文字込みで指定してよい)。</param>
    /// <returns>識別子として含まれていれば <c>true</c>。</returns>
    public static bool ContainsIdentifier(string text, string identifier)
    {
        // 出現位置を順に調べる
        for (var i = text.IndexOf(identifier, StringComparison.Ordinal); i >= 0;
             i = text.IndexOf(identifier, i + 1, StringComparison.Ordinal))
        {
            // 一致部分の直後の位置
            var after = i + identifier.Length;
            // 末尾で終わっているか、直後が識別子の文字でなければ「その名前」だと判断する
            if (after >= text.Length || (!char.IsLetterOrDigit(text[after]) && text[after] != '_'))
                return true;
        }
        // どの出現も別の名前の一部だった
        return false;
    }

    /// <summary>
    /// ブロック内の <b>すべての</b> <c>foreach (var d in &lt;ここ&gt;)</c> について
    /// 「ここ」(＝回している対象の式)を取り出す。
    /// </summary>
    /// <remarks>
    /// <para>括弧を数えて閉じ位置を探すのは、対象の式が括弧を含みうるため。
    /// 実際 <c>/PreventiveMeasures</c> は <c>(List&lt;string&gt;)ViewBag.Xxx</c> とキャストしており、
    /// 「最初の <c>)</c> まで」を取る正規表現ではキャストの閉じ括弧で切れて
    /// <c>"(List&lt;string&gt;"</c> だけが取れてしまう(実測で落ちた)。
    /// 検出網が対象を取り違えると、判定はいつも同じ答えになり黙って無力化される。</para>
    ///
    /// <para>ブロック内の <c>foreach</c> をすべて拾う。1 つ目だけを見ると、あとから
    /// <c>&lt;optgroup&gt;</c> のグルーピング等で 2 つ目のループが足されたときに見えなくなる
    /// (この repo は原因分類のドロップダウンで実際に入れ子の構造を使っている)。</para>
    ///
    /// <para><b>解析できないループは黙って読み飛ばす</b>ので、呼び出し側は
    /// 取り出せた数とブロック内の <c>foreach</c> の数が一致することを必ず確かめること
    /// ——ずれたまま使うと「出所の検査だけが素通りする」fail-open になる。</para>
    /// </remarks>
    /// <param name="block">走査する Razor のブロック(コメントは落としてから渡す)。</param>
    /// <returns>各 <c>foreach</c> が回している対象の式。</returns>
    public static List<string> ExtractForeachSources(string block)
    {
        // 見つかった対象の式をためる
        var sources = new List<string>();
        // 走査の開始位置
        var cursor = 0;

        while (true)
        {
            // 次の foreach キーワードを探す。CountForeach と<b>同じ語境界つきの照合</b>を使う
            // ——素の部分文字列検索にすると、走査対象に foreach を含む識別子
            // (class="js-foreach-host" など)があったときにこちらだけが 1 件多く数え、
            // しかもその位置から次の括弧を拾って重複した対象を返す。
            // 呼び出し側は両者の件数一致を fail-closed の門番にしているので、
            // 数え方がずれると「解析できないループがある」という<b>実在しない問題</b>で落ちる
            var match = ForeachKeyword.Match(block, cursor);
            // 無ければ走査を終える
            if (!match.Success) break;
            var keyword = match.Index;
            // 次の周回はこのキーワードの先から探す(見つからない形でも無限ループにしない)
            cursor = keyword + match.Length;

            // その直後の開き括弧を探す
            var open = block.IndexOf('(', keyword);
            if (open < 0) continue;

            // 入れ子を数えながら対応する閉じ括弧を探す
            var depth = 0;
            var close = -1;
            for (var i = open; i < block.Length; i++)
            {
                // 開き括弧で 1 段深くなる
                if (block[i] == '(') depth++;
                // 閉じ括弧で 1 段浅くなる
                else if (block[i] == ')')
                {
                    depth--;
                    // 深さが 0 に戻った位置が対応する閉じ括弧
                    if (depth == 0) { close = i; break; }
                }
            }
            // 閉じ括弧が見つからなければこの 1 件は解析できない
            if (close < 0) continue;

            // 括弧の中身から「 in 」の後ろを取り出す(前後の空白は落とす)
            var inside = block[(open + 1)..close];
            var inKeyword = inside.IndexOf(" in ", StringComparison.Ordinal);
            if (inKeyword < 0) continue;
            sources.Add(inside[(inKeyword + 4)..].Trim());
        }

        // 見つかったすべての対象を返す
        return sources;
    }

    /// <summary>
    /// ブロック内の <c>foreach</c> キーワードの数を数える。
    /// </summary>
    /// <remarks>
    /// <see cref="ExtractForeachSources"/> が取り出せた数との照合に使う。
    /// 解析できない書き方のループが現れたら、呼び出し側はここで落として
    /// 「書き方」と「解析」のどちらを直すか人に決めさせること。
    /// </remarks>
    /// <param name="block">走査する Razor のブロック(コメントは落としてから渡す)。</param>
    /// <returns>ブロック内の <c>foreach</c> の数。</returns>
    public static int CountForeach(string block) => ForeachKeyword.Matches(block).Count;

    /// <summary>
    /// <c>foreach</c> キーワード。語境界つきで照合する(<c>js-foreach-host</c> のような
    /// 識別子の一部に当たらないようにするため)。
    /// </summary>
    /// <remarks>
    /// <b>数える側と取り出す側で同じものを使う。</b> 呼び出し側は
    /// <see cref="CountForeach"/> と <see cref="ExtractForeachSources"/> の件数一致を
    /// fail-closed の門番にしているので、照合の仕方が分かれると実在しない解析エラーで落ちる。
    /// </remarks>
    private static readonly Regex ForeachKeyword =
        new(@"\bforeach\b", RegexOptions.Compiled);
}
