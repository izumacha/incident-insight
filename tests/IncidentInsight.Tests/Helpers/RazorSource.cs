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
            var keyword = NextForeachKeyword(block, cursor);
            // 無ければ走査を終える
            if (keyword < 0) break;
            // 次の周回はこのキーワードの先から探す(見つからない形でも無限ループにしない)
            cursor = keyword + ForeachKeywordLength;

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
    /// <paramref name="startAt"/> 以降にある次の <c>foreach</c> キーワードの位置を返す。
    /// 無ければ <c>-1</c>。
    /// </summary>
    /// <remarks>
    /// <b>foreach を探す処理はすべてここを通すこと。</b> 素の部分文字列検索を各所で書くと、
    /// <see cref="CountForeach"/> の語境界つきの照合とずれる ——走査対象に
    /// <c>class="js-foreach-host"</c> のような識別子があるだけで件数が食い違い、
    /// 呼び出し側の「解析できた数と foreach の数が一致するか」という門番が
    /// <b>実在しない解析エラー</b>で落ちる(正しいマークアップを咎める検出網は、いずれ緩められる)。
    /// </remarks>
    /// <param name="block">走査する Razor のブロック(コメントは落としてから渡す)。</param>
    /// <param name="startAt">探し始める位置。</param>
    /// <returns>見つかった位置。無ければ <c>-1</c>。</returns>
    public static int NextForeachKeyword(string block, int startAt)
    {
        // 語境界つきで次の 1 件を探す(数える側とまったく同じ照合)
        var match = ForeachKeyword.Match(block, startAt);
        // 見つからなければ -1 を返す
        return match.Success ? match.Index : -1;
    }

    /// <summary>
    /// <c>foreach</c> キーワードの文字数。走査位置を進めるときに使う。
    /// </summary>
    /// <remarks>
    /// <b>裸の数値を書かず綴りから導く。</b> 走査は
    /// 「<see cref="NextForeachKeyword"/> が返した位置 ＋ この長さ」で次の周回へ進むので、
    /// 正規表現が探す綴りとこの値は必ず対で正しい必要がある。書き写すと、
    /// 進む幅が綴りより短くなったときに<b>同じ位置を何度も見つけて</b>同じループを
    /// 積み続け、呼び出し側の門番が「foreach N 件のうち M 件しか解析できていない」
    /// (M &gt; N)という意味の通らない診断で落ちる ——直す人はビューを疑ってこの定数へは
    /// たどり着けない。0 なら無限ループになる(§6 マジックナンバーを避ける)。
    /// </remarks>
    public static readonly int ForeachKeywordLength = ForeachKeywordText.Length;

    /// <summary>
    /// <c>foreach</c> <b>文</b>の開始。キーワードに続く開き括弧まで見て照合する。
    /// </summary>
    /// <remarks>
    /// <para><b>語境界(<c>\bforeach\b</c>)だけでは足りない(実測)。</b> 正規表現の語境界は
    /// ハイフンを単語の区切りとみなすため、<c>class="js-foreach-host"</c> のような
    /// <b>正しいマークアップ</b>の中の <c>foreach</c> に当たってしまう。実際に
    /// <c>&lt;select name="department" class="js-foreach-host"&gt;</c> を置くと
    /// 件数が 1 対 2 に食い違い、呼び出し側の門番が
    /// 「本体を取り出せていない」という<b>実在しない問題</b>で落ちた。
    /// 正しいコードを咎める検出網はいずれ緩められるので、精度側に寄せる。</para>
    ///
    /// <para>実際に数えたいのは <c>foreach</c> <b>文</b>なので、C# の構文どおり
    /// 「キーワードの直後に(空白を挟んで)開き括弧が来る」ことまで要求する。
    /// 属性値やクラス名の中の <c>foreach</c> には括弧が続かないため当たらない。</para>
    ///
    /// <para><b>数える側と取り出す側で同じものを使う。</b> 呼び出し側は
    /// <see cref="CountForeach"/> と <see cref="ExtractForeachSources"/> の件数一致を
    /// fail-closed の門番にしているので、照合の仕方が分かれると実在しない解析エラーで落ちる。</para>
    /// </remarks>
    private static readonly Regex ForeachKeyword =
        new($@"\b{ForeachKeywordText}\s*\(", RegexOptions.Compiled);

    /// <summary>
    /// <c>foreach</c> キーワードの綴り。正規表現と <see cref="ForeachKeywordLength"/> の
    /// <b>唯一の出所</b>。
    /// </summary>
    private const string ForeachKeywordText = "foreach";

    /// <summary>
    /// ビューのソースから、目印の開始タグで始まる <c>&lt;select&gt;</c> ブロックを
    /// (Razor のコメントを落として)取り出す。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ共有するのか。</b> 「コントローラが決めた選択肢をビューが本当に
    /// 回しているか」を確かめる検査は、どれも<b>その画面の 1 つの
    /// <c>&lt;select&gt;</c> ブロックだけ</b>を対象にする ——静的な一覧の参照自体は
    /// 登録・編集フォームの別の箇所では正しい書き方なので、一律に禁じると
    /// 正しいコードを咎める検出網になる。切り出し方は 3 つの検査で同一
    /// (一覧の絞り込み・登録/編集フォームの発生部署・一覧の並び順)で、
    /// 違うのは<b>開始タグの目印だけ</b>だった。写しのままにすると、
    /// 切り出しの規則を直したとき(たとえば属性を単一引用符でも書けるようにする)に
    /// 覚えている写しだけが直り、残りが黙って対象を狭める。</para>
    ///
    /// <para><b>見つからなければ fail-closed で落とす。</b>「見るべきブロックが無い＝緑」に
    /// すると、目印を変えただけで検出網が黙って死ぬ。</para>
    /// </remarks>
    /// <param name="source">ビューの Razor ソース全体。</param>
    /// <param name="startMarker">開始タグの目印(例: <c>&lt;select name="sortBy"</c>)。</param>
    /// <param name="viewLabel">失敗メッセージに出すビューの呼び名(例: <c>Incidents/Index.cshtml</c>)。</param>
    /// <returns>コメントを落とした <c>&lt;select&gt;</c> ブロックの中身。</returns>
    public static string ExtractSelectBlock(string source, string startMarker, string viewLabel)
    {
        // 対象ドロップダウンの開始タグを探す
        var selectStart = source.IndexOf(startMarker, StringComparison.Ordinal);
        // 見つからなければ、ビューの構造が変わったか目印が消えている
        Assert.True(selectStart >= 0,
            $"{viewLabel} に {startMarker}\"> が見つからない。"
            + "この検査はこのブロックの中身だけを見るので、目印を変えるならこの検査も"
            + "同じ変更セットで直すこと。");
        // 対応する閉じタグまでを切り出す(select は入れ子にならないので最初の </select> でよい)
        var selectEnd = source.IndexOf("</select>", selectStart, StringComparison.Ordinal);
        Assert.True(selectEnd > selectStart,
            $"{viewLabel} の {startMarker}\"> に対応する </select> が見つからない。");

        // Razor のコメントを落として返す(コメントで検査を満たしたり破ったりできないようにする)
        return StripComments(source[selectStart..selectEnd]);
    }

}
