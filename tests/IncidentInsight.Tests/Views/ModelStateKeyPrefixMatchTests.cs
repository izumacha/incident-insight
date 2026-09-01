// 呼び出しの綴りを空白込みで探すために使う
using System.Text.RegularExpressions;
// リポジトリ内のパスを解決する共有ヘルパーを使う
using IncidentInsight.Tests.Helpers;

// ソース走査系の guard-rail テストが集まっている名前空間
// (ChartAccessibilityTests / ConcurrencyTokenFormTests / RoleGatedNavigationTests などと同居させる)
namespace IncidentInsight.Tests.Views;

/// <summary>
/// Guard-rail test: <b>ModelState のキーに対する前方一致は必ず序数比較で行う</b>ことを固定する。
///
/// <para><b>なぜ機械的に見張るのか。</b> 引数なしの <c>string.StartsWith</c> は現在のカルチャで
/// 比較するため、ICU が「無視できる文字」とみなす記号(ソフトハイフン U+00AD・ZWJ U+200D 等)を
/// 挟んだキーまで前方一致と判定する(実測: <c>"­CauseAnalysis.Why1"</c> は
/// <c>StartsWith("CauseAnalysis.")</c> が true、<c>StringComparison.Ordinal</c> を渡すと false)。
/// この一致は「ModelState からキーを除去する側」に効くので、意図より多くの検証エラーを捨てる
/// <b>fail-open</b> になり、しかも成立するかどうかがサーバの OS ロケールと ICU の版に左右される
/// (CLAUDE.md §10 プラットフォーム差異ゼロ設計)。</para>
///
/// <para><b>この検査が要る理由は、実際に 2 度取りこぼしたから。</b> 同じ構文はコントローラに
/// 3 箇所・Razor ビューに 2 箇所あり、序数比較へ揃える作業を 2 回行ってなお 3 箇所が残っていた。
/// 個別の振る舞いテストは「今ある呼び出し」しか押さえられず、次に増える箇所を止められない。</para>
///
/// <para><b>この検査自体が何度も素通りさせた。</b> 同じ失敗を繰り返さないよう記録しておく。
/// <list type="number">
///   <item>引数を行末まで取っていたため、1 行に 2 つ呼び出しがあると最初の一致が行の残りを
///     飲み込み、後ろの呼び出しは <c>Regex.Matches</c> の非重複規則で数えられもしなかった
///     (実測: 1 行に書き直すだけで全件緑)。→ 対応する閉じ括弧まで数えて切り出す。</item>
///   <item>引数に <c>StringComparison</c> という綴りがあれば通していたため、
///     <c>StringComparison.CurrentCulture</c> を渡す形が素通りした(実測: 全件緑)。
///     「明示したか」ではなく<b>「序数比較か」</b>を見るのが正しい。→ 許可する値を
///     <see cref="AllowedComparisons"/> に列挙して突き合わせる。</item>
///   <item>許可値を引数の文字列全体から探していたため、<b>入れ子の呼び出しが受け取る</b>
///     <c>StringComparison.Ordinal</c> を外側の呼び出しの合格根拠にしてしまった
///     (実測: <c>StartsWith(Prefix("x", StringComparison.Ordinal))</c> が素通り)。
///     → 最上位のカンマで区切り、<b>最後の引数そのもの</b>を突き合わせる。</item>
///   <item>走査対象を <c>"ModelState.Keys"</c> という綴りで選んでいたため、
///     <c>ModelState.Where(e =&gt; e.Key.StartsWith(...))</c> のようにキー集合を経由しない
///     ファイルが丸ごと対象から外れた(実測: 素通り)。しかも判定が生の本文だったので
///     <b>コメントの文言が検査範囲を決めて</b>いた。→ 目印を <c>"ModelState"</c> まで緩め、
///     コメントを潰した本文で判定する。</item>
/// </list>
/// いずれも「検査が形だけ通る条件」を見ていたのが原因で、<b>守りたい性質そのもの</b>を
/// 条件にしていなかった。<b>この検査を変えるときは、変異を 1 つ作って実際に落ちることを
/// 確かめてから通すこと。</b></para>
///
/// <para><b>意図的に対象外にしているもの。</b>
/// <list type="bullet">
///   <item><c>StartsWith(char)</c> … 定義上つねに序数比較で、比較方法の引数を受け取れない。
///     報告しても従いようがなく、実行不能な指示を出す検出網はいずれ緩められる方向へ倒れる。
///     <b>ただし判別できるのは文字リテラル(<c>','</c> の形)まで</b>で、
///     <c>k.StartsWith(p[0])</c> のように <c>char</c> 型の<b>式</b>を渡す形は
///     型を見ないと区別できないため違反として報告される(現在そのような呼び出しは無い)。
///     出てきたら、その呼び出しの意図をレビューで確認したうえでこの判定を見直すこと。</item>
///   <item><c>IndexOf(prefix) == 0</c> … 前方一致の書き方としては同じ危険があるが、
///     このリポジトリに用例が 1 つも無い一方、<c>IndexOf</c> 全般へ比較方法を要求すると
///     部分文字列検索の正当な用例まで巻き込む。実在しない事情のために検出網を広げない
///     (CLAUDE.md §6「将来を見越した過度な抽象化を避ける」)。<b>前方一致を
///     <c>IndexOf</c> で書く用例が出た時点で、この判断ごと見直すこと。</b></item>
/// </list></para>
/// </summary>
public class ModelStateKeyPrefixMatchTests
{
    // 許可する比較方法。ModelState のキーは画面が組み立てる識別子なので、
    // ロケールに依存しない序数比較だけを認める(CurrentCulture / InvariantCulture は
    // どちらも「文字を無視できる」規則を持ち込むため不可)
    private static readonly string[] AllowedComparisons =
    {
        "StringComparison.Ordinal",
        "StringComparison.OrdinalIgnoreCase",
    };

    // 探す呼び出しの綴り。メソッド名と開き括弧の間の空白は C# として妥当なので許す
    // (実測: "StartsWith(" と決め打ちしていた版は、間に空白を 1 つ入れるだけで
    //  呼び出しが見えなくなった。新しい呼び出し側には振る舞いのテストが無いため、
    //  その綴りなら全件緑のまま出荷できてしまう)
    private static readonly Regex StartsWithCallRegex = new(@"StartsWith\s*\(", RegexOptions.Compiled);

    [Fact]
    public void ModelStateKeyPrefixMatches_AlwaysUseOrdinalComparison()
    {
        // Razor 側も .cs 側と同じくアセンブリ全体を根にする。
        //
        // 当初 EnumerateViewFiles は Views/ 配下だけを辿っており、それは fail-open だった
        // (Areas/<Name>/Views/ や Pages/ 配下の .cshtml が走査対象から静かに外れる。
        //  実測: Pages/Probe.cshtml に素の StartsWith を置くと全件緑のまま通った)。
        // ここで自分だけ広い列挙を持つと、同じ列挙を使う 4 つの guard-rail テスト
        // (ConcurrencyTokenFormTests など)は取りこぼしたままになり、しかも
        // RepositoryPaths が「走査条件の唯一の源」だという宣言が嘘になる。
        // そこで共有ヘルパー側を広げ、こちらはそれを使う。
        var viewFiles = RepositoryPaths.EnumerateViewFiles().ToList();

        // .cs 側は Web プロジェクト配下を丸ごと対象にする（ビルド生成物だけ除く）。
        //
        // 「ModelState に触っているファイルだけ」という目印で絞る版を 2 度試したが、
        // どちらも fail-open だった: "ModelState.Keys" と綴りで絞った版は
        // ModelState.Where(...) を持つファイルを取りこぼし、"ModelState" まで緩めた版も
        // キー集合だけを受け取るヘルパ（KeysWithPrefix(IEnumerable<string> keys, ...) の形。
        // このリポジトリの既存ヘルパも MVC の型ではなく素のコレクションを受け取る）を
        // 取りこぼした。いずれも実測で全件緑のまま素通りしている。
        //
        // 絞り込みをやめられるのは、Web プロジェクト全体の StartsWith が実測で 5 箇所しか
        // 無く、そのすべてが ModelState のキーに対する前方一致だから。目印という
        // 「当たっているかどうか自体が見えない条件」を持たない方が、この規模では安全側。
        // 言語的な比較を意図する呼び出しが将来出てきたら、失敗メッセージの案内に従って
        // 許可値を広げるか対象から外す判断をレビューで行う。
        var controllerSources = RepositoryPaths.EnumerateWebSourceFiles()
            // .cs はコメントと文字列リテラルの中身を潰す(文言にメソッド名が出ても誤検出しない)
            .Select(p => ReadFor(p, blankStringContents: true))
            .ToList();

        // .cs が 1 つも無いなら、走査の根か配置が壊れている(空振り対策)
        Assert.True(controllerSources.Count > 0,
            "Web プロジェクト配下に .cs が 1 つもありません。走査の根が壊れています。");

        // ビュー側も同じ形（パスとコメントを潰した本文の組）に揃えておく
        var viewSources = viewFiles
            // .cshtml はコメントだけを潰す(理由は Neutralize の Razor に関する説明を参照)
            .Select(p => ReadFor(p, blankStringContents: false))
            .ToList();

        // 検出した違反(ファイル名・行番号・引数)を集める
        var violations = new List<string>();
        // ファイルごとに検査した呼び出し数を記録する。全体で 1 件でも見ていれば緑、では
        // 「片方の系統が丸ごと検査対象から外れた」ことを検出できないため、系統ごとに見る
        var callsByFile = new Dictionary<string, int>();

        // .cs 側とビュー側を合わせて走査する（本文はコメントを潰した状態で読み込み済み。
        // CLAUDE.md §5 が 1 行ごとの日本語コメントを求めるため、説明のために
        // StartsWith("...") をコメントへ書くことは実際にありうる。コード上の欠陥が
        // 無いのにコメントで落ちる検出網は、いずれ緩められる方向へ倒れる）
        foreach (var (path, source, raw) in controllerSources.Concat(viewSources))
        {
            // 報告用にリポジトリルートからの相対パスにしておく
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, path);
            // このファイルで見つけた呼び出しの数を数える
            var callsInFile = 0;

            // StartsWith の呼び出しを先頭から順に辿る(名前と開き括弧の間の空白も許す)
            foreach (Match call in StartsWithCallRegex.Matches(source))
            {
                // 報告用にこの呼び出しの開始位置を控える
                var index = call.Index;
                // この呼び出しの引数(開き括弧の直後から対応する閉じ括弧まで)を切り出す
                var arguments = ExtractArguments(source, call.Index + call.Length);
                // 括弧が閉じていない(＝読み取れない)なら、黙って見逃さず違反として報告する
                if (arguments == null)
                {
                    violations.Add($"{relativePath}:{LineNumberAt(source, index)}: 引数を読み取れませんでした");
                    continue;
                }
                // 引数を最上位のカンマで区切る（入れ子の呼び出しの中のカンマは数えない）
                var topLevelArguments = SplitTopLevelArguments(arguments);
                // char を取る多重定義は定義上つねに序数比較で、比較方法の引数を受け取れない。
                // 「StringComparison を明示せよ」と報告しても従いようがなく、実行不能な指示を
                // 出す検出網はいずれ緩められる方向へ倒れるので、対象から外す
                if (topLevelArguments.Count > 0 && IsCharLiteral(topLevelArguments[0]))
                    continue;
                // 検査した呼び出しとして数える
                callsInFile++;
                // 比較方法は「最後の引数そのもの」が許可した序数比較であることを求める。
                // 引数の文字列のどこかに綴りがあれば通す形だと、入れ子の呼び出しが受け取る
                // StringComparison.Ordinal を外側の（比較方法を渡していない）呼び出しの
                // 合格根拠にしてしまう（実測: Prefix("x", StringComparison.Ordinal) を
                // 引数に渡す形が素通りした）。見るべきは「その呼び出し自身が何を渡したか」
                if (topLevelArguments.Count > 0
                    && AllowedComparisons.Contains(StripArgumentName(topLevelArguments[^1]), StringComparer.Ordinal))
                    continue;
                // 序数比較を渡していない(引数なし・CurrentCulture 等)ので違反として記録する
                // 報告には元のソースの綴りを使う。走査用の本文は文字列の中身を空白へ潰して
                // あるので、そのまま出すと StartsWith("      ") のような読めない報告になる
                // (無害化は位置を保つよう同じ長さの空白へ置換しているので、同じ範囲を
                //  元のソースから切り出せば元の綴りが得られる)
                violations.Add($"{relativePath}:{LineNumberAt(source, index)}: "
                    + $"StartsWith({SameRange(raw, source, arguments, index)})");
            }

            // このファイルの検査件数を記録する
            callsByFile[relativePath] = callsInFile;
        }

        // 系統ごとに「1 件も見ていない」状態を弾く。片方が 0 でも全体が 0 でなければ
        // 気づけない、という前版の穴を塞ぐ
        AssertScanned(controllerSources.Select(f => f.Path), "Web プロジェクト配下(.cs)");
        AssertScanned(viewSources.Select(f => f.Path), "Razor ビュー(.cshtml)");

        // 違反があれば、直し方まで示して落とす
        Assert.True(violations.Count == 0,
            "StringComparison.Ordinal を明示してください"
            + "(引数なし・CurrentCulture・InvariantCulture はいずれも ICU が無視できるとみなす文字を"
            + "挟んだ文字列に誤一致します。ModelState のキーではこれが検証エラーの捨てすぎに直結します)。"
            + "(OrdinalIgnoreCase も可)。"
            + "【この検査の適用範囲】Web プロジェクト配下の .cs と .cshtml にある StartsWith を"
            + "すべて対象にします——受け手が ModelState のキーかどうかを構文解析なしに"
            + "判別できないためです。"
            + "【言語的な比較を意図している場合】許可値(AllowedComparisons)を広げてはいけません。"
            + "そこへ CurrentCulture を足すと、この検査が本来守っている ModelState のキーの"
            + "前方一致まで一斉に素通りします(この検査が存在する理由そのものが失われます)。"
            + "その呼び出しだけを対象から外す仕組みは現状ありません。必要になった時点で、"
            + "呼び出し単位の除外(理由付きの表)を足すところからレビューで設計してください。違反箇所:"
            + Environment.NewLine + string.Join(Environment.NewLine, violations));

        // 系統ごとの空振りを表明するローカル関数
        void AssertScanned(IEnumerable<string> files, string label)
        {
            // その系統で検査できた呼び出しの合計を求める
            var total = files.Sum(p => callsByFile.GetValueOrDefault(Path.GetRelativePath(RepositoryPaths.Root, p)));
            // 1 件も無ければ検出網が死んでいるので落とす
            Assert.True(total > 0,
                $"{label} から StartsWith( を 1 件も検出できませんでした。"
                + "前方一致を別の場所へ移したのなら、走査対象の導出条件も併せて直してください。");
        }
    }

    /// <summary>
    /// 引数の並びを「最上位のカンマ」で区切る。入れ子の括弧の中と文字列リテラルの中の
    /// カンマは区切りとして数えない(<c>Prefix("a", b)</c> のような入れ子の呼び出しを
    /// 1 つの引数として扱うため)。
    /// </summary>
    private static List<string> SplitTopLevelArguments(string arguments)
    {
        // 切り出した引数を順に溜める
        var parts = new List<string>();
        // 現在見ている括弧の深さ(0 が最上位)
        var depth = 0;
        // 今の引数が始まった位置
        var start = 0;
        // 引数の並びを 1 文字ずつ見ていく
        for (var i = 0; i < arguments.Length; i++)
        {
            // 現在の文字を取り出す
            var c = arguments[i];
            // 文字列/文字リテラルなら閉じ記号まで読み飛ばす(中のカンマを数えないため。
            // ',' という文字リテラルを区切りとして数えると引数の並びが壊れる)
            if (c == '"' || c == '\'')
            {
                // 閉じ記号の位置を求める
                var end = c == '"' ? SkipStringLiteral(arguments, i) : SkipCharLiteral(arguments, i);
                // 閉じていなければこれ以上は解釈できないので打ち切る
                if (end < 0) break;
                // リテラル全体を読み飛ばす
                i = end;
                // 次の文字へ
                continue;
            }
            // 括弧が開いたら深さを増やす(角括弧・波括弧も入れ子として数える)
            if (c is '(' or '[' or '{') depth++;
            // 括弧が閉じたら深さを減らす
            else if (c is ')' or ']' or '}') depth--;
            // 最上位のカンマだけを区切りとして扱う
            else if (c == ',' && depth == 0)
            {
                // ここまでを 1 つの引数として切り出す
                parts.Add(arguments[start..i]);
                // 次の引数はカンマの次から始まる
                start = i + 1;
            }
        }
        // 残りを最後の引数として加える(引数が空文字なら「引数なし」を表す 0 件にする)
        if (arguments.Trim().Length > 0) parts.Add(arguments[start..]);
        // 切り出した引数の並びを返す
        return parts;
    }

    /// <summary>
    /// 走査用（無害化済み）と報告用（元のまま）の本文を組にして読み込む。
    /// 無害化は同じ長さの空白へ置換するので、両者の位置は 1 文字もずれない。
    /// </summary>
    private static (string Path, string Source, string Raw) ReadFor(string path, bool blankStringContents)
    {
        // ファイル全体を 1 度だけ読む
        var raw = File.ReadAllText(path);
        // 走査用に無害化した本文と組にして返す
        return (path, Neutralize(raw, blankStringContents), raw);
    }

    /// <summary>
    /// 無害化済み本文の中の引数と同じ範囲を、元のソースから切り出して返す。
    /// 位置が対応しない場合（想定外）は無害化済みの綴りをそのまま返す。
    /// </summary>
    private static string SameRange(string raw, string source, string arguments, int callIndex)
    {
        // 引数が本文のどこから始まるかを、呼び出し位置以降で探す
        var start = source.IndexOf(arguments, callIndex, StringComparison.Ordinal);
        // 見つからない、または元のソースからはみ出すなら無害化済みの綴りで報告する
        if (start < 0 || start + arguments.Length > raw.Length) return arguments;
        // 同じ範囲を元のソースから切り出して返す
        return raw[start..(start + arguments.Length)];
    }

    /// <summary>
    /// 引数から名前付き引数の接頭辞(<c>comparisonType:</c> の形)を取り除いて値だけを返す。
    ///
    /// <para>名前付き引数は位置指定と意味がまったく同じなので、これを違反として報告すると
    /// 「すでにやっていることをやれ」という従いようのない指示になる(実測で確認)。
    /// 三項演算子の <c>:</c> と取り違えないよう、<b>コロンの手前が識別子 1 つだけ</b>の
    /// ときに限って取り除く。</para>
    /// </summary>
    private static string StripArgumentName(string argument)
    {
        // 前後の空白を落として素の綴りにする
        var trimmed = argument.Trim();
        // 最初のコロンの位置を求める
        var colon = trimmed.IndexOf(':');
        // コロンが無ければ名前付きではないのでそのまま返す
        if (colon < 0) return trimmed;
        // コロンの手前を取り出す
        var name = trimmed[..colon].Trim();
        // 識別子として妥当（英数字と _ のみ、かつ空でない）なときだけ接頭辞として落とす
        var isIdentifier = name.Length > 0 && name.All(c => char.IsLetterOrDigit(c) || c == '_');
        // 識別子ならコロンの後ろを、そうでなければ元の綴りを返す
        return isIdentifier ? trimmed[(colon + 1)..].Trim() : trimmed;
    }

    /// <summary>最初の引数が char リテラル(<c>'x'</c> の形)かどうかを返す。</summary>
    private static bool IsCharLiteral(string argument)
    {
        // 前後の空白を落として素の綴りにする
        var trimmed = argument.Trim();
        // 単一引用符で囲まれていれば char リテラル(最低でも 'x' の 3 文字)
        return trimmed.Length >= 3 && trimmed[0] == '\'' && trimmed[^1] == '\'';
    }

    /// <summary>
    /// 走査の邪魔になる領域を空白へ潰す: コメント(C# の <c>//</c>・<c>/* */</c> と
    /// Razor の <c>@* *@</c>)と、<b>文字列リテラルの中身</b>。
    ///
    /// <para><b>文字列の中身まで潰す理由。</b> 走査範囲をアセンブリ全体へ広げた結果、
    /// 「メソッド名を文言として含む文字列」がコード中に現れうるようになった
    /// (実測: <c>const string M = "use StartsWith(prefix) carefully";</c> を足すと、
    /// 前方一致を 1 つも持たないファイルが違反として報告された)。利用者向けメッセージや
    /// ログの書式にメソッド名が出るのは自然なことで、それを咎める検出網は
    /// いずれ緩められる方向へ倒れる。引用符は残して中身だけ潰すので、
    /// <c>StartsWith("x", StringComparison.Ordinal)</c> は
    /// <c>StartsWith("", StringComparison.Ordinal)</c> として正しく解釈でき、
    /// 比較方法の引数(文字列ではない)はそのまま残る。</para>
    ///
    /// <para><b>Razor(.cshtml)では文字列の中身を潰さない</b>(<paramref name="blankStringContents"/>
    /// を false にする)。Razor の <c>"</c> は HTML 属性の区切りでもあり、C# の文字列リテラルとして
    /// 追うと属性の開き引用符とコード中の引用符が対になって<b>間のコードごと飲み込む</b>
    /// (実測: <c>data-a="@(k.StartsWith("A") ? "on" : "off")"</c> と書くと呼び出しが
    /// 丸ごと見えなくなり、違反が素通りした)。取りこぼしは fail-open で、
    /// 文言にメソッド名が出る誤検出より重い。ビューでは引用符をただの 1 文字として
    /// 読み進め、コメントだけを潰す。</para>
    /// 文字列リテラルの中の同じ綴りはコメントとして扱わない。
    /// 位置(行番号)を保つため、取り除くのではなく改行以外を空白へ置き換える。
    /// </summary>
    private static string Neutralize(string source, bool blankStringContents)
    {
        // 書き換え用に 1 文字ずつ写せる配列にする
        var chars = source.ToCharArray();
        // 先頭から順に見ていく
        for (var i = 0; i < chars.Length; i++)
        {
            // 文字列リテラル・文字リテラルはそのまま残す(中の // や " をコメント/文字列扱いしないため)。
            // 文字リテラルを見落とすと '"' の 1 文字だけで解釈がずれ、そこから先のコメントが
            // 一切潰されなくなる——§5 が求める日本語コメントに StartsWith( と書いてあるだけで
            // 正しいコードが違反として報告される(実測)。文字列と同じ場所で必ず一緒に扱う
            if (chars[i] == '"' || chars[i] == '\'')
            {
                // Razor では " が HTML 属性の区切りでもあるため、C# の文字列リテラルとして
                // 追うと属性の開き引用符とコードの中の引用符が対になり、間のコードごと
                // 飲み込んでしまう(実測: data-a="@(k.StartsWith("A") ? ... )" と書くと
                // 呼び出しが丸ごと見えなくなり、違反が素通りした)。
                // .cshtml では引用符を「ただの 1 文字」として読み進め、コメントだけを潰す
                if (!blankStringContents && chars[i] == '"') continue;
                // 閉じ記号まで位置を進める
                var isString = chars[i] == '"';
                var end = isString ? SkipStringLiteral(source, i) : SkipCharLiteral(source, i);
                // 閉じ記号が無ければ、その 1 文字はリテラルの開始ではなかったと解釈して読み進める。
                // ここでファイル全体を打ち切ってはいけない: Razor の本文にある素のアポストロフィ
                // (英文の don't など。Create.cshtml だけで 56 個ある)で以降のコメントが一切
                // 潰されなくなり、§5 が求める日本語コメントに StartsWith( と書いてあるだけで
                // 正しいコードが違反として報告される(実測)。誤検出は検出網を緩める圧力になる
                if (end < 0) continue;
                // 文字列リテラルは中身だけ空白へ潰す(引用符は残すので構文としては壊れない)。
                // 文字リテラルは中身に括弧やカンマが入りうるので、潰さずそのまま読み飛ばす
                // (IsCharLiteral が ',' や '(' を判別できる必要があるため)
                if (isString && blankStringContents)
                    for (var j = i + 1; j < end; j++)
                        if (chars[j] != '\n' && chars[j] != '\r') chars[j] = ' ';
                // リテラル全体を読み飛ばす
                i = end;
                // 次の文字へ
                continue;
            }
            // 行コメント(//)・ブロックコメント(/* */)・Razor コメント(@* *@)の開始を判定する
            var (isComment, closing) = DetectCommentStart(source, i);
            // コメントでなければ何もしない
            if (!isComment) continue;
            // 終端の綴りが空なら行末まで、そうでなければその綴りまでを潰す
            var stop = closing.Length == 0
                // 行コメントは改行の直前まで
                ? IndexOfLineEnd(source, i)
                // ブロック系は終端の綴りを含めた位置まで
                : EndOfBlock(source, i, closing);
            // 開始位置から終端までを空白へ置き換える(改行だけは残して行番号を保つ)
            for (var j = i; j < stop; j++)
                if (chars[j] != '\n' && chars[j] != '\r') chars[j] = ' ';
            // 潰した領域の直後から走査を続ける
            i = stop - 1;
        }
        // 潰し終えた内容を文字列に戻す
        return new string(chars);
    }

    /// <summary>指定位置がコメントの開始かを判定し、開始なら終端の綴り(行コメントは空)を返す。</summary>
    private static (bool IsComment, string Closing) DetectCommentStart(string source, int i)
    {
        // 2 文字読めないなら開始ではありえない
        if (i + 1 >= source.Length) return (false, "");
        // // なら行コメント(終端は行末なので綴りは空)
        if (source[i] == '/' && source[i + 1] == '/') return (true, "");
        // /* ならブロックコメント
        if (source[i] == '/' && source[i + 1] == '*') return (true, "*/");
        // @* なら Razor コメント
        if (source[i] == '@' && source[i + 1] == '*') return (true, "*@");
        // どれでもない
        return (false, "");
    }

    /// <summary>指定位置から見た行末(改行の直前)の位置を返す。</summary>
    private static int IndexOfLineEnd(string source, int from)
    {
        // 次の改行を探す
        var newline = source.IndexOf('\n', from);
        // 改行が無ければ終端までが行の残り
        return newline < 0 ? source.Length : newline;
    }

    /// <summary>ブロックコメントの終端(終端綴りを含む)の位置を返す。見つからなければ終端。</summary>
    private static int EndOfBlock(string source, int from, string closing)
    {
        // 終端の綴りを探す
        var end = source.IndexOf(closing, from + 2, StringComparison.Ordinal);
        // 見つからなければファイル終端まで、見つかれば綴りを含めた位置まで
        return end < 0 ? source.Length : end + closing.Length;
    }

    /// <summary>
    /// 開き括弧の直後から、対応する閉じ括弧までの引数文字列を切り出す。
    /// 入れ子の括弧を数え、文字列リテラルの中は括弧として数えない。
    /// 括弧が閉じないまま終端に達したら <c>null</c> を返す(呼び出し側が違反として報告する)。
    /// </summary>
    private static string? ExtractArguments(string source, int start)
    {
        // 開き括弧 1 つぶんの深さから数え始める
        var depth = 1;
        // 開き括弧の直後から 1 文字ずつ見ていく
        for (var i = start; i < source.Length; i++)
        {
            // 現在の文字を取り出す
            var c = source[i];
            // 文字列/文字リテラルの開始なら、その終わりまで読み飛ばす(中の括弧を数えないため。
            // '(' のような文字リテラルを数えてしまうと括弧が永久に閉じず、
            // 「引数を読み取れませんでした」という直しようのない報告になる)
            if (c == '"' || c == '\'')
            {
                // 閉じ記号を探して位置を進める
                i = c == '"' ? SkipStringLiteral(source, i) : SkipCharLiteral(source, i);
                // 閉じ記号が見つからなければ読み取り不能
                if (i < 0) return null;
                // 読み飛ばしたので次の文字へ
                continue;
            }
            // 開き括弧なら深さを 1 増やす
            if (c == '(') depth++;
            // 閉じ括弧なら深さを 1 減らす
            else if (c == ')')
            {
                // 深さを減らした結果 0 になったら、そこが対応する閉じ括弧
                if (--depth == 0)
                    // 開き括弧の直後からここまでを引数として返す
                    return source[start..i];
            }
        }
        // 括弧が閉じないまま終端に達した
        return null;
    }

    /// <summary>
    /// 引用符の位置から文字列リテラルの閉じ引用符の位置を返す(見つからなければ -1)。
    ///
    /// <para>C# の 3 つの書き方を扱う。<b>1 つでも取り違えるとリテラルの終わりを
    /// 見失い、そこから先の解釈が丸ごとずれる</b>——<c>Neutralize</c> は以降の
    /// コメントを潰せなくなり、§5 が求める日本語コメントに <c>StartsWith(</c> と
    /// 書いてあるだけで正しいコードが違反として報告される。正しいコードを咎める
    /// 検出網はいずれ緩められる方向へ倒れるので、ここは網羅しておく。
    /// <list type="bullet">
    ///   <item>通常の <c>"..."</c> … バックスラッシュがエスケープになる。</item>
    ///   <item>逐語的 <c>@"..."</c> … バックスラッシュはエスケープ<b>ではなく</b>、
    ///     引用符を重ねた <c>""</c> が引用符 1 つを表す(実測: 逐語的リテラルを通常の
    ///     規則で読むと、末尾のバックスラッシュが閉じ引用符を打ち消して暴走した)。</item>
    ///   <item>生文字列 <c>"""..."""</c> … 開始と同じ数の引用符が終端になる。</item>
    /// </list></para>
    /// </summary>
    private static int SkipStringLiteral(string source, int quoteIndex)
    {
        // 直前の接頭辞を遡って逐語的リテラルかを判定する。@" だけでなく @$" / $@" もあり、
        // 直前 1 文字だけ見る版は @$" を取り違えてバックスラッシュをエスケープ扱いし、
        // 末尾のバックスラッシュで閉じ引用符を飲み込んで暴走した
        var isVerbatim = false;
        for (var k = quoteIndex - 1; k >= 0 && (source[k] == '@' || source[k] == '$'); k--)
            // 接頭辞に @ が含まれていれば逐語的リテラル
            if (source[k] == '@') { isVerbatim = true; break; }

        // 引用符が 3 つ以上続いていれば生文字列リテラル。ただし逐語的リテラルの
        // @"""..." は「引用符を重ねて 1 つを表す」書き方なので生文字列とは別物——
        // 先に逐語的かを見てから判定しないと、終端の意味を取り違えて暴走する
        var fenceLength = 0;
        while (quoteIndex + fenceLength < source.Length && source[quoteIndex + fenceLength] == '"') fenceLength++;
        if (!isVerbatim && fenceLength >= 3)
        {
            // 開始と同じ数の引用符が並ぶ位置が終端になる
            var fence = new string('"', fenceLength);
            // 開始フェンスの直後から終端フェンスを探す
            var close = source.IndexOf(fence, quoteIndex + fenceLength, StringComparison.Ordinal);
            // 見つからなければ読み取り不能、見つかればフェンス末尾の位置を返す
            return close < 0 ? -1 : close + fenceLength - 1;
        }

        // 開き引用符の次の文字から探し始める
        for (var i = quoteIndex + 1; i < source.Length; i++)
        {
            // 通常のリテラルだけバックスラッシュをエスケープとして扱う
            if (!isVerbatim && source[i] == '\\') { i++; continue; }
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

    /// <summary>
    /// 単一引用符の位置から文字リテラルの閉じ引用符の位置を返す(見つからなければ -1)。
    /// <c>'\''</c> のようなエスケープを考慮する。
    /// </summary>
    private static int SkipCharLiteral(string source, int quoteIndex)
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

    /// <summary>指定位置が何行目かを返す(報告用。1 始まり)。</summary>
    private static int LineNumberAt(string source, int index) =>
        // 先頭からその位置までに現れた改行の数 + 1 が行番号になる
        source.AsSpan(0, index).Count('\n') + 1;
}
