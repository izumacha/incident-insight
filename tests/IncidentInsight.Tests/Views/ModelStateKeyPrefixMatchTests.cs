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
/// <para><b>この検査自体も 2 度素通りさせた。</b> 直し方を記録しておく。
/// <list type="number">
///   <item>引数を行末まで取っていたため、1 行に 2 つ呼び出しがあると最初の一致が行の残りを
///     飲み込み、後ろの呼び出しは <c>Regex.Matches</c> の非重複規則で数えられもしなかった
///     (実測: 1 行に書き直すだけで全件緑)。→ 対応する閉じ括弧まで数えて切り出す。</item>
///   <item>引数に <c>StringComparison</c> という綴りがあれば通していたため、
///     <c>StringComparison.CurrentCulture</c> を渡す形が素通りした(実測: 全件緑)。
///     「明示したか」ではなく<b>「序数比較か」</b>を見るのが正しい。→ 許可する値を
///     <see cref="AllowedComparisons"/> に列挙して突き合わせる。</item>
/// </list>
/// どちらも「検査が形だけ通る条件」を見ていたのが原因で、<b>守りたい性質そのもの</b>を
/// 条件にしていなかった。</para>
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

    // 探す呼び出しの綴り(この後ろの開き括弧から対応する閉じ括弧までを引数とみなす)
    private const string StartsWithCall = "StartsWith(";

    // .cs 側の走査範囲を決める目印。ModelState のキー集合を触っているファイルだけを対象にする
    private const string ModelStateKeysMarker = "ModelState.Keys";

    [Fact]
    public void ModelStateKeyPrefixMatches_AlwaysUseOrdinalComparison()
    {
        // Razor ビューは共有の列挙から導出する(4 つのビュー走査テストが各自で列挙して
        // ずれた経緯があり、RepositoryPaths.EnumerateViewFiles が唯一の源)。
        // 2 度列挙して食い違う余地を作らないよう、1 度だけ実体化して使い回す
        var viewFiles = RepositoryPaths.EnumerateViewFiles().ToList();

        // .cs 側は一覧を手で持たず、「Controllers 配下で ModelState.Keys に触っているファイル」
        // という増えれば自動的に増える目印から導出する。手書きの一覧だと、別のコントローラへ
        // 同じ構文を足したときに検査対象から静かに外れる(この検査が防ごうとしている形そのもの)
        var controllerFiles = Directory
            .EnumerateFiles(Path.Combine(RepositoryPaths.WebProject, "Controllers"), "*.cs", SearchOption.AllDirectories)
            .Where(p => File.ReadAllText(p).Contains(ModelStateKeysMarker, StringComparison.Ordinal))
            .ToList();

        // 目印を持つコントローラが 1 つも無いなら、導出条件か配置が壊れている(空振り対策)
        Assert.True(controllerFiles.Count > 0,
            $"Controllers 配下に {ModelStateKeysMarker} を含むファイルが 1 つもありません。"
            + "導出条件が壊れているか、ModelState のキー操作が別の場所へ移っています。");

        // 検出した違反(ファイル名・行番号・引数)を集める
        var violations = new List<string>();
        // ファイルごとに検査した呼び出し数を記録する。全体で 1 件でも見ていれば緑、では
        // 「片方の系統が丸ごと検査対象から外れた」ことを検出できないため、系統ごとに見る
        var callsByFile = new Dictionary<string, int>();

        // .cs 側とビュー側を合わせて走査する
        foreach (var path in controllerFiles.Concat(viewFiles))
        {
            // 報告用にリポジトリルートからの相対パスにしておく
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, path);
            // ファイル全体を読み、コメントを取り除いてから走査する。
            // CLAUDE.md §5 が 1 行ごとの日本語コメントを求めるため、説明のために
            // StartsWith("...") をコメントへ書くことが実際にありうる。コード上の欠陥が
            // 無いのにコメントで落ちる検出網は、いずれ緩められる方向へ倒れる
            var source = StripComments(File.ReadAllText(path));
            // このファイルで見つけた呼び出しの数を数える
            var callsInFile = 0;

            // StartsWith( の出現位置を先頭から順に辿る
            for (var index = source.IndexOf(StartsWithCall, StringComparison.Ordinal);
                 index >= 0;
                 index = source.IndexOf(StartsWithCall, index + StartsWithCall.Length, StringComparison.Ordinal))
            {
                // この呼び出しの引数(対応する閉じ括弧まで)を切り出す
                var arguments = ExtractArguments(source, index + StartsWithCall.Length);
                // 括弧が閉じていない(＝読み取れない)なら、黙って見逃さず違反として報告する
                if (arguments == null)
                {
                    violations.Add($"{relativePath}:{LineNumberAt(source, index)}: 引数を読み取れませんでした");
                    continue;
                }
                // 検査した呼び出しとして数える
                callsInFile++;
                // 許可した序数比較のいずれかを渡していれば違反ではない
                if (AllowedComparisons.Any(c => arguments.Contains(c, StringComparison.Ordinal)))
                    continue;
                // 序数比較を渡していない(引数なし・CurrentCulture 等)ので違反として記録する
                violations.Add($"{relativePath}:{LineNumberAt(source, index)}: StartsWith({arguments})");
            }

            // このファイルの検査件数を記録する
            callsByFile[relativePath] = callsInFile;
        }

        // 系統ごとに「1 件も見ていない」状態を弾く。片方が 0 でも全体が 0 でなければ
        // 気づけない、という前版の穴を塞ぐ
        AssertScanned(controllerFiles, "Controllers 配下(.cs)");
        AssertScanned(viewFiles, "Razor ビュー(.cshtml)");

        // 違反があれば、直し方まで示して落とす
        Assert.True(violations.Count == 0,
            "ModelState のキーに対する前方一致は StringComparison.Ordinal を明示してください"
            + "(引数なし・CurrentCulture・InvariantCulture はいずれも ICU が無視できるとみなす文字を"
            + "挟んだキーに誤一致し、検証エラーを捨てすぎます)。違反箇所:"
            + Environment.NewLine + string.Join(Environment.NewLine, violations));

        // 系統ごとの空振りを表明するローカル関数
        void AssertScanned(List<string> files, string label)
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
    /// C# の <c>//</c>・<c>/* */</c> と Razor の <c>@* *@</c> を空白へ潰す。
    /// 文字列リテラルの中の同じ綴りはコメントとして扱わない。
    /// 位置(行番号)を保つため、取り除くのではなく改行以外を空白へ置き換える。
    /// </summary>
    private static string StripComments(string source)
    {
        // 書き換え用に 1 文字ずつ写せる配列にする
        var chars = source.ToCharArray();
        // 先頭から順に見ていく
        for (var i = 0; i < chars.Length; i++)
        {
            // 文字列リテラルはそのまま残す(中の // などをコメント扱いしないため)
            if (chars[i] == '"')
            {
                // 閉じ引用符まで位置を進める
                var end = SkipStringLiteral(source, i);
                // 閉じ引用符が無ければこれ以上は解釈できないので打ち切る
                if (end < 0) break;
                // 文字列リテラル全体を読み飛ばす
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
            // 文字列リテラルの開始なら、その終わりまで読み飛ばす(中の括弧を数えないため)
            if (c == '"')
            {
                // 閉じ引用符を探して位置を進める
                i = SkipStringLiteral(source, i);
                // 閉じ引用符が見つからなければ読み取り不能
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
    /// バックスラッシュによるエスケープを考慮する。
    /// </summary>
    private static int SkipStringLiteral(string source, int quoteIndex)
    {
        // 開き引用符の次の文字から探し始める
        for (var i = quoteIndex + 1; i < source.Length; i++)
        {
            // エスケープなら次の 1 文字を読み飛ばす
            if (source[i] == '\\') { i++; continue; }
            // 引用符に出会ったらそこが閉じ位置
            if (source[i] == '"') return i;
        }
        // 閉じ引用符が見つからなかった
        return -1;
    }

    /// <summary>指定位置が何行目かを返す(報告用。1 始まり)。</summary>
    private static int LineNumberAt(string source, int index) =>
        // 先頭からその位置までに現れた改行の数 + 1 が行番号になる
        source.AsSpan(0, index).Count('\n') + 1;
}
