// リポジトリ内のパスを解決する共有ヘルパーを使う
using IncidentInsight.Tests.Helpers;

// ソース走査系の guard-rail テストが集まっている名前空間
// (ChartAccessibilityTests / ConcurrencyTokenFormTests / RoleGatedNavigationTests などと同居させる。
//  Razor ビューを走査するので、既存のビュー走査テストと同じ家に置くのが探しやすい)
namespace IncidentInsight.Tests.Views;

/// <summary>
/// Guard-rail test: <b>ModelState のキーに対する前方一致は必ず <c>StringComparison</c> を明示する</b>
/// ことを固定する。
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
/// 個別の振る舞いテストは「今ある呼び出し」しか押さえられず、次に増える箇所を止められない。
/// ソースを走査して「<c>StringComparison</c> を伴わない前方一致が 1 つも無いこと」を条件に
/// すれば、増えた側が自動的に検査対象になる。</para>
///
/// <para><b>引数の切り出しは行単位ではなく対応する括弧まで見る。</b> 初版は
/// <c>StartsWith\((?&lt;args&gt;[^\r\n]*)</c> という正規表現で行末までを引数とみなしていたが、
/// これは 2 つの意味で壊れていた: (1) 1 行に 2 つの呼び出しがあると最初の一致が行の残り全部を
/// 飲み込み、後ろの <c>StringComparison</c> を自分の引数と誤認する。(2) <c>Regex.Matches</c> は
/// 重なる一致を返さないので、後ろの呼び出しは<b>そもそも数えられない</b>。実測では
/// <c>.Where(k =&gt; k.StartsWith("CauseAnalysis.") || k.StartsWith("Measures[", StringComparison.Ordinal))</c>
/// と 1 行に書くだけで全 529 件が緑のまま通った——この検査が防ごうとしている当の回帰である。
/// そこで各呼び出しの<b>対応する閉じ括弧まで</b>を数えて引数を切り出す
/// (入れ子の括弧と文字列リテラルを追う)。複数行に折り返された式も同じ理由で
/// 行単位ではなくファイル全体を対象にする。</para>
/// </summary>
public class ModelStateKeyPrefixMatchTests
{
    /// <summary>
    /// 走査対象のうち <c>.cs</c> 側(Razor ビュー側は
    /// <see cref="RepositoryPaths.EnumerateViewFiles"/> から導出するのでここには書かない)。
    ///
    /// <para>ModelState のキーを前方一致で扱う <c>.cs</c> はこのファイルだけ。走査対象を
    /// アプリ全体の <c>.cs</c> へ広げると、自然言語の文字列に対する前方一致まで巻き込んで
    /// 実行不能な指示を出す検出網になるため、範囲を絞っている。<b>ModelState のキーを
    /// 前方一致で扱うコードを別の <c>.cs</c> へ足すときは、ここへ追加すること</b>。</para>
    /// </summary>
    private static readonly string[] ScannedSourceFiles =
    {
        Path.Combine(RepositoryPaths.WebProject, "Controllers", "IncidentsController.cs"),
    };

    // 探す呼び出しの綴り(この後ろの開き括弧から対応する閉じ括弧までを引数とみなす)
    private const string StartsWithCall = "StartsWith(";

    // 引数に必ず現れるべき綴り(序数比較などの比較方法の明示)
    private const string RequiredArgument = "StringComparison";

    [Fact]
    public void ModelStateKeyPrefixMatches_AlwaysSpecifyStringComparison()
    {
        // 検出した違反(ファイル名・行番号・引数)を集める
        var violations = new List<string>();
        // ファイルごとに検査した呼び出し数を記録する。全体で 1 件でも見ていれば緑、では
        // 「片方のファイルが丸ごと検査対象から外れた」ことを検出できない
        // (例: ビュー側の判定を partial やヘルパへ切り出すと、そのファイルの寄与が 0 になる)。
        // 空振りの判定はファイル単位で行う
        var inspectedCallsByFile = new Dictionary<string, int>();

        // .cs 側の対象と、Razor ビュー側の対象(共有の列挙から導出)を合わせて走査する
        foreach (var path in ScannedSourceFiles.Concat(RepositoryPaths.EnumerateViewFiles()))
        {
            // 報告用にリポジトリルートからの相対パスにしておく
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, path);
            // ファイル全体を読む(式が複数行へ折り返されていても取りこぼさないため)
            var source = File.ReadAllText(path);
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
                // 比較方法が明示されていれば違反ではない
                if (arguments.Contains(RequiredArgument, StringComparison.Ordinal))
                    continue;
                // 明示が無い＝現在のカルチャで比較されるので違反として記録する
                violations.Add($"{relativePath}:{LineNumberAt(source, index)}: StartsWith({arguments})");
            }

            // このファイルの検査件数を記録する
            inspectedCallsByFile[relativePath] = callsInFile;
        }

        // .cs 側の対象は必ず 1 件以上の呼び出しを含むはず。0 件なら走査か対象指定が壊れている
        foreach (var path in ScannedSourceFiles)
        {
            // 相対パスに直してから件数を引く
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, path);
            // 対象ファイルが実在することを確かめる(改名で走査が黙って空振りするのを防ぐ)
            Assert.True(File.Exists(path), $"走査対象のファイルが見つかりません: {relativePath}");
            // 1 件も検出できていなければ、このファイルは検査されていないのと同じなので落とす
            Assert.True(inspectedCallsByFile.GetValueOrDefault(relativePath) > 0,
                $"{relativePath} から StartsWith( を 1 件も検出できませんでした。"
                + "前方一致を別の場所へ移したのなら、走査対象(ScannedSourceFiles)も併せて直してください。");
        }

        // Razor ビュー側も、全体で 1 件も見ていなければ検出網が死んでいる
        Assert.True(
            RepositoryPaths.EnumerateViewFiles()
                .Select(p => inspectedCallsByFile.GetValueOrDefault(Path.GetRelativePath(RepositoryPaths.Root, p)))
                .Sum() > 0,
            "Razor ビューから StartsWith( を 1 件も検出できませんでした。走査条件が壊れています。");

        // 違反があれば、直し方まで示して落とす
        Assert.True(violations.Count == 0,
            "ModelState のキーに対する前方一致は StringComparison.Ordinal を明示してください"
            + "(引数なしの StartsWith は現在のカルチャで比較され、ICU が無視できるとみなす文字を"
            + "挟んだキーにも誤一致して検証エラーを捨てすぎます)。違反箇所:"
            + Environment.NewLine + string.Join(Environment.NewLine, violations));
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
