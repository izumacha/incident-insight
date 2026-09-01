// ソース走査に使う正規表現
using System.Text.RegularExpressions;
// リポジトリ内のパスを解決する共有ヘルパーを使う
using IncidentInsight.Tests.Helpers;

// テストの名前空間(ソース走査系の guard-rail は Models 配下に集めている)
namespace IncidentInsight.Tests.Models;

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
/// <para><b>この検査が要る理由は、実際に取りこぼしたから。</b> 同じ構文は当初
/// コントローラに 3 箇所・Razor ビューに 2 箇所あった。序数比較へ揃える作業を 2 回行って
/// なお、コントローラの 1 箇所とビューの 2 箇所が残っていた。個別の振る舞いテストは
/// 「今ある呼び出し」しか押さえられず、<b>4 箇所目・5 箇所目が黙って増える</b>のを止められない。
/// ソースを走査して「素の StartsWith が 1 つも無いこと」を条件にすれば、増えた側が自動的に
/// 検査対象になる(このリポジトリが繰り返し採っている「写しを持たず、導出する」形)。</para>
///
/// <para>対象を「ModelState のキーに対する前方一致」に絞っているのは、自然言語の文字列に
/// 対する前方一致(利用者向けの表示文字列など)まで序数比較を強いると、実行不能な指示を
/// 出す検出網になるため。判定は「<c>ModelState</c> を含む行から始まる式の中の
/// <c>StartsWith(</c>」ではなく、下記のとおり<b>該当ファイルに現れる全ての
/// <c>StartsWith(</c> が <c>StringComparison</c> を伴うこと</b>で行う
/// (現状これらのファイルにある前方一致は ModelState のキーに対するものだけで、
/// 式が複数行へ折り返される書き方でも取りこぼさないため)。</para>
/// </summary>
public class ModelStateKeyPrefixMatchTests
{
    /// <summary>
    /// 走査対象のソースファイル(リポジトリルートからの相対パス)。
    ///
    /// <para>ModelState のキーを前方一致で扱っているのはこの 2 ファイルだけ。
    /// 一覧を持つ以上「新しいファイルで同じことをすると視界に入らない」境界は残るが、
    /// 対象をアプリ全体へ広げると自然言語向けの <c>StartsWith</c> まで巻き込むため、
    /// 実行可能な範囲に絞っている。<b>ModelState のキーを前方一致で扱うコードを
    /// 別のファイルへ足すときは、ここへ追加すること</b>(この一覧の意味は下の
    /// 「空振り対策」の表明が支えている)。</para>
    /// </summary>
    private static readonly string[] ScannedFiles =
    {
        Path.Combine("src", RepositoryPaths.WebProjectDirectoryName, "Controllers", "IncidentsController.cs"),
        Path.Combine("src", RepositoryPaths.WebProjectDirectoryName, "Views", "Incidents", "Details.cshtml"),
    };

    // StartsWith( の呼び出しを 1 件ずつ抜き出す正規表現。
    // 引数の中に入れ子の括弧・文字列補間が入りうるので、閉じ括弧までを厳密に取らず
    // 「StartsWith( から、その行の末尾または閉じ括弧の並びまで」を粗く取り、
    // StringComparison の有無だけを見る(判定に必要なのはそれだけのため)
    private static readonly Regex StartsWithCallRegex =
        new(@"StartsWith\((?<args>[^\r\n]*)", RegexOptions.Compiled);

    [Fact]
    public void ModelStateKeyPrefixMatches_AlwaysSpecifyStringComparison()
    {
        // 検出した違反(ファイル名・行番号・該当行)を集める
        var violations = new List<string>();
        // 検査した StartsWith 呼び出しの数。0 件のまま終わると「違反なし」と区別が付かず、
        // 検出パターンが壊れただけなのに緑になってしまうため数えておく
        // (ConcurrencyTokenFormTests と同じ空振り対策)
        var inspectedCalls = 0;

        // 走査対象のファイルを 1 つずつ見る
        foreach (var relativePath in ScannedFiles)
        {
            // リポジトリルートからの絶対パスへ直す
            var fullPath = Path.Combine(RepositoryPaths.Root, relativePath);
            // 対象ファイルが実在することを確かめる(改名で走査が黙って空振りするのを防ぐ)
            Assert.True(File.Exists(fullPath), $"走査対象のファイルが見つかりません: {relativePath}");

            // 行番号を添えて報告できるよう 1 行ずつ読む
            var lines = File.ReadAllLines(fullPath);
            // 各行を先頭から順に見る
            for (var i = 0; i < lines.Length; i++)
            {
                // この行に含まれる StartsWith( の呼び出しをすべて取り出す
                foreach (Match match in StartsWithCallRegex.Matches(lines[i]))
                {
                    // 検査した呼び出しの件数を 1 増やす
                    inspectedCalls++;
                    // 引数に StringComparison が含まれていれば序数比較などが明示されている
                    if (match.Groups["args"].Value.Contains("StringComparison", StringComparison.Ordinal))
                        // 明示済みなので違反ではない
                        continue;
                    // 明示が無い＝現在のカルチャで比較されるので違反として記録する
                    violations.Add($"{relativePath}:{i + 1}: {lines[i].Trim()}");
                }
            }
        }

        // 検出パターン自体が壊れていないことを確かめる(1 件も見ていなければ検査が無意味)
        Assert.True(inspectedCalls > 0,
            "StartsWith( の呼び出しを 1 件も検出できませんでした。走査対象か正規表現が壊れています。");

        // 違反があれば、直し方まで示して落とす
        Assert.True(violations.Count == 0,
            "ModelState のキーに対する前方一致は StringComparison.Ordinal を明示してください"
            + "(引数なしの StartsWith は現在のカルチャで比較され、ICU が無視できるとみなす文字を"
            + "挟んだキーにも誤一致して検証エラーを捨てすぎます)。違反箇所:"
            + Environment.NewLine + string.Join(Environment.NewLine, violations));
    }
}
