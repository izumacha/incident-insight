// packages.lock.json を JSON として読むために取り込む
using System.Text.Json;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// NuGet の <c>packages.lock.json</c> を「構造」として読むための共有ヘルパー。
///
/// <para><b>なぜ集約するか。</b> ロックファイルの書式を表すキー名（<c>dependencies</c> /
/// <c>type</c> / <c>resolved</c>）と <c>type</c> の値（<c>Direct</c>）は、読み手ごとに
/// 書き写すと <b>ずれても誰も落ちない</b>種類の写しになる。CLAUDE.md §6 は
/// 「キー名は名前付き定数にし単一の参照元に置く」と、DRY とは別の項目として要求している。
/// 実際、Central Package Management を入れると <c>type</c> に <c>CentralTransitive</c> が
/// 増えるが、そのとき片方の読み手だけを直しても、もう片方は<b>その項目を黙って読み飛ばす</b>
/// （「違反ゼロ＝緑」へ倒れる向き）。</para>
///
/// <para><b>走査そのものも共有する。</b> 「ターゲットフレームワークごとの入れ子を降りて
/// 各パッケージの type と resolved を見る」という歩き方は、複数の guard-rail テストが
/// 同じ形で必要とする。ここで 1 度だけ書いておけば、multi-target 化のような書式の変化に
/// 追随する場所も 1 つに保てる。</para>
/// </summary>
internal static class ProjectLockFile
{
    /// <summary>各プロジェクトの隣に置かれるロックファイルの名前。</summary>
    internal const string FileName = "packages.lock.json";

    /// <summary>ターゲットフレームワークごとの解決結果をまとめている JSON キー。</summary>
    internal const string DependenciesKey = "dependencies";

    // 直接参照か推移依存かを表す JSON キー。
    // 【なぜ private か】この綴りを読むのはこのクラスの走査だけで、外へ出すと
    // 別のロックファイル走査へ書き写す足場になる(このヘルパーが止めようとしている drift そのもの)
    private const string TypeKey = "type";

    // 実際に解決された版を表す JSON キー(private の理由は TypeKey と同じ)
    private const string ResolvedKey = "resolved";

    /// <summary>
    /// <see cref="TypeKey"/> が「csproj に直接書かれた参照」を表すときの値
    /// （推移依存なら <c>Transitive</c>、ProjectReference なら <c>Project</c> になる）。
    /// </summary>
    internal const string DirectKind = "Direct";

    /// <summary>
    /// ロックファイルの 1 項目。<paramref name="Version"/> は解決済みの版で、
    /// ProjectReference の項目のように <see cref="ResolvedKey"/> を持たない項目では <c>null</c>。
    /// </summary>
    /// <param name="Id">パッケージ ID。</param>
    /// <param name="Kind">直接参照か推移依存かを表す値（<see cref="DirectKind"/> 等）。</param>
    /// <param name="Version">解決済みの版。読み取れないときは <c>null</c>。</param>
    internal record Entry(string Id, string Kind, string? Version);

    /// <summary>
    /// そのプロジェクトファイルの隣にあるロックファイルの絶対パスを返す。
    /// <para><b>受け取るのはプロジェクトファイルのパスで、ディレクトリではない。</b>
    /// 「ロックファイルがどこに置かれるか」という知識を呼び出し側へ漏らさないため
    /// （漏らすと置き場所が変わったときに、直し漏れた呼び出し側だけが静かに意味を変える）。</para>
    /// </summary>
    /// <param name="projectFilePath">csproj の絶対パス。</param>
    internal static string PathFor(string projectFilePath) =>
        // ロックファイルはプロジェクトファイルと同じディレクトリに置かれる決まり
        Path.Combine(Path.GetDirectoryName(projectFilePath)!, FileName);

    /// <summary>
    /// ロックファイルの全項目を読み出す。ファイルが無い・<see cref="DependenciesKey"/> が無いといった
    /// 「読めない」形は、どのファイルかを示して <see cref="Xunit.Assert"/> で落とす（fail-closed）。
    /// 項目が 0 件であること自体は正当な状態なので落とさない（実装のコメントを参照）。
    /// </summary>
    /// <param name="lockFilePath">読むロックファイルの絶対パス。</param>
    internal static IReadOnlyList<Entry> ReadEntries(string lockFilePath)
    {
        // 失敗メッセージ用に、リポジトリルートからの相対パスにしておく
        var relativePath = Path.GetRelativePath(RepositoryPaths.Root, lockFilePath);

        // 見つからないまま先へ進むと検査が空振りするので、探した場所を示して落とす(fail-closed)
        Assert.True(File.Exists(lockFilePath),
            $"{relativePath} が見つかりません(移動・リネーム、または RestorePackagesWithLockFile が"
            + $"外れた可能性があります)。探した場所: {lockFilePath}");

        // ロックファイルを JSON として解析する
        using var document = JsonDocument.Parse(File.ReadAllText(lockFilePath));

        // 解決結果はターゲットフレームワークごとに入れ子になっている。
        // 書式が変わって読めないときは、素の例外ではなくどのファイルが読めなかったかを示して落とす
        Assert.True(document.RootElement.TryGetProperty(DependenciesKey, out var dependencies),
            $"{relativePath} に {DependenciesKey} がありません。{FileName} の書式が変わった可能性が"
            + "あります(読み取れないと、このファイルを読む検査が静かに空振りします)。");

        // 読み取った項目を溜める入れ物
        var entries = new List<Entry>();
        // ターゲットフレームワークごとに解決結果を見る(multi-target でも取りこぼさない)
        foreach (var framework in dependencies.EnumerateObject())
        {
            // そのフレームワーク配下のパッケージを 1 件ずつ取り出す
            foreach (var entry in framework.Value.EnumerateObject())
            {
                // 直接参照か推移依存かを控える(読めない項目は空文字として扱い、呼び出し側の判定に委ねる)
                var kind = entry.Value.TryGetProperty(TypeKey, out var type) ? type.GetString() ?? "" : "";
                // 解決済みの版を控える。
                // 【「キーが無い」と「キーはあるが null」を区別する】前者は ProjectReference の項目など
                // 版を持たないもので、呼び出し側が対象外として飛ばす正当な形。後者は壊れた記録で、
                // null と同じ扱いにすると呼び出し側が黙って読み飛ばす(fail-open)。空文字として返せば、
                // 版を解釈する側(例: メジャー番号の読み取り)がどのパッケージかを名指しして落とせる
                var version = entry.Value.TryGetProperty(ResolvedKey, out var resolved)
                    ? resolved.GetString() ?? ""
                    : null;
                // 1 件分として記録する
                entries.Add(new Entry(entry.Name, kind, version));
            }
        }

        // 読み取った一覧を返す。
        //
        // 【ここで「0 件なら異常」とは判定しない】PackageReference も ProjectReference も持たない
        // プロジェクトのロックファイルは {"dependencies":{"net8.0":{}}} になり、これは正当な状態。
        // ここで落とすと、そういうプロジェクトを 1 つ足しただけで、このファイルを読むすべての検査が
        // 「書式が変わった」という誤った原因を名指しして赤くなる(直し方の無い赤)。
        // 「読み取りが丸ごと空振りしていないか」は、複数のプロジェクトを束ねて見る呼び出し側が
        // 集計に対して判定する(EfCorePackageAlignmentTests.ReadAllResolvedPackages がその形)。
        // 本当に読めない形 ―― dependencies が無い・ファイルが無い ―― は上で fail-closed にしている
        return entries;
    }
}
