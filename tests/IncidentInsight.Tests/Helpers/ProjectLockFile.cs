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

    /// <summary>直接参照か推移依存かを表す JSON キー。</summary>
    internal const string TypeKey = "type";

    /// <summary>実際に解決された版を表す JSON キー。</summary>
    internal const string ResolvedKey = "resolved";

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

    /// <summary>そのプロジェクトの隣にあるロックファイルの絶対パスを返す。</summary>
    /// <param name="projectDirectory">プロジェクトファイルを置いているディレクトリ。</param>
    internal static string PathFor(string projectDirectory) =>
        // ロックファイルはプロジェクトファイルと同じディレクトリに置かれる決まり
        Path.Combine(projectDirectory, FileName);

    /// <summary>
    /// ロックファイルの全項目を読み出す。書式が読めないときは、どのファイルかを示して
    /// <see cref="Xunit.Assert"/> で落とす（黙って 0 件を返すと呼び出し側の検査が空振りする）。
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
                // 解決済みの版を控える(ProjectReference の項目のように持たないものは null)
                var version = entry.Value.TryGetProperty(ResolvedKey, out var resolved) ? resolved.GetString() : null;
                // 1 件分として記録する
                entries.Add(new Entry(entry.Name, kind, version));
            }
        }

        // 1 件も読めないのは書式変更などの異常で、放置すると呼び出し側が「違反ゼロ＝緑」になる
        Assert.True(entries.Count > 0,
            $"{relativePath} から項目を 1 件も読み取れませんでした。{FileName} の書式が変わった"
            + "可能性があります(この状態では、このファイルを読む検査がすべて空振りします)。");

        // 読み取った一覧を返す
        return entries;
    }
}
