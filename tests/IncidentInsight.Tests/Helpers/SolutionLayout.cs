// ソリューションファイルからプロジェクト行を抜き出すために正規表現を使う
using System.Text.RegularExpressions;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// ソリューションファイル（<c>IncidentInsight.sln</c>）に登録されているプロジェクトを読み出す共有ヘルパー。
///
/// <para><b>なぜ集約するか。</b> ソリューションは「CI が <c>dotnet restore</c> する範囲そのもの」なので、
/// guard-rail テストが「対象を取りこぼしていないか」を照合する独立な手がかりとして使える。
/// 読み手ごとに行の書式（<c>Project("{型GUID}") = "表示名", "相対パス.csproj", "{GUID}"</c>）を
/// 書き写すと、書式の解釈がずれたときに片方だけが取りこぼす。</para>
///
/// <para><b>これは「導出」ではなく「照合の手がかり」として使う。</b> 対象を選ぶ導出と照合するガードを
/// 同じ手がかりから作ると、導出が狭まったときにガードも一緒に狭まって「取りこぼしゼロ＝緑」で
/// 無力化される（CLAUDE.md が別の検査について繰り返し記録している形）。
/// <c>ProductionDirectDependencyTests</c> は導出をファイルシステムから行い、ここを照合に使う。</para>
/// </summary>
internal static class SolutionLayout
{
    /// <summary>ソリューションファイルの名前（リポジトリルート直下）。</summary>
    internal const string FileName = "IncidentInsight.sln";

    // ソリューション行から csproj の相対パスを抜き出す正規表現。
    // ソリューションフォルダ(仮想フォルダ)の行は .csproj を含まないため自然に除外される
    private static readonly Regex ProjectLineRegex =
        new(@"""(?<path>[^""]+\.csproj)""", RegexOptions.Compiled);

    // 読み取りは 1 回で済むので結果を保持する(§8)。失敗時のメッセージをそのまま届けたいので Lazy
    private static readonly Lazy<IReadOnlyList<string>> Projects = new(ReadProjects);

    /// <summary>ソリューションに登録されたプロジェクトファイルの絶対パス（並びは固定）。</summary>
    internal static IReadOnlyList<string> ProjectFiles => Projects.Value;

    // ソリューションファイルを読み、登録されたプロジェクトの絶対パスを返す
    private static IReadOnlyList<string> ReadProjects()
    {
        // リポジトリルート直下のソリューションファイルを指す
        var solution = Path.Combine(RepositoryPaths.Root, FileName);

        // 見つからないまま先へ進むと照合が空振りするので、探した場所を示して落とす(fail-closed)
        Assert.True(File.Exists(solution),
            $"{FileName} が見つかりません(移動・リネーム、または探索の起点がずれている可能性があります)。"
            + $"探した場所: {solution}");

        // 各行から csproj の相対パスを抜き出し、絶対パスへ直す
        var projects = ProjectLineRegex.Matches(File.ReadAllText(solution))
            // ソリューションは Windows 形式の区切りで書かれるため、実行環境の区切りへ直す
            .Select(match => match.Groups["path"].Value.Replace('\\', Path.DirectorySeparatorChar))
            // リポジトリルートからの絶対パスにする
            .Select(relativePath => Path.Combine(RepositoryPaths.Root, relativePath))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // プロジェクトが 1 つも読み取れないのは書式変更などの異常なので落とす
        Assert.True(projects.Count > 0,
            $"{FileName} からプロジェクトを 1 つも読み取れませんでした。書式が変わった可能性があります。");

        // 登録されているのに実体が無いプロジェクトは、ソリューションの記述ずれとして落とす
        var missing = projects.Where(path => !File.Exists(path)).ToList();
        Assert.True(missing.Count == 0,
            $"{FileName} に登録されたプロジェクトが見つかりません:\n"
            + string.Join("\n", missing.Select(path => $"  {Path.GetRelativePath(RepositoryPaths.Root, path)}")));

        // 読み取ったプロジェクト一覧を返す
        return projects;
    }
}
