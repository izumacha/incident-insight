// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// テスト実行ディレクトリ(ビルド出力先)から親を遡って、リポジトリ内の主要なパスを解決する。
///
/// なぜ必要か: View の Razor ソースや dependabot.yml のような「ソースファイルそのもの」を
/// 読む guard-rail テストは、ビルド出力にコピーされないファイルを絶対パスで開く必要がある。
/// その探索ロジックが 5 箇所へコピーされ、しかも探す目印が微妙に食い違っていたため
/// (4 箇所は src/IncidentInsight.Web だけ、1 箇所は .github も条件に加えていた)、
/// 唯一の参照元としてここへ集約する(issue #164 / CLAUDE.md §6 の DRY)。
///
/// 目印は「src/IncidentInsight.Web と .github を併せ持つ階層」で統一する。
/// src/IncidentInsight.Web だけを目印にすると、将来リポジトリの外側に同名の
/// ディレクトリ構成があった場合に誤って手前で止まりうるため、条件が厳しい方に揃えている。
/// </summary>
internal static class RepositoryPaths
{
    // ソースを収める最上位ディレクトリ名(リポジトリルートの目印その 1)
    private const string SrcDirectoryName = "src";

    // Web プロジェクトのディレクトリ名(リポジトリルートの目印その 1・続き)
    private const string WebProjectDirectoryName = "IncidentInsight.Web";

    // GitHub 設定ディレクトリ名(リポジトリルートの目印その 2)
    private const string GitHubDirectoryName = ".github";

    // Razor ビューを収めるディレクトリ名
    private const string ViewsDirectoryName = "Views";

    // リポジトリルートの絶対パス。探索は 1 回で済むので静的フィールドへ保持する
    private static readonly string RootDirectory = FindRoot();

    /// <summary>リポジトリルート(ソリューションファイルや .github がある階層)の絶対パス。</summary>
    public static string Root => RootDirectory;

    /// <summary>Web プロジェクト(src/IncidentInsight.Web)の絶対パス。</summary>
    public static string WebProject => Path.Combine(Root, SrcDirectoryName, WebProjectDirectoryName);

    /// <summary>Razor ビュー(src/IncidentInsight.Web/Views)の絶対パス。</summary>
    public static string Views => Path.Combine(WebProject, ViewsDirectoryName);

    // ビルド出力ディレクトリから上へ辿ってリポジトリルートを探す
    private static string FindRoot()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ファイルシステムのルートに達するまで親を遡る
        while (dir != null)
        {
            // Web プロジェクトと .github の両方を持つ階層がリポジトリルート
            if (Directory.Exists(Path.Combine(dir.FullName, SrcDirectoryName, WebProjectDirectoryName))
                && Directory.Exists(Path.Combine(dir.FullName, GitHubDirectoryName)))
            {
                // 見つかったのでその絶対パスを返す
                return dir.FullName;
            }
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException(
            $"リポジトリルート({SrcDirectoryName}/{WebProjectDirectoryName} と {GitHubDirectoryName} を持つ階層)が"
            + $"テスト実行位置({AppContext.BaseDirectory})から見つかりません。");
    }
}
