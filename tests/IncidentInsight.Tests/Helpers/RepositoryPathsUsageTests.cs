// このテストクラスが属する名前空間(検査対象の RepositoryPaths と同じなので using は不要)
namespace IncidentInsight.Tests.Helpers;

// Guard-rail test: リポジトリ内のパス探索を <see cref="RepositoryPaths"/> 以外で
// 自前実装していないことを検査する。
//
// 背景: ビルド出力から親を遡ってソースツリーを探すロジックは、集約するまでに
// テストプロジェクト内へ 5 箇所コピーされていた(issue #164)。しかも探す目印が
// 揃っておらず、4 箇所は src/IncidentInsight.Web だけ、1 箇所は .github も条件に
// 加えていた。コピーが増えても何も落ちないため重複は静かに育つ
// (実際、5 つ目を足した PR のコメント自体が「既存と同じ探索ロジック」と認めていた)。
//
// そこで「起点となる AppContext.BaseDirectory をテストソースで直接触るのは
// 共有ヘルパーだけ」という形で機械的に固定する。6 つ目のコピーはこのテストで落ちる。
public class RepositoryPathsUsageTests
{
    // 探索の起点として使われる API。これをテストソースで直に触るのが重複の入口になる
    private const string SearchRootApi = "AppContext.BaseDirectory";

    // 唯一この API を使ってよいファイル(共有ヘルパー本体)
    private const string SharedHelperFileName = "RepositoryPaths.cs";

    // 検査対象から外すファイル名。共有ヘルパー本体に加えて、本テスト自身も除外する
    // (探す文字列そのものをソースに書く必要があるため、除外しないと自分を違反として拾う)
    private static readonly string[] ExemptFileNames =
    {
        SharedHelperFileName,
        nameof(RepositoryPathsUsageTests) + ".cs",
    };

    [Fact]
    public void RepositorySearch_IsImplementedOnlyInSharedHelper()
    {
        // テストプロジェクトのソースディレクトリを組み立てる
        var testProjectDir = Path.Combine(RepositoryPaths.Root, "tests", "IncidentInsight.Tests");
        // 走査対象が実在すること(ディレクトリ改名でテストが無言で無効化されるのを防ぐ)
        Assert.True(Directory.Exists(testProjectDir), $"{testProjectDir} が見つかりません。");

        // 共有ヘルパー以外で探索起点 API を使っているファイルを集める
        var violations = new List<string>();

        // テストプロジェクト配下の C# ソースを 1 件ずつ確認する
        foreach (var file in Directory.EnumerateFiles(testProjectDir, "*.cs", SearchOption.AllDirectories))
        {
            // ビルド生成物(obj/bin 配下の自動生成コード)は検査対象から外す
            if (IsBuildArtifact(file, testProjectDir)) continue;
            // 除外対象(共有ヘルパー本体と本テスト自身)は探索起点 API を書いてよい
            if (ExemptFileNames.Contains(Path.GetFileName(file), StringComparer.Ordinal)) continue;
            // ソースを読み込む
            var source = File.ReadAllText(file);
            // 探索起点 API を含まなければ問題なし
            if (!source.Contains(SearchRootApi, StringComparison.Ordinal)) continue;
            // 含んでいれば重複の芽として記録する
            violations.Add(Path.GetRelativePath(RepositoryPaths.Root, file));
        }

        // 違反ゼロであること(あればどのファイルかをメッセージで示す)
        Assert.True(violations.Count == 0,
            $"リポジトリ内のパス探索は {SharedHelperFileName} の {nameof(RepositoryPaths)} に集約してください "
            + $"(過去に同じ探索が 5 箇所へ複製され、目印の条件まで食い違っていました)。"
            + $"次のファイルが {SearchRootApi} を直接使っています:\n"
            + string.Join("\n", violations));
    }

    // obj / bin 配下(ビルド生成物)かどうかを判定する
    private static bool IsBuildArtifact(string filePath, string testProjectDir)
    {
        // テストプロジェクトからの相対パスをディレクトリ区切りで分解する
        var segments = Path.GetRelativePath(testProjectDir, filePath)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        // 途中に obj / bin があれば生成物とみなす
        return segments.Any(segment =>
            segment.Equals("obj", StringComparison.OrdinalIgnoreCase)
            || segment.Equals("bin", StringComparison.OrdinalIgnoreCase));
    }
}
