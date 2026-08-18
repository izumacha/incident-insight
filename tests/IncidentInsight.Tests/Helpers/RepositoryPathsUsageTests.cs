// コメントを除去する前処理で正規表現を使うために取り込む
using System.Text.RegularExpressions;

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
// そこで「探索の起点になる API をテストソースで直接触るのは共有ヘルパーだけ」という形で
// 機械的に固定する。6 つ目のコピーはこのテストで落ちる。
public class RepositoryPathsUsageTests
{
    // 探索の起点として使える API 群。ここを直に触るのが重複の入口になる。
    // AppContext.BaseDirectory だけを見ていると、dotnet test では同じ場所を指す
    // Directory.GetCurrentDirectory() などで書かれた「同じ意味の重複」を取り逃がすため、
    // 起点になりうる API をまとめて見る
    private static readonly string[] SearchRootApis =
    {
        "AppContext.BaseDirectory",
        "Directory.GetCurrentDirectory()",
        "Environment.CurrentDirectory",
        "Assembly.Location",
    };

    // 検査対象から外すファイル(リポジトリルートからの相対パス)。
    // ファイル名だけで判定すると、別フォルダへ置いた同名のコピー
    // (Views/RepositoryPaths.cs など)まで免除されて検出網が素通りするため、
    // 「どこにある、どのファイルか」まで含めて指定する
    private static readonly string[] ExemptRelativePaths =
    {
        // 共有ヘルパー本体。ここだけが実際に探索を実装してよい
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPaths.cs"),
        // 本テスト自身。探す文字列そのものをソースに書く必要があるため除外する
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPathsUsageTests.cs"),
    };

    // ビルド生成物が置かれるディレクトリ名(走査対象から外す)
    private static readonly string[] BuildArtifactDirectoryNames = { "obj", "bin" };

    // 行コメント(// …)とブロックコメント(/* … */)を取り除くための正規表現。
    // CLAUDE.md §5 が 1 行ごとのコメントを求めている以上、「AppContext.BaseDirectory から遡る
    // 処理は集約済み」のような正確な説明文がコメントに現れるのは自然で、それを違反として
    // 報告すると正しいコードを直させることになる。判定はコードの部分だけで行う
    private static readonly Regex CommentRegex = new(
        @"//[^\r\n]*|/\*.*?\*/",
        RegexOptions.Singleline | RegexOptions.Compiled);

    [Fact]
    public void RepositorySearch_IsImplementedOnlyInSharedHelper()
    {
        // 走査対象のテストプロジェクトを共有ヘルパーから受け取る(パスの知識を二重に持たない)
        var testProjectDir = RepositoryPaths.TestProject;
        // 走査対象が実在すること(ディレクトリ改名でテストが無言で無効化されるのを防ぐ)
        Assert.True(Directory.Exists(testProjectDir), $"{testProjectDir} が見つかりません。");

        // 共有ヘルパー以外で探索起点 API を使っているファイルを集める
        var violations = new List<string>();
        // 除外指定が実際に使われたかを数える(パス変更で除外が空振りしていないかの確認用)
        var exemptionsApplied = 0;

        // テストプロジェクト配下の C# ソースを 1 件ずつ確認する
        foreach (var file in Directory.EnumerateFiles(testProjectDir, "*.cs", SearchOption.AllDirectories))
        {
            // ビルド生成物(obj / bin 配下の自動生成コード)は検査対象から外す
            if (IsBuildArtifact(file, testProjectDir)) continue;

            // リポジトリルートからの相対パスに直して除外リストと突き合わせる
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, file);
            // 除外対象(共有ヘルパー本体と本テスト自身)は探索起点 API を書いてよい
            if (ExemptRelativePaths.Contains(relativePath, StringComparer.Ordinal))
            {
                exemptionsApplied++;
                continue;
            }

            // ソースを読み込み、コメントを除いたコード部分だけを判定対象にする
            var code = CommentRegex.Replace(File.ReadAllText(file), string.Empty);
            // 探索起点 API を 1 つも含まなければ問題なし
            if (!SearchRootApis.Any(api => code.Contains(api, StringComparison.Ordinal))) continue;
            // 含んでいれば重複の芽として記録する
            violations.Add(relativePath);
        }

        // 除外リストが実際のファイル配置と一致していること
        // (ファイルを移動して除外が効かなくなると、本来の検査ではなく除外漏れで落ちて紛らわしい)
        Assert.True(exemptionsApplied == ExemptRelativePaths.Length,
            $"除外リストの {ExemptRelativePaths.Length} 件のうち {exemptionsApplied} 件しか実在しません。"
            + $"ファイルを移動・改名した場合は {nameof(ExemptRelativePaths)} も更新してください:\n"
            + string.Join("\n", ExemptRelativePaths));

        // 違反ゼロであること(あればどのファイルかをメッセージで示す)
        Assert.True(violations.Count == 0,
            $"リポジトリ内のパス探索は {nameof(RepositoryPaths)} に集約してください "
            + "(過去に同じ探索が 5 箇所へ複製され、目印の条件まで食い違っていました)。"
            + $"次のファイルが探索起点 API({string.Join(" / ", SearchRootApis)})を直接使っています:\n"
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
            BuildArtifactDirectoryNames.Contains(segment, StringComparer.OrdinalIgnoreCase));
    }
}
