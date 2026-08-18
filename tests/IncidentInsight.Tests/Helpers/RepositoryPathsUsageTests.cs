// 探索パターンの照合に正規表現を使うために取り込む
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
// 何を「重複」とみなすか: 禁じたいのは API 名そのものではなく「起点となるディレクトリを
// 取得し、そこから親を遡る」という探索の形なので、
//   (1) 起点になりうる API(AppContext.BaseDirectory など)
//   (2) 親を遡る操作(.Parent / Directory.GetParent)
// の両方が同じファイルに現れることを違反とする。
//
// この条件にした理由は 2 つある。第一に、起点 API の出現だけを見ると、CLAUDE.md §5 が
// 求める説明コメントの中で API 名に言及しただけの正しいファイルまで違反になってしまう
// (コメントを機械的に除去する方法も試したが、文字列リテラルに "/*" や "//" を含む
// ファイルでコメント除去がコード本体を巻き込み、逆に違反を隠す穴になった)。
// 第二に、探索の形そのものを見るほうが、起点 API の綴りを変えただけの複製にも効く。
public class RepositoryPathsUsageTests
{
    // 探索の起点になりうる API。dotnet test ではいずれもテスト出力ディレクトリを指すため、
    // どれを使っても同じ探索が書けてしまう。綴りの揺れ(空白・改行)を許して照合する
    private static readonly Regex SearchRootApiRegex = new(
        @"\bAppContext\s*\.\s*BaseDirectory\b"
        + @"|\bAppDomain\s*\.\s*CurrentDomain\s*\.\s*BaseDirectory\b"
        + @"|\bDirectory\s*\.\s*GetCurrentDirectory\b"
        + @"|\bEnvironment\s*\.\s*CurrentDirectory\b"
        + @"|\bAssembly\s*\.\s*Location\b",
        RegexOptions.Compiled);

    // 親ディレクトリを遡る操作。起点 API と組み合わさって初めて「探索の複製」になる
    private static readonly Regex ParentWalkRegex = new(
        @"\.\s*Parent\b|\bDirectory\s*\.\s*GetParent\b",
        RegexOptions.Compiled);

    // 検査対象から外すファイル(リポジトリルートからの相対パス)。
    // ファイル名だけで判定すると、別フォルダへ置いた同名のコピー
    // (Views/RepositoryPaths.cs など)まで免除されて検出網が素通りするため、
    // 「どこにある、どのファイルか」まで含めて指定する
    private static readonly string[] ExemptRelativePaths =
    {
        // 共有ヘルパー本体。ここだけが実際に探索を実装してよい
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPaths.cs"),
        // 本テスト自身。探すパターンそのものをソースに書く必要があるため除外する
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPathsUsageTests.cs"),
    };

    // ビルド生成物が置かれるディレクトリ名(走査対象から外す)
    private static readonly string[] BuildArtifactDirectoryNames = { "obj", "bin" };

    [Fact]
    public void RepositorySearch_IsImplementedOnlyInSharedHelper()
    {
        // 走査対象は tests 配下の全テストプロジェクト。1 つに決め打ちすると、
        // 将来 2 つ目のテストプロジェクトが増えたときにそこだけ検査対象から漏れる
        // (RepositoryPaths は internal なので、別アセンブリからは見えず自前実装しやすい)
        var testsRoot = RepositoryPaths.TestsRoot;
        // 走査対象が実在すること(ディレクトリ改名でテストが無言で無効化されるのを防ぐ)
        Assert.True(Directory.Exists(testsRoot), $"{testsRoot} が見つかりません。");

        // 共有ヘルパー以外で探索を自前実装しているファイルを集める
        var violations = new List<string>();
        // 除外指定が実際に使われたかを数える(パス変更で除外が空振りしていないかの確認用)
        var exemptionsApplied = 0;

        // tests 配下の C# ソースを 1 件ずつ確認する
        foreach (var file in Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories))
        {
            // ビルド生成物(obj / bin 配下の自動生成コード)は検査対象から外す
            if (IsBuildArtifact(file, testsRoot)) continue;

            // リポジトリルートからの相対パスに直して除外リストと突き合わせる
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, file);
            // 除外対象(共有ヘルパー本体と本テスト自身)は探索を書いてよい
            if (ExemptRelativePaths.Contains(relativePath, StringComparer.Ordinal))
            {
                exemptionsApplied++;
                continue;
            }

            // ソースを読み込む
            var source = File.ReadAllText(file);
            // 起点 API と親を遡る操作の両方が揃ったときだけ「探索の複製」とみなす
            if (!SearchRootApiRegex.IsMatch(source) || !ParentWalkRegex.IsMatch(source)) continue;
            // 揃っていれば重複として記録する
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
            + "次のファイルが「起点ディレクトリの取得」と「親を遡る操作」を自前で組み合わせています:\n"
            + string.Join("\n", violations));
    }

    // obj / bin 配下(ビルド生成物)かどうかを判定する
    private static bool IsBuildArtifact(string filePath, string scanRoot)
    {
        // 走査の起点からの相対パスをディレクトリ区切りで分解する
        var segments = Path.GetRelativePath(scanRoot, filePath)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        // 途中に obj / bin があれば生成物とみなす
        return segments.Any(segment =>
            BuildArtifactDirectoryNames.Contains(segment, StringComparer.OrdinalIgnoreCase));
    }
}
