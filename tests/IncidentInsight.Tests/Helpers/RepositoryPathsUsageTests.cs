// このテストクラスが属する名前空間(検査対象の RepositoryPaths と同じなので using は不要)
namespace IncidentInsight.Tests.Helpers;

// Guard-rail test: リポジトリの構成(src/IncidentInsight.Web という配置)を知っているのが
// <see cref="RepositoryPaths"/> だけであることを検査する。
//
// 背景: ビルド出力から親を遡ってソースツリーを探すロジックは、集約するまでに
// テストプロジェクト内へ 5 箇所コピーされていた(issue #164)。しかも探す目印が
// 揃っておらず、4 箇所は src/IncidentInsight.Web だけ、1 箇所は .github も条件に
// 加えていた。コピーが増えても何も落ちないため重複は静かに育つ
// (実際、5 つ目を足した PR のコメント自体が「既存と同じ探索ロジック」と認めていた)。
//
// 何を見るか: 「探索の書き方」ではなく「リポジトリ構成の目印を書いていること」を見る。
// issue #164 が問題としたのは、目印(src/IncidentInsight.Web)を変えると 5 箇所すべてを
// 直す必要がある状態そのものだった。どんな書き方で親を遡ろうと
// (.Parent でも ".." 相対でも Path.GetDirectoryName の連鎖でも)、目的地を名指しする以上
// この目印だけは必ずソースに現れるため、書き方の揺れに左右されずに済む。
//
// なぜ探索 API 名を見ないのか: 最初は AppContext.BaseDirectory 等の出現で判定したが、
// それだと (a) 綴りを変えた複製や ".." 相対で遡る複製を取り逃がし、
// (b) 説明コメントで API 名に触れただけの正しいファイルを違反にしてしまい、
// (c) .Parent は CauseCategory.Parent というドメイン語彙でもあるため、
// パス探索をしていないテストまで巻き込む、という三方向の外れ方をした。
//
// 判定は「引用符で囲まれた文字列リテラル」に限る。日本語の説明文では
// src/IncidentInsight.Web のように引用符なしで書くため、コメントとは衝突しない。
//
// 既知の限界: ルートの目印にソリューションファイル名を使う複製までは捕まえられない
// (EfCorePackageAlignmentTests が正当な用途で同じ名前を書いているため、そちらは見ない)。
public class RepositoryPathsUsageTests
{
    // 検査対象のリテラル。共有ヘルパーの定数から組み立てるので、
    // この文字列そのものは本テストのソースには現れない(自分を違反として拾わずに済む)
    private static readonly string QuotedLayoutMarker = $"\"{RepositoryPaths.WebProjectDirectoryName}\"";

    // 検査対象から外すファイル(リポジトリルートからの相対パス)。
    // ファイル名だけで判定すると、別フォルダへ置いた同名のコピー
    // (Views/RepositoryPaths.cs など)まで免除されて検出網が素通りするため、
    // 「どこにある、どのファイルか」まで含めて指定する
    private static readonly string[] ExemptRelativePaths =
    {
        // 共有ヘルパー本体。ここだけがリポジトリ構成の目印を持ってよい
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPaths.cs"),
    };

    // ビルド生成物が置かれるディレクトリ名(走査対象から外す)
    private static readonly string[] BuildArtifactDirectoryNames = { "obj", "bin" };

    [Fact]
    public void RepositoryLayout_IsKnownOnlyToSharedHelper()
    {
        // 走査対象は tests 配下の全テストプロジェクト。1 つに決め打ちすると、
        // 将来 2 つ目のテストプロジェクトが増えたときにそこだけ検査対象から漏れる
        var testsRoot = RepositoryPaths.TestsRoot;
        // 走査対象が実在すること(ディレクトリ改名でテストが無言で無効化されるのを防ぐ)
        Assert.True(Directory.Exists(testsRoot), $"{testsRoot} が見つかりません。");

        // 共有ヘルパー以外でリポジトリ構成の目印を書いているファイルを集める
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
            // 除外対象(共有ヘルパー本体)は目印を書いてよい
            if (ExemptRelativePaths.Contains(relativePath, StringComparer.Ordinal))
            {
                exemptionsApplied++;
                continue;
            }

            // ソースを読み込み、目印が文字列リテラルとして現れるかを見る
            if (!File.ReadAllText(file).Contains(QuotedLayoutMarker, StringComparison.Ordinal)) continue;
            // 現れていれば、構成の知識がヘルパーの外へ漏れた状態として記録する
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
            $"リポジトリ構成を指す {QuotedLayoutMarker} をソースに書いてよいのは {nameof(RepositoryPaths)} だけです "
            + "(過去に同じ探索が 5 箇所へ複製され、目印の条件まで食い違っていました)。"
            + $"必要なパスは {nameof(RepositoryPaths)} のプロパティから受け取ってください。次のファイルが目印を直接書いています:\n"
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
