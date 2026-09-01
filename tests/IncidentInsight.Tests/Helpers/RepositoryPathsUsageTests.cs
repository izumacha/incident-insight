// 目印の出現位置を判定するために正規表現を使う
using System.Text.RegularExpressions;

// このテストクラスが属する名前空間(検査対象の RepositoryPaths と同じなので using は不要)
namespace IncidentInsight.Tests.Helpers;

// Guard-rail test: Web プロジェクトの配置(src/IncidentInsight.Web)をパス文字列として
// 書いているのが <see cref="RepositoryPaths"/> だけであることを検査する。
// 「構成に関する知識すべて」ではなく、この目印 1 つに対象を限っている(下の「既知の限界」)。
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
// 判定は「目印がパス文字列の中に現れること」を直前の 1 文字(" / \)で見分ける。
// 名前空間参照(using IncidentInsight.Web.Models;)は直前が空白なので巻き込まない。
//
// 既知の限界: ルートの目印にソリューションファイル名を使う複製までは捕まえられない
// (EfCorePackageAlignmentTests が正当な用途で同じ名前を書いているため、そちらは見ない)。
public class RepositoryPathsUsageTests
{
    // 検査するパターン。目印が「パスの 1 区切り」として現れることを、前後の 1 文字で見分ける。
    // 前後とも引用符かパス区切り(" / \)であることを求めるので、次のように切り分けられる。
    //   検出する  "IncidentInsight.Web"          単独のセグメントとして書いた形
    //   検出する  "src/IncidentInsight.Web/Views" 1 つのリテラルへ繋げて書いた形
    //   検出する  @"src\IncidentInsight.Web"      逐語リテラルで区切りに \ を使った形
    //   見送る    using IncidentInsight.Web.Models;  名前空間参照(前が空白)
    //   見送る    <see cref="IncidentInsight.Web.Services.IClock"/>  型参照(後ろが . )
    //   見送る    Type.GetType("IncidentInsight.Web.Models.Incident") 型名(後ろが . )
    // 後ろ側も見るのは、CLAUDE.md §5 が求める XML ドキュメントの cref 参照を
    // 違反にしないため。前側だけで判定すると、パス探索をしていない正しいファイルを
    // 落としてしまい、逃げ道がファイル丸ごとの除外しか無くなる(除外は網に穴を開ける)。
    // 目印そのものは共有ヘルパーの定数から組み立て、リテラルを書き写さない
    private static readonly Regex LayoutMarkerRegex = new(
        "[\"/\\\\]" + Regex.Escape(RepositoryPaths.WebProjectDirectoryName) + "[\"/\\\\]",
        RegexOptions.Compiled);

    // 行全体がコメントの行(先頭の空白を除いて // で始まる行)を取り除くための正規表現。
    // 説明文の中で目印に触れただけの行を検査対象から外すために使う。
    // 「行全体がコメント」の行しか消さないので、コードを巻き込む余地が無い
    // (行末コメントやコード中の文字列は手を付けないため、"https://…" のような
    // リテラルの後ろに書いた違反を消してしまう心配も無い)
    private static readonly Regex WholeLineCommentRegex = new(
        @"^[ \t]*//.*$",
        RegexOptions.Multiline | RegexOptions.Compiled);

    // 検査対象から外すファイル(リポジトリルートからの相対パス)。
    // ファイル名だけで判定すると、別フォルダへ置いた同名のコピー
    // (Views/RepositoryPaths.cs など)まで免除されて検出網が素通りするため、
    // 「どこにある、どのファイルか」まで含めて指定する。
    // 本テスト自身はここに入れない。説明文で目印に触れてはいるが、それは
    // 行全体コメントの除去で外れるので、免除しなくても誤検出しない。
    // ファイル単位の免除はその中の違反も見えなくするため、1 件でも減らす
    private static readonly string[] ExemptRelativePaths =
    {
        // 共有ヘルパー本体。ここだけがリポジトリ構成の目印をコードに持ってよい
        Path.Combine("tests", "IncidentInsight.Tests", "Helpers", "RepositoryPaths.cs"),
    };


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
            if (RepositoryPaths.IsBuildArtifact(file)) continue;

            // リポジトリルートからの相対パスに直して除外リストと突き合わせる
            var relativePath = Path.GetRelativePath(RepositoryPaths.Root, file);
            // 除外対象(共有ヘルパー本体)は目印を書いてよい
            if (ExemptRelativePaths.Contains(relativePath, StringComparer.Ordinal))
            {
                // 除外が 1 件適用されたことを数える(下で件数の一致を確認するため)
                exemptionsApplied++;
                // 除外対象なので中身は見ずに次のファイルへ進む
                continue;
            }

            // ソースを読み込み、説明だけの行を落としてから判定する
            var code = WholeLineCommentRegex.Replace(File.ReadAllText(file), string.Empty);
            // 目印がパスの 1 区切りとして現れるかを見る
            if (!LayoutMarkerRegex.IsMatch(code)) continue;
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
            $"リポジトリ構成を指す {RepositoryPaths.WebProjectDirectoryName} をパス文字列に書いてよいのは {nameof(RepositoryPaths)} だけです "
            + "(過去に同じ探索が 5 箇所へ複製され、目印の条件まで食い違っていました)。"
            + $"必要なパスは {nameof(RepositoryPaths)} のプロパティから受け取ってください。次のファイルが目印を直接書いています:\n"
            + string.Join("\n", violations));
    }
}
