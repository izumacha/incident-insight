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
/// 目印は src/IncidentInsight.Web だけにする。下から上へ遡って最初に一致した階層を返すため、
/// 見つかるのは必ず「最も近い」= 本物のリポジトリルートであり、外側に同名の構成があっても
/// 手前で止まることはない。かつて 1 箇所だけが加えていた .github の条件は、この探索を
/// 厳しくする意味がない一方で、.github を含まない形でソースを展開した場合(git archive で
/// 書き出したツリーなど)に探索そのものを失敗させるため、採用しない。.github を実際に読む
/// EfCorePackageAlignmentTests は、そのファイルの存在を自分で Assert して落ちるので
/// 検出は失われない(むしろ「dependabot.yml が無い」と正確に報告される)。
/// </summary>
internal static class RepositoryPaths
{
    // ソースを収める最上位ディレクトリ名(リポジトリルートの目印)
    private const string SrcDirectoryName = "src";

    /// <summary>
    /// Web プロジェクトのディレクトリ名。リポジトリの構成を指す目印そのもので、
    /// この文字列をソースに書いてよいのはこのクラスだけ(RepositoryPathsUsageTests が
    /// それを検査するために、リテラルを書き写さずここから読む)。
    /// </summary>
    internal const string WebProjectDirectoryName = "IncidentInsight.Web";

    // Razor ビューを収めるディレクトリ名
    private const string ViewsDirectoryName = "Views";

    // テストプロジェクトを収める最上位ディレクトリ名
    private const string TestsDirectoryName = "tests";

    // リポジトリルートの絶対パス。探索は 1 回で済むので結果を保持する(§8)。
    // static readonly フィールドで直接初期化すると探索が型初期化子の中で走り、
    // 失敗時に下の DirectoryNotFoundException が TypeInitializationException に包まれて
    // 「型の初期化子が例外をスローしました」だけが見出しに出る。原因を名指しした
    // メッセージを呼び出し側にそのまま届けたいので Lazy で遅延させる
    private static readonly Lazy<string> RootDirectory = new(FindRoot);

    /// <summary>リポジトリルート(Web プロジェクトを直下に持つ階層)の絶対パス。</summary>
    public static string Root => RootDirectory.Value;

    /// <summary>Web プロジェクト(src/IncidentInsight.Web)の絶対パス。</summary>
    public static string WebProject => Path.Combine(Root, SrcDirectoryName, WebProjectDirectoryName);

    /// <summary>Razor ビュー(src/IncidentInsight.Web/Views)の絶対パス。</summary>
    public static string Views => Path.Combine(WebProject, ViewsDirectoryName);

    /// <summary>テストプロジェクトを収める階層(tests)の絶対パス。</summary>
    public static string TestsRoot => Path.Combine(Root, TestsDirectoryName);

    /// <summary>
    /// Razor ビュー(<c>Views</c> 配下の全 <c>.cshtml</c>)を再帰的に列挙する。
    ///
    /// View ソースを走査する guard-rail テスト(ChartAccessibilityTests /
    /// ConcurrencyTokenFormTests / RoleGatedNavigationTests / MeasurePrioritySelectTests)が
    /// 同じ列挙を各自で書いていたため、走査対象を変えるとき(例: Areas 配下の追加、
    /// 生成物ディレクトリの除外)に直し漏れたテストだけが静かに検査範囲を取り違える状態だった。
    /// 走査条件の唯一の源としてここに集約する(CLAUDE.md §6 DRY)。
    /// </summary>
    // Views 配下を再帰的に辿り .cshtml のパスを返す
    public static IEnumerable<string> EnumerateViewFiles() =>
        Directory.EnumerateFiles(Views, ViewFileSearchPattern, SearchOption.AllDirectories);

    // Razor ビューのファイル名パターン(走査条件の唯一の源)
    private const string ViewFileSearchPattern = "*.cshtml";

    // ビルド出力ディレクトリから上へ辿ってリポジトリルートを探す
    private static string FindRoot()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ファイルシステムのルートに達するまで親を遡る
        while (dir != null)
        {
            // Web プロジェクトを持つ最も近い階層がリポジトリルート
            if (Directory.Exists(Path.Combine(dir.FullName, SrcDirectoryName, WebProjectDirectoryName)))
            {
                // 見つかったのでその絶対パスを返す
                return dir.FullName;
            }
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException(
            $"リポジトリルート({SrcDirectoryName}/{WebProjectDirectoryName} を持つ階層)が"
            + $"テスト実行位置({AppContext.BaseDirectory})から見つかりません。");
    }
}
