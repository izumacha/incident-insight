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
    /// Razor ビュー(Web プロジェクト配下の全 <c>.cshtml</c>。ビルド生成物は除く)を再帰的に列挙する。
    ///
    /// <para><b>Views/ 配下だけではない。</b> 以前は <c>Views</c> 配下に限っていたが、
    /// MVC の Areas(<c>Areas/&lt;Name&gt;/Views/</c>)や Razor Pages(<c>Pages/</c>)の
    /// <c>.cshtml</c> がその外にあり、走査対象から静かに外れていた(実測)。</para>
    ///
    /// View ソースを走査する guard-rail テスト(ChartAccessibilityTests /
    /// ConcurrencyTokenFormTests / RoleGatedNavigationTests / MeasurePrioritySelectTests)が
    /// 同じ列挙を各自で書いていたため、走査対象を変えるとき(例: Areas 配下の追加、
    /// 生成物ディレクトリの除外)に直し漏れたテストだけが静かに検査範囲を取り違える状態だった。
    /// 走査条件の唯一の源としてここに集約する(CLAUDE.md §6 DRY)。
    /// </summary>
    // Web プロジェクト配下を再帰的に辿り .cshtml のパスを返す(生成物は除く)。
    //
    // 【走査の根を Views/ から Web プロジェクト全体へ広げた経緯】以前は Views/ 配下だけを
    // 辿っていたが、これは fail-open だった: MVC の Areas(Areas/<Name>/Views/)や
    // Razor Pages(Pages/)配下の .cshtml は Views/ の外にあり、走査対象から静かに外れる
    // (実測: Pages/ に置いたビューが、これを使う全 guard-rail テストを素通りした)。
    // 取りこぼしたビューは「検査したつもりで検査していない」状態になり、
    // ConcurrencyTokenFormTests が守る楽観ロックの不変条件のように、失われても
    // 誰も気づけない性質のものが含まれる。現在 Views/ の外に .cshtml は 1 つも無いので
    // 挙動は変わらず、増えたときに自動的に検査対象へ入る
    public static IEnumerable<string> EnumerateViewFiles() =>
        Directory.EnumerateFiles(WebProject, ViewFileSearchPattern, SearchOption.AllDirectories)
            .Where(path => !IsBuildArtifact(path));

    // Web プロジェクト配下を再帰的に辿り .cs のパスを返す(生成物は除く)
    public static IEnumerable<string> EnumerateWebSourceFiles() =>
        Directory.EnumerateFiles(WebProject, SourceFileSearchPattern, SearchOption.AllDirectories)
            .Where(path => !IsBuildArtifact(path));

    /// <summary>
    /// ビルド生成物(obj / bin 配下)かどうかを返す。走査系のテストが共有する唯一の判定。
    ///
    /// <para>以前は走査するテストごとに書かれ、しかも条件が食い違っていた
    /// (一方はパスを区切って大文字小文字を無視して照合、もう一方は区切り文字を挟んだ
    /// 文字列の部分一致で大文字小文字を区別)。<c>Obj/</c> のような表記で判定が割れ、
    /// 片方だけが生成物を走査して生成コードを違反として報告しうる。判定はここ 1 か所に置く。</para>
    /// </summary>
    public static bool IsBuildArtifact(string filePath) =>
        // 判定は必ず「リポジトリルートからの相対パス」に対して行う。絶対パスを分解すると、
        // チェックアウト先の途中に obj / bin という名前のディレクトリがあるだけで
        // (例: /home/user/bin/incident-insight)全ファイルが生成物と判定され、
        // これを使う 5 つの走査テストが「対象が 1 つも無い」で一斉に落ちる——
        // しかも原因を指さないメッセージで落ちるので、追跡が難しい
        Path.GetRelativePath(Root, filePath)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(segment => BuildArtifactDirectoryNames.Contains(segment, StringComparer.OrdinalIgnoreCase));

    // ビルド生成物を収めるディレクトリ名(走査条件の唯一の源)
    private static readonly string[] BuildArtifactDirectoryNames = { "obj", "bin" };

    // Razor ビューのファイル名パターン(走査条件の唯一の源)
    private const string ViewFileSearchPattern = "*.cshtml";

    // C# ソースのファイル名パターン(走査条件の唯一の源)
    private const string SourceFileSearchPattern = "*.cs";

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
