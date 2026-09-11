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
    /// <para><b>Views/ 配下だけではない。</b> 以前は <c>Views</c> 配下に限っていたが、それは
    /// fail-open だった: MVC の Areas(<c>Areas/&lt;Name&gt;/Views/</c>)や Razor Pages
    /// (<c>Pages/</c>)の <c>.cshtml</c> は <c>Views</c> の外にあり、走査対象から静かに外れる
    /// (実測: <c>Pages/</c> に置いたビューが、これを使う全 guard-rail テストを素通りした)。
    /// 取りこぼしたビューは「検査したつもりで検査していない」状態になり、楽観ロックの
    /// 不変条件のように、失われても誰も気づけない性質のものが含まれる。現在 <c>Views</c> の外に
    /// <c>.cshtml</c> は 1 つも無いので挙動は変わらず、増えたときに自動的に検査対象へ入る。</para>
    ///
    /// View ソースを走査する guard-rail テストが同じ列挙を各自で書いていたため、走査対象を
    /// 変えるとき(例: Areas 配下の追加、生成物ディレクトリの除外)に直し漏れたテストだけが
    /// 静かに検査範囲を取り違える状態だった。走査条件の唯一の源としてここに集約する
    /// (CLAUDE.md §6 DRY)。
    ///
    /// <para><b>利用側はここに書き並べない。</b> 誰が使っているかは参照を辿れば分かる一方、
    /// 書き並べた一覧は利用側が増えるたびに古くなり、しかも<b>古くなったことに誰も気付けない</b>
    /// (実測: 一覧が 4 件を名指ししていた時点で、実際の利用側は 6 件あった)。
    /// 走査範囲を狭めようとした人が短い一覧を読み、そこに無いテストを「影響しない」と
    /// 結論すると、そのテストの Razor 側カバレッジだけが黙って縮む——
    /// 走査の根を広げて塞いだ fail-open が失われるのに、テストは緑のまま。
    /// 同じ理由で <c>IncidentControllerHelpers</c> のクラス docstring からも利用側の列挙を
    /// 取り除いてある(issue #190)。</para>
    /// </summary>
    // Web プロジェクト配下を再帰的に辿り .cshtml のパスを返す(生成物は除く)。
    // 走査の根を Views/ ではなく Web プロジェクト全体にしている理由は上の docstring が持つ
    // (同じ説明を 2 か所に置くと、根を変えたときに片方だけが古くなる)
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
    /// <para>元は走査するテストのうち 1 つ(<c>RepositoryPathsUsageTests</c>)だけが持っており、
    /// 基準にする走査起点を引数で受け取っていた。共有ヘルパーが <c>tests</c> の外
    /// (Web プロジェクト)も走査するようになり、判定を使う側が増えたため、
    /// 基準を <see cref="Root"/> に固定したうえでここ 1 か所へ移した。</para>
    /// </summary>
    public static bool IsBuildArtifact(string filePath) =>
        // 判定は必ず「リポジトリルートからの相対パス」に対して行う。
        //
        // 【集約で変えたのは基準にするルートだけ】統合前の実装も相対パス化はしており
        // (Path.GetRelativePath(scanRoot, filePath))、絶対パスをそのまま分解する版は
        // 一度も存在しない(履歴を走査して確認済み)。変わったのは基準が呼び出し側の走査起点
        // (tests 配下)から Root へ広がった点だけで、判定結果は変わらない。Root にしたのは、
        // 共有ヘルパーが tests の外(Web プロジェクト)も走査するようになり、
        // 両方の走査起点を内側に持つ階層でなければ基準にできなくなったため。
        //
        // 【基準ルートは判定対象の祖先でなければならない】Root の内側のパスなら、分解される
        // セグメントはリポジトリ内のディレクトリ名だけになる。Root の外のパスを渡すと
        // GetRelativePath は .. を含む相対パスを返し、分解の対象がリポジトリの外側の
        // ディレクトリ名まで広がる(実測: Root=/home/user/bin/incident-insight に対し
        // /home/other/bin/x.cshtml は ../../../other/bin/x.cshtml となり、
        // リポジトリと無関係な bin セグメントで生成物と判定される)。
        // 誤判定されるのは渡したそのパスだけなので、走査テストから見ると
        // 「1 件だけ黙って対象から外れる」形になり、落ちずに検査範囲が縮む。
        // したがって **この判定を Root の外のパスへ再利用しないこと**
        // (セグメント分割はどんな基準パスに対しても安全、ではない。issue #190)。
        // なお「リポジトリの祖先に bin という名前のディレクトリがある」配置
        // (/home/user/bin/incident-insight そのもの)は問題にならない——
        // 祖先は相対パス化で .. に畳まれるため、セグメントとして現れない(実測)
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
