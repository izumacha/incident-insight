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
    /// <param name="filePath">
    /// <see cref="Root"/> そのものか、その配下にある<b>絶対</b>パス。
    /// <see cref="Root"/> 自身を渡した場合は「生成物ではない」と答える(相対パスが <c>"."</c> になり、
    /// 親へも出ていないため)。<b>相対パスは受け付けない</b>(下の例外を参照)。
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="filePath"/> が完全修飾のパスでないか、<see cref="Root"/> の外にあるとき。
    /// この判定は基準ルートが判定対象の祖先であることを前提にしており、外のパスでは
    /// リポジトリ外のディレクトリ名を見てしまう(理由は実装のコメント)。前提が崩れた呼び出しは
    /// 黙って通さず落とす(CLAUDE.md §9 の fail-closed)。
    /// </exception>
    public static bool IsBuildArtifact(string filePath)
    {
        // 【相対パスで呼ばれるのも前提崩れ】Path.GetRelativePath は相対の入力をプロセスの
        // カレントディレクトリ基準で解決する。テストのカレントはビルド出力
        // (tests/.../bin/Debug/net8.0)なので、リポジトリ相対のパスを渡すと
        // bin セグメントを踏んで**必ず生成物と判定される**(実測: "Views/Incidents/Index.cshtml"
        // が true)。しかも解決先は Root の内側に収まるため、下の「外を指しているか」の
        // ガードには当たらない。このリポジトリの走査テストは
        // Path.GetRelativePath(RepositoryPaths.Root, file) の値を手元に持っているので、
        // それを誤って渡す形は隣り合わせにある。完全修飾でなければここで落とす。
        //
        // **IsPathRooted ではなく IsPathFullyQualified を使う。** Windows の
        // ドライブ相対パス(C:Views\Index.cshtml のように、ドライブを指しつつ
        // そのドライブの現在のディレクトリからの相対)は IsPathRooted が true を返すが、
        // GetRelativePath は内部の GetFullPath でカレント基準に解決する。
        // つまり rooted で絞ると、このガードが塞ぐと宣言している当の事故が
        // 綴り違いのパス表記でそのまま再現する
        if (!Path.IsPathFullyQualified(filePath))
        {
            // 何が渡されたのかと、なぜ受け付けられないのかを添える
            throw new ArgumentException(
                "ビルド生成物の判定には完全修飾の絶対パスを渡してください。"
                + $"渡されたパス: {filePath}。"
                + "相対パスはテスト実行時のカレントディレクトリ(ビルド出力)を基準に解決されるため、"
                + "リポジトリ内のどのファイルを指していても生成物と判定されます(issue #190)。",
                nameof(filePath));
        }

        // 判定は必ず「リポジトリルートからの相対パス」に対して行う。
        //
        // 【集約で変えたのは基準にするルートだけ】統合前の実装も相対パス化はしており
        // (Path.GetRelativePath(scanRoot, filePath))、絶対パスをそのまま分解する版は
        // 一度も存在しない(履歴を走査して確認済み)。変わったのは基準が呼び出し側の走査起点
        // (tests 配下)から Root へ広がった点だけで、判定結果は変わらない
        // (Root を基準にした理由は上の summary が持つ。同じ説明を 2 か所に置かない)。
        var relativePath = Path.GetRelativePath(Root, filePath);

        // 【基準ルートは判定対象の祖先でなければならない】Root の内側のパスなら、Root までの
        // 祖先は共通の前置きとして取り除かれるので、分解されるセグメントはリポジトリ内の
        // ディレクトリ名だけになる(祖先の名前は .. にもならず、そもそも現れない。実測:
        // Root=/home/user/bin/incident-insight 配下の src/.../V.cshtml は src/.../V.cshtml)。
        // だから「リポジトリの祖先に bin という名前のディレクトリがある」配置そのものは
        // 問題にならず、下のガードにも当たらない。
        //
        // 一方 Root の外のパスを渡すと GetRelativePath は .. を含む相対パスを返し
        // (別ドライブなど共通の根を持たない場合は絶対パスをそのまま返す)、分解の対象が
        // リポジトリの外側のディレクトリ名まで広がる(実測: 同じ Root に対し
        // /home/other/bin/x.cshtml は ../../../other/bin/x.cshtml となり、リポジトリと
        // 無関係な bin セグメントで生成物と判定される)。誤判定されるのは渡したそのパスだけ
        // なので、走査テストからは「1 件だけ黙って対象から外れる」形になり、
        // 落ちずに検査範囲が縮む。
        //
        // この前提はコメントに書くだけにせず、ここで fail-closed にする
        // (CLAUDE.md §9「パスの判定は『不明なら拒否』をデフォルトにする」)。
        // 前提が崩れた呼び出しを黙って通すと、上のとおり縮んだ範囲が緑のまま残るため
        // ——「読んだ人が気付く」に頼らず、その場で原因を名指しして落とす。

        // 相対パスをディレクトリ区切りで分解する(外を指しているかの判定と生成物の判定で使い回す)
        var segments = SplitPathSegments(relativePath);
        if (PointsOutsideRoot(relativePath, segments))
        {
            // どのパスが、どの基準から外れたのかを名指しする(原因を指さないメッセージを避ける)。
            // filePath を文面へ埋めるのは、例外の型が持つ付加情報に頼らないため
            // ——頼ると「文面を空にしても気付けない」状態になり、型を替えただけで
            // 検査が落ちる(ガードの正しさと無関係な理由でテストを緩める動機ができる)
            throw new ArgumentException(
                $"ビルド生成物の判定はリポジトリルート({Root})の配下にあるパスにしか使えません。"
                + $"渡されたパス: {filePath}。"
                + $"外のパスを渡すと相対パス({relativePath})にリポジトリ外のディレクトリ名が現れ、"
                + "そのパスだけが黙って走査対象から外れます(issue #190)。",
                nameof(filePath));
        }

        // 途中に obj / bin があればビルド生成物とみなす(大文字小文字は区別しない)
        return segments.Any(segment => BuildArtifactDirectoryNames.Contains(segment, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// <b><see cref="Path.GetRelativePath"/> が返した</b>相対パスが、基準の外を指しているかを返す。
    ///
    /// <para><b>入力は正規化済みであることが前提。</b> <c>GetRelativePath</c> の結果は
    /// <c>..</c> が必ず先頭にまとまるので、先頭セグメントだけを見れば足りる。
    /// <b>任意の相対パスに対する一般の判定ではない</b> —— 途中に <c>..</c> を書いた
    /// 正規化前の文字列(<c>src/../../other/x.cs</c>)は「外を指していない」と答える(実測)。
    /// 正しく扱うには <c>Path.GetFullPath</c> で正規化することになるが、
    /// この判定の入力は <see cref="IsBuildArtifact"/> が作る <c>GetRelativePath</c> の結果
    /// 1 通りしか無いので、実在しない事情のために分岐を増やさない(CLAUDE.md §6)。
    /// 別の作り方の相対パスを渡す利用側が現れたら、そのときに正規化を足すこと。</para>
    ///
    /// <para><b>判定を切り出してあるのは、片方の条件が Linux では原理的に成立しないから。</b>
    /// Unix ではすべての絶対パスが <c>/</c> という共通の根を持つため
    /// <c>Path.GetRelativePath</c> が絶対パスを返すことは無く、<c>IsPathRooted</c> の側が
    /// 真になるのは Windows のドライブ違い(基準が <c>D:\</c>、対象が <c>C:\</c>)だけ。
    /// CI は ubuntu だけなので、<see cref="IsBuildArtifact"/> 越しに試そうとしても
    /// その枝には到達できず、<b>条件ごと消しても全件緑のまま通る</b>(実測)。
    /// 相対パスを直接受ける形にしておけば、rooted な文字列を渡してテストで固定できる。</para>
    /// </summary>
    internal static bool PointsOutsideRoot(string relativePath) =>
        // 分解はこの入口で 1 度だけ行い、判定そのものは下の実体へ渡す
        PointsOutsideRoot(relativePath, SplitPathSegments(relativePath));

    // 判定の実体。分解済みのセグメントを受け取るので、呼び出し側が既に分解していれば
    // 二度目の分解を避けられる(IsBuildArtifact は生成物の判定にも同じ配列を使う)
    private static bool PointsOutsideRoot(string relativePath, string[] segments) =>
        // 相対化できず絶対パスのまま返った(共通の根が無い)か、先頭が親ディレクトリを指すか
        Path.IsPathRooted(relativePath) || segments[0] == ParentDirectorySegment;

    // 相対パスをディレクトリ区切り(OS 既定と代替の両方)で分解する。
    // 判定と分解で 2 回書くと、区切りの扱いを直したとき片方だけが取り残される
    private static string[] SplitPathSegments(string path) =>
        path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    // 親ディレクトリを指す相対パスのセグメント。Root の外へ出たことの目印として使う
    private const string ParentDirectorySegment = "..";

    // ビルド生成物を収めるディレクトリ名(走査条件の唯一の源)。
    // internal なのは、列挙が実際にこの判定を通しているかを見る検査が、
    // ここへ候補ファイルを置いて確かめるため(ディレクトリ名を書き写させない)。
    // 読み取り専用で公開するのは、可変の配列だとアセンブリ内のどこからでも要素を
    // 差し替えられ、この判定を共有する全走査テストの範囲が実行順に依存して変わりうるため
    // (並列実行下では「違反ゼロ＝緑」で検出網が黙って無力化される)。
    // **型を IReadOnlyList にするだけでは足りない** —— 実体が配列のままだと
    // (string[]) へキャストして書き換えられるので、AsReadOnly でラップする
    internal static readonly IReadOnlyList<string> BuildArtifactDirectoryNames =
        Array.AsReadOnly(new[] { "obj", "bin" });

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
