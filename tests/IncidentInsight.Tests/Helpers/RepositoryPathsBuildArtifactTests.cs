// このテストクラスが属する名前空間(検査対象の RepositoryPaths と同じなので using は不要)
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// <see cref="RepositoryPaths.IsBuildArtifact"/> の判定そのものを固定する。
///
/// <para>この判定は走査系の guard-rail テストが共有しており、<b>誤ると検査範囲が
/// 黙って変わる</b>種類のもの: 生成物を取りこぼせば自動生成コードを違反として報告し、
/// 逆に本物のソースを生成物と誤判定すればそのファイルだけが検査から外れる
/// (どちらも「落ちない」側へ倒れうる)。共有する判定なので、判定自身にも検査を置く。</para>
///
/// <para><b>とくに「基準ルートの外のパス」を固定する。</b> <c>Path.GetRelativePath</c> は
/// 基準の外を指すと <c>..</c> を含む相対パスを返すため、分解されるセグメントが
/// リポジトリの外側のディレクトリ名まで広がる。そのまま通すと、そのパスだけが
/// 静かに走査対象から外れて緑のまま残る(issue #190)。実装は fail-closed にして
/// 呼び出し側の誤用として落とすので、その挙動をここで固定する。</para>
/// </summary>
public class RepositoryPathsBuildArtifactTests
{
    [Theory]
    // ビルド出力(bin)配下のファイルは生成物
    [InlineData("bin", "Debug", "App.dll")]
    // 中間出力(obj)配下のファイルも生成物
    [InlineData("obj", "Debug", "Generated.cs")]
    // 表記の揺れ(大文字)でも判定は変わらない
    [InlineData("Obj", "Debug", "Generated.cs")]
    public void BuildOutputDirectories_AreTreatedAsArtifacts(params string[] segmentsUnderWebProject)
    {
        // Web プロジェクト配下の絶対パスを組み立てる(実在しなくてよい。判定は文字列だけを見る)
        var path = CombineUnderWebProject(segmentsUnderWebProject);
        // 生成物として判定されることを確かめる
        Assert.True(
            RepositoryPaths.IsBuildArtifact(path),
            $"ビルド生成物として判定されるはずのパスが素通りした: {path}");
    }

    [Theory]
    // 通常のソースは生成物ではない
    [InlineData("Views", "Incidents", "Index.cshtml")]
    // ディレクトリ名の一部に bin を含むだけのものは巻き込まない(前方一致で判定していないこと)
    [InlineData("Binding", "Helper.cs")]
    // ファイル名が obj で始まるだけのものも巻き込まない
    [InlineData("Models", "object-map.cs")]
    public void SourceFiles_AreNotTreatedAsArtifacts(params string[] segmentsUnderWebProject)
    {
        // Web プロジェクト配下の絶対パスを組み立てる
        var path = CombineUnderWebProject(segmentsUnderWebProject);
        // 生成物ではないと判定されることを確かめる
        Assert.False(
            RepositoryPaths.IsBuildArtifact(path),
            $"ソースファイルがビルド生成物と誤判定された: {path}");
    }

    // Web プロジェクトを起点に絶対パスを組み立てる。起点は共有ヘルパーのプロパティから受け取り、
    // リポジトリ構成の目印(ディレクトリ名)をこのファイルへ書き写さない
    // (書き写すと RepositoryPathsUsageTests が落ちる。issue #164 の集約の趣旨そのもの)
    private static string CombineUnderWebProject(params string[] segmentsUnderWebProject) =>
        Path.Combine(RepositoryPaths.WebProject, Path.Combine(segmentsUnderWebProject));

    [Fact]
    public void PathsOutsideTheRepositoryRoot_AreRejected()
    {
        // リポジトリルートの親を取る。ルートがファイルシステムの最上位("/" 直下に展開した配置)
        // だと親が無いので、null 免除で NullReferenceException にせず前提崩れとして落とす
        var parentOfRoot = Path.GetDirectoryName(RepositoryPaths.Root);
        Assert.True(
            parentOfRoot is not null,
            $"リポジトリルート({RepositoryPaths.Root})に親ディレクトリが無いため、外を指すパスを組み立てられない。");
        // リポジトリルートの外を指すパスを作る(親へ 1 つ出てから別名のディレクトリへ入る)。
        // 実在しなくてよい。判定はファイルシステムを触らず文字列だけを見る
        var outsidePath = Path.Combine(parentOfRoot!, "other-checkout", "bin", "x.cshtml");
        // 前提が崩れた呼び出しは「黙って通す」のではなく例外で落ちることを確かめる
        var error = Assert.Throws<ArgumentException>(
            () => RepositoryPaths.IsBuildArtifact(outsidePath));
        // どのパスが問題なのかがメッセージから分かることまで求める(原因を指さない失敗を避ける)。
        // 例外の型が自動で付け足す情報ではなく、書いた文面そのものに載っていることを見る
        Assert.Contains(outsidePath, error.Message, StringComparison.Ordinal);
    }

    [Theory]
    // 親へ出る形(GetRelativePath は基準の外を必ずこの形で返す)
    [InlineData("../other/x.cshtml", true)]
    // 相対化できず絶対パスのまま返った形。**Linux では IsBuildArtifact 越しに作れない**
    // (Unix の絶対パスは必ず / を共有するので GetRelativePath が絶対パスを返さない)。
    // 実際に成立するのは Windows のドライブ違いだが、判定は「rooted かどうか」しか見ないので、
    // ここでは POSIX の絶対パスでその枝を固定する(ドライブ付きの文字列は Linux では
    // rooted と判定されず、この枝を通らない)
    [InlineData("/absolute/obj/x.cs", true)]
    // ルート自身を指す形("." は親へ出ていない)
    [InlineData(".", false)]
    // 通常の内側のパス
    [InlineData("src/Views/Index.cshtml", false)]
    // **既知の限界**: 正規化前の文字列は正しく判定できない。GetRelativePath の結果は
    // .. が先頭にまとまるので実際の入力では起きないが、別の作り方の相対パスを渡す利用側が
    // 現れたら正規化が要る、という境界をここで可視にしておく(docstring と対にしている)
    [InlineData("src/../../other/bin/x.cs", false)]
    public void PointsOutsideRoot_ClassifiesNormalizedRelativePaths(string relativePath, bool expected)
    {
        // 相対パスだけを見る純粋な判定なので、そのまま呼んで結果を突き合わせる
        Assert.Equal(expected, RepositoryPaths.PointsOutsideRoot(relativePath));
    }

    [Fact]
    public void RelativePaths_AreRejected()
    {
        // リポジトリ相対のパス。走査テストが Path.GetRelativePath(Root, file) で手元に持つ形で、
        // 誤って渡す経路が隣り合わせにある
        var relativePath = Path.Combine("src", "Views", "Index.cshtml");
        // 相対パスはテスト実行時のカレント(ビルド出力)基準で解決され、必ず bin を踏むため、
        // 黙って true を返さずに落ちることを確かめる
        var error = Assert.Throws<ArgumentException>(() => RepositoryPaths.IsBuildArtifact(relativePath));
        // どのパスが問題なのかがメッセージから分かることまで求める
        Assert.Contains(relativePath, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ScannedEnumerations_ExcludeBuildArtifacts()
    {
        // 走査系の列挙が実際にこの判定を通していることを見る。
        // **判定そのものの検査だけでは足りない**: 列挙側の .Where を外しても判定は正しいままなので、
        // 配線が切れたことに誰も気付けない(実測: .Where を外しても全件緑だった)。
        //
        // **候補ファイルは自分で用意する。** 実際のビルド出力に頼ると、ビュー側の配線が
        // 検査されないまま緑になる —— Razor SDK はビューをアセンブリへ取り込むので
        // obj / bin 配下に .cshtml は 1 つも現れず、EnumerateViewFiles の .Where を外しても
        // 拾える候補が存在しない(実測)。.cs の側がたまたま自動生成ファイル
        // (*.AssemblyInfo.cs 等)を持っているだけで、そちらも出力先の設定 1 つで空になりうる。
        // 生成物として扱われるディレクトリ名すべてに、ビューとソースの候補を 1 つずつ置く
        var probeViews = new List<string>();
        var probeSources = new List<string>();
        var probeDirectories = new List<string>();
        try
        {
            foreach (var artifactDirectoryName in RepositoryPaths.BuildArtifactDirectoryNames)
            {
                // 並行実行と後始末の取りこぼしに備えて、毎回一意な名前のディレクトリを使う
                var probeDirectory = Path.Combine(
                    RepositoryPaths.WebProject, artifactDirectoryName, $"scan-probe-{Guid.NewGuid():N}");
                // 生成物の配下に置くので、リポジトリの追跡対象にはならない(obj / bin は gitignore 済み)
                Directory.CreateDirectory(probeDirectory);
                // 後始末できるよう控えておく
                probeDirectories.Add(probeDirectory);
                // ビュー側の候補(EnumerateViewFiles が拾う拡張子)
                probeViews.Add(WriteProbe(probeDirectory, "ScanProbe.cshtml", "@* 走査から除外されることの確認用 *@"));
                // ソース側の候補(EnumerateWebSourceFiles が拾う拡張子)
                probeSources.Add(WriteProbe(probeDirectory, "ScanProbe.cs", "// 走査から除外されることの確認用"));
            }

            // 候補を全部置いてから列挙を 1 回ずつ回す。ディレクトリごとに回し直すと、
            // Web プロジェクト全体(ファイル数の多い obj 配下を含む)の再帰走査が
            // 回数分だけ増えるのに、得られる情報は変わらない
            var views = RepositoryPaths.EnumerateViewFiles().ToList();
            var sources = RepositoryPaths.EnumerateWebSourceFiles().ToList();
            // 列挙ごとに見る(まとめて見ると、片側の配線だけが切れたときにもう片側が隠す)
            AssertEnumerationExcludes(views, probeViews, nameof(RepositoryPaths.EnumerateViewFiles));
            AssertEnumerationExcludes(sources, probeSources, nameof(RepositoryPaths.EnumerateWebSourceFiles));
        }
        finally
        {
            // 検査が落ちても候補を残さない(次の実行に持ち越すと原因の切り分けが難しくなる)
            DeleteProbeDirectories(probeDirectories);
        }
    }

    [Fact]
    public void ScannedEnumerations_CoverTheWholeWebProject()
    {
        // 走査の「根」が Web プロジェクト全体であることを見る。
        // **除外の検査だけでは足りない**: 根を Views/ や Controllers/ へ狭めても、
        // 生成物配下に置いた候補はどのみち列挙されないので除外の検査は緑のまま通る(実測)。
        // 根が狭まるのは docstring が 2 段落を割いて説明している当の fail-open
        // (Areas/ や Pages/ の .cshtml が黙って検査対象から外れる)なので、対で固定する。

        // .cs 側は既存ファイルで足りる —— Web プロジェクト直下の Program.cs は、
        // 根をどのサブディレクトリへ狭めても真っ先に落ちる(候補を作らないので副作用も無い)
        var programPath = Path.Combine(RepositoryPaths.WebProject, "Program.cs");
        Assert.True(
            RepositoryPaths.EnumerateWebSourceFiles().Contains(programPath, StringComparer.Ordinal),
            $"{nameof(RepositoryPaths.EnumerateWebSourceFiles)} が Web プロジェクト直下の Program.cs を列挙しなかった。"
            + "走査の根がサブディレクトリへ狭まっている可能性がある。");

        // .cshtml 側は Views/ の外に 1 つも無いので、候補を置いて確かめるしかない。
        // 中身は Razor コメントだけにしてある —— 他のビュー走査テストが並行して
        // 列挙しても違反として拾わないため(実測で全件緑を確認)
        var probeDirectory = Path.Combine(RepositoryPaths.WebProject, $"scan-root-probe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(probeDirectory);
        try
        {
            // Views/ の外・かつ生成物ディレクトリの外に置くのが要点
            var probeView = WriteProbe(probeDirectory, "ScanRootProbe.cshtml", "@* 走査の根の確認用 *@");
            Assert.True(
                RepositoryPaths.EnumerateViewFiles().Contains(probeView, StringComparer.Ordinal),
                $"{nameof(RepositoryPaths.EnumerateViewFiles)} が Views/ の外に置いたビューを列挙しなかった: {probeView}。"
                + "走査の根が Views/ 配下へ狭まると、Areas/ や Pages/ のビューが黙って検査対象から外れる。");
        }
        finally
        {
            // 追跡対象になりうる場所に作るので、必ず消す
            DeleteProbeDirectories(new[] { probeDirectory });
        }
    }

    // 候補ファイルを 1 つ書き出し、その絶対パスを返す
    private static string WriteProbe(string directory, string fileName, string content)
    {
        // 置き場所と名前から絶対パスを組み立てる
        var path = Path.Combine(directory, fileName);
        // 中身は「何のためのファイルか」が分かる 1 行だけにする
        File.WriteAllText(path, content);
        // 呼び出し側が列挙結果と突き合わせられるようにパスを返す
        return path;
    }

    // 候補ディレクトリをすべて消す。**1 つの失敗で残りを諦めない** ——
    // 途中で例外を送出すると、残った候補がソースツリーに居座るうえ、
    // finally から投げた例外が本来の失敗メッセージを置き換えてしまう
    // (「配線が切れている」ではなく「削除できません」としか出なくなる)
    private static void DeleteProbeDirectories(IEnumerable<string> directories)
    {
        // 消せなかったものを控え、全部試してからまとめて報告する
        var undeleted = new List<string>();
        foreach (var directory in directories)
        {
            try
            {
                // 中のファイルごと消す
                Directory.Delete(directory, recursive: true);
            }
            catch (IOException error)
            {
                // 握り潰さず、どこがなぜ残ったのかを控える(§6 エラーを握り潰さない)
                undeleted.Add($"{directory} ({error.Message})");
            }
            catch (UnauthorizedAccessException error)
            {
                // 権限で消せない場合も同じ扱い
                undeleted.Add($"{directory} ({error.Message})");
            }
        }
        // 1 つでも残っていれば、次の実行に持ち越さないよう知らせる
        Assert.True(
            undeleted.Count == 0,
            $"検査用に作った候補ディレクトリを削除できなかった: {string.Join(" / ", undeleted)}");
    }

    // 列挙に「置いた候補」が 1 つも現れないことを確かめる。
    // 「対象ゼロだから違反ゼロ」で緑にならないよう、まず列挙できていること自体を見る(fail-closed)
    private static void AssertEnumerationExcludes(
        IReadOnlyCollection<string> files, IEnumerable<string> probePaths, string enumerationName)
    {
        // 1 件も列挙できていなければ、以降の判定は意味を持たないので前提崩れとして落とす
        Assert.True(files.Count > 0, $"{enumerationName} が 1 件も列挙しなかった。");
        // 生成物配下に置いた候補が出てくれば、除外の配線が切れている
        var leaked = probePaths.Where(probe => files.Contains(probe, StringComparer.Ordinal)).ToList();
        Assert.True(
            leaked.Count == 0,
            $"{enumerationName} がビルド生成物配下のファイルを列挙した: {string.Join(" / ", leaked)}");
    }

    [Fact]
    public void TheRootItself_IsNotTreatedAsAnArtifact()
    {
        // 境界値: 基準ルートそのものを渡すと相対パスは "." になる。
        // .. を含まないのでガードには当たらず、生成物でもないと判定されること
        Assert.False(
            RepositoryPaths.IsBuildArtifact(RepositoryPaths.Root),
            "リポジトリルート自身がビルド生成物と判定された。");
    }
}
