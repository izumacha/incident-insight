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
        // リポジトリルートの外を指すパスを作る(親へ 1 つ出てから別名のディレクトリへ入る)。
        // 実在しなくてよい。判定はファイルシステムを触らず文字列だけを見る
        var outsidePath = Path.Combine(Path.GetDirectoryName(RepositoryPaths.Root)!, "other-checkout", "bin", "x.cshtml");
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
        // 配線が切れたことに誰も気付けない(実測: 両方の .Where を外しても全件緑だった)
        var scanned = RepositoryPaths.EnumerateViewFiles()
            .Concat(RepositoryPaths.EnumerateWebSourceFiles())
            .ToList();
        // 「対象ゼロだから違反ゼロ」で緑にならないよう、まず列挙できていることを確かめる(fail-closed)
        Assert.True(scanned.Count > 0, "走査対象のファイルを 1 つも列挙できなかった。");
        // 生成物が 1 つでも混ざっていれば、どのファイルかを名指しして落とす
        var artifacts = scanned.Where(RepositoryPaths.IsBuildArtifact).ToList();
        Assert.True(
            artifacts.Count == 0,
            $"走査対象にビルド生成物が混ざっている: {string.Join(" / ", artifacts)}");
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
