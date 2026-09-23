// このテストクラスが属する名前空間(検査対象の ProjectLockFile と同じなので using は不要)
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// <see cref="ProjectLockFile.ReadEntries"/> の挙動を合成した JSON で固定する。
///
/// <para><b>なぜ実データでは足りないか。</b> この repo の 2 つの <c>packages.lock.json</c> には
/// <c>resolved</c> が JSON の <c>null</c> である項目が 1 つも無く、項目が 0 件のフレームワークも無い。
/// つまり「読めない形」と「正当に空な形」を切り分けている部分は実データでは一度も通らないので、
/// そこを潰しても全件緑のまま通る。とくに <c>resolved</c> が <c>null</c> の項目を
/// <c>Version = null</c> で返すようにすると、呼び出し側（<c>EfCorePackageAlignmentTests</c>）は
/// 「版を持たない項目」として<b>黙って読み飛ばす</b>ため、そのパッケージだけがメジャー版の
/// 揃え検査から消える（fail-open）。走査を共有ヘルパーへ出した以上、判定もここで固定する
/// （同じ理由で <see cref="CSharpLiteralTests"/> が兄弟の近似を固定している）。</para>
/// </summary>
public class ProjectLockFileTests
{
    // 合成したプロジェクトファイルの名前(PathFor がこの隣にロックファイルを置く)
    private const string SyntheticProjectFileName = "Synthetic.csproj";

    [Fact]
    public void ReadEntries_ReadsIdKindAndVersion()
    {
        // 直接参照と推移依存を 1 件ずつ持つロックファイルを組み立てる
        var entries = ReadSynthetic("""
            {"version":1,"dependencies":{"net8.0":{
              "Some.Direct":{"type":"Direct","requested":"[1.0.0, )","resolved":"1.0.0"},
              "Some.Transitive":{"type":"Transitive","resolved":"2.3.4"}
            }}}
            """);

        // 直接参照の項目が種類と版まで読めていること
        Assert.Contains(entries, e => e.Id == "Some.Direct" && e.Kind == "Direct" && e.Version == "1.0.0");
        // 推移依存の項目も同じく読めていること
        Assert.Contains(entries, e => e.Id == "Some.Transitive" && e.Kind == "Transitive" && e.Version == "2.3.4");
    }

    [Fact]
    public void ReadEntries_ReportsAMissingResolvedAsNull()
    {
        // ProjectReference の項目は resolved を持たない(これは正当な形)
        var entries = ReadSynthetic("""
            {"version":1,"dependencies":{"net8.0":{
              "someproject":{"type":"Project"}
            }}}
            """);

        // 版を持たない項目として返る(呼び出し側がこれを「対象外」として飛ばす)
        Assert.Null(Assert.Single(entries).Version);
    }

    [Fact]
    public void ReadEntries_ReportsAnExplicitNullResolvedAsEmpty_NotAsMissing()
    {
        // resolved が JSON の null になっている壊れた記録
        var entries = ReadSynthetic("""
            {"version":1,"dependencies":{"net8.0":{
              "Broken.Package":{"type":"Transitive","resolved":null}
            }}}
            """);

        // null ではなく空文字で返すこと。
        // 【なぜここが要点か】null を返すと呼び出し側が「版を持たない正当な項目」と同じ扱いで
        // 黙って飛ばし、そのパッケージが版の検査から消える。空文字なら、版を解釈する側が
        // どのパッケージかを名指しして落ちる(fail-closed)
        Assert.Equal("", Assert.Single(entries).Version);
    }

    [Fact]
    public void ReadEntries_ReportsAMissingTypeAsEmpty()
    {
        // type が無い項目(書式変更などで起こりうる)
        var entries = ReadSynthetic("""
            {"version":1,"dependencies":{"net8.0":{
              "No.Type":{"resolved":"1.0.0"}
            }}}
            """);

        // 空文字として返す。呼び出し側の「Direct と一致するか」の判定は一致せず、
        // 推移依存としても数えられないので、種類を根拠にする検査から静かに外れる形にはならない
        Assert.Equal("", Assert.Single(entries).Kind);
    }

    [Fact]
    public void ReadEntries_AcceptsAFrameworkWithNoPackages()
    {
        // PackageReference も ProjectReference も持たないプロジェクトのロックファイル
        var entries = ReadSynthetic("""{"version":1,"dependencies":{"net8.0":{}}}""");

        // 正当な状態なので落とさず、0 件として返す
        // (ここで落とすと、そういうプロジェクトを 1 つ足しただけで
        //  このファイルを読むすべての検査が「書式が変わった」という誤った原因で赤くなる)
        Assert.Empty(entries);
    }

    [Fact]
    public void ReadEntries_FailsWhenTheDependenciesKeyIsMissing()
    {
        // 解決結果をまとめるキーが無い = 書式が読めない形
        var error = Record.Exception(() => ReadSynthetic("""{"version":1}"""));

        // 黙って 0 件を返すと呼び出し側の検査が空振りするので、原因を名指しして落ちること
        Assert.NotNull(error);
        Assert.Contains(ProjectLockFile.DependenciesKey, error!.Message);
    }

    [Fact]
    public void ReadEntries_FailsWhenTheFileIsMissing()
    {
        // 実在しないパスを指す(ロックファイルがコミットされていない状態を模す)
        var missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ProjectLockFile.FileName);

        // 探した場所を添えて落ちること(移動・リネームと「探す起点がずれた」を切り分けられるように)
        var error = Record.Exception(() => ProjectLockFile.ReadEntries(missing));
        Assert.NotNull(error);
        Assert.Contains(missing, error!.Message);
    }

    // 合成した JSON を一時ファイルへ書き、ReadEntries に読ませる。
    // ReadEntries はパスを受け取る API なので、中身だけを渡す経路は用意していない
    // (本番の呼び出しと同じ入口を通すため)
    private static IReadOnlyList<ProjectLockFile.Entry> ReadSynthetic(string json)
    {
        // テストごとに衝突しない作業ディレクトリを作る
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            // 本物と同じ名前で置く(PathFor が組み立てる名前と揃える)
            var path = ProjectLockFile.PathFor(Path.Combine(directory, SyntheticProjectFileName));
            // 合成した中身を書き出す
            File.WriteAllText(path, json);
            // 本番と同じ入口から読む
            return ProjectLockFile.ReadEntries(path);
        }
        finally
        {
            // 成否にかかわらず作業ディレクトリを片付ける(§8 リソースを確実に解放する)
            Directory.Delete(directory, recursive: true);
        }
    }
}
