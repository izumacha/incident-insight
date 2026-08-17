// packages.lock.json を読むために取り込む
using System.Text.Json;
// dependabot.yml のパターン照合に正規表現を使うため取り込む
using System.Text.RegularExpressions;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Packaging;

// Guard-rail test: EF Core 系 NuGet パッケージのメジャー版が全プロジェクトで揃っていることを検査する。
//
// 背景: このアプリは DB プロバイダ非依存(SQLite / SQL Server / PostgreSQL を Database:Provider で
// 実行時切替)で、各プロバイダ実装は EF Core 本体(Microsoft.EntityFrameworkCore.Relational)と
// 同じメジャー版でしか動作保証がない。ところが一部のパッケージだけメジャー版を上げても、
//   - ビルドは通る(NuGet は Relational を最も高い版へ解決するだけ)
//   - テストも通る(テストは InMemory / SQLite しか触らず、PostgreSQL 経路を実行しない)
// ため、「PostgreSQL 配備でだけ実行時に壊れる」という無言の破壊になる。
// 実際、Dependabot の既定(major は個別 PR)ではプロバイダごとに 1 本ずつ PR が作られ、
// どれか 1 本をマージした時点でこの状態になっていた。
//
// 対策は 2 段構え。
//   (1) .github/dependabot.yml の nuget-ef-core / nuget-ef-core-security グループが
//       major も含めて 1 本の PR に束ねる(予防)
//   (2) 本テストが版ズレそのものを検出する(手動編集や設定変更で束ねが外れた場合の最後の砦)
//
// 【なぜ csproj ではなく packages.lock.json を読むのか】
// 壊れる仕組みは「Sqlite を上げると Relational が"推移的に"上がる」ことであり、Relational は
// どの csproj にも直接書かれていない。csproj の <PackageReference> だけを見ると、まさに
// 破壊の主役である推移依存が視野に入らない。ロックファイルは直接参照と推移依存の両方について
// 「実際に解決された版」を持つ唯一の記録で、両プロジェクトとも RestorePackagesWithLockFile で
// 生成・コミット済み、CI は locked-mode restore で一致を強制している。属性の書き順など
// csproj の記述ゆれにも影響されない。
//
// 「EF Core 系とは何か」の定義は dependabot.yml のグループ patterns を唯一の真実の源として読む。
// ここへ書き写すと、パッケージを 1 つ足したときに片方だけ更新されて検出網に穴が空くため(§6)。
// パターン側を削って検出網を無効化することもできてしまうので、逆向きの網羅性
// (EntityFrameworkCore を名前に含むパッケージがすべてパターンに拾われていること)も併せて固定する。
public class EfCorePackageAlignmentTests
{
    // dependabot.yml で EF Core 系の「通常の版更新」を束ねているグループ名
    private const string EfCoreGroupName = "nuget-ef-core";

    // 同じく「セキュリティ更新」を束ねているグループ名。
    // グループの applies-to は既定が version-updates で、セキュリティ更新には及ばない。
    // 片方だけだと CVE 対応の更新がパッケージ単位の PR として現れ、束ねを迂回してしまう
    private const string EfCoreSecurityGroupName = "nuget-ef-core-security";

    // minor / patch をまとめているグループ名(EF Core 系を除外していることを確認する対象)
    private const string MinorAndPatchGroupName = "nuget-minor-and-patch";

    // グループが束ねる対象を並べる YAML キー名
    private const string PatternsKey = "patterns";

    // グループが束ねから外す対象を並べる YAML キー名
    private const string ExcludePatternsKey = "exclude-patterns";

    // グループの適用対象(通常の版更新 / セキュリティ更新)を指定する YAML キー名
    private const string AppliesToKey = "applies-to";

    // 更新設定エントリがどのパッケージ管理系を対象にするかを指定する YAML キー名
    private const string EcosystemKey = "package-ecosystem";

    // グループ定義をまとめる YAML キー名
    private const string GroupsKey = "groups";

    // EF Core 系グループが属していなければならないエコシステム(.NET のパッケージ管理系)
    private const string NuGetEcosystem = "nuget";

    // 通常の版更新を表す applies-to の値
    private const string VersionUpdates = "version-updates";

    // セキュリティ更新を表す applies-to の値
    private const string SecurityUpdates = "security-updates";

    // 「EF Core 系のはずなのにパターンから漏れている」を検出するための目印。
    // EF Core 連携パッケージの ID は慣例として、この 2 つのどちらかを含む。
    //   - EntityFrameworkCore: Microsoft.EntityFrameworkCore.* / Npgsql.EntityFrameworkCore.PostgreSQL /
    //                          Pomelo.EntityFrameworkCore.MySql など
    //   - EFCore            : EFCore.NamingConventions / EFCore.BulkExtensions など、EF Core の
    //                          メジャー版に厳密追随する周辺パッケージ
    // 前者だけを目印にすると後者の系統が丸ごと検査対象から外れる(片方が他方の部分文字列では
    // ないため、両方を並べる必要がある)
    private static readonly string[] EfCoreIdMarkers = { "EntityFrameworkCore", "EFCore" };

    // NuGet が解決済みの版を記録するロックファイルの名前
    private const string LockFileName = "packages.lock.json";

    // 「このリポジトリのプロジェクト」の正本。CI の dotnet restore / build / test もこれを対象にする
    private const string SolutionFileName = "IncidentInsight.sln";

    // ソリューションファイルからプロジェクトの相対パスを抜き出す正規表現。
    // 行の形は Project("{型GUID}") = "表示名", "相対パス.csproj", "{GUID}"
    private static readonly Regex SolutionProjectRegex =
        new(@"""(?<path>[^""]+\.csproj)""", RegexOptions.None);

    // EF Core 系グループに書いてよいキー。
    // 【なぜ限定するか】patterns と applies-to が正しくても、同じグループに update-types や
    // exclude-patterns を足せば束ねる範囲を後から狭められる(例: update-types を minor/patch に
    // すると major が再びプロバイダごとの単独 PR に戻り、この PR が防いだ状態そのものに戻る)。
    // 「何が書いてあるか」だけでなく「他に何も書かれていないこと」まで固定する
    private static readonly string[] AllowedEfCoreGroupKeys = { AppliesToKey, PatternsKey };

    // リポジトリルート。走査のたびに親を遡り直す必要はないので一度だけ解決して使い回す(§8)
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    // dependabot.yml の中身。1 回のテスト実行で何度も読み直さないよう遅延初期化で 1 度だけ読む(§8)
    private static readonly Lazy<string[]> DependabotLines = new(ReadDependabotLines);

    // nuget エコシステムの groups: 配下の行。グループ探索のたびに切り出し直さないよう共有する(§8)
    private static readonly Lazy<List<string>> NuGetGroupsBlock = new(ReadNuGetGroupsBlock);

    // ソリューションに登録されたプロジェクトの絶対パス一覧(複数のテストで共有する)
    private static readonly Lazy<IReadOnlyList<string>> SolutionProjects = new(ReadSolutionProjects);

    // 解決済みパッケージの一覧。ロックファイルの読み取りを複数のテストで共有する(§8)
    private static readonly Lazy<IReadOnlyList<ResolvedPackage>> ResolvedPackages = new(ReadAllResolvedPackages);

    // ロックファイル 1 行分の情報(どのプロジェクトの・どのパッケージが・直接か推移か・どの版か)
    private readonly record struct ResolvedPackage(string Project, string Id, string Kind, string Version);

    [Fact]
    public void EfCorePackages_ShareTheSameMajorVersion()
    {
        // dependabot.yml が定める「EF Core 系」の判定パターンを読み出す
        var patterns = ReadGroupList(EfCoreGroupName, PatternsKey);
        // 全ロックファイルから EF Core 系として解決されているパッケージだけを集める
        var efCorePackages = ResolvedPackages.Value
            .Where(package => MatchesAnyPattern(package.Id, patterns))
            .ToList();

        // 1 件も見つからないのは検出網の劣化(ロックファイルの書式変更・探索漏れ)を疑うべき状態
        Assert.True(efCorePackages.Count > 0,
            $"EF Core 系のパッケージが {LockFileName} から 1 件も見つかりませんでした。"
            + "ロックファイルの配置・書式か dependabot.yml の patterns が変わった可能性があります。");

        // 版のメジャー番号だけを取り出して重複を除く(9.0.19 と 9.0.20 は「揃っている」とみなす。
        // EF Core が動作保証を切るのはメジャー版の食い違いで、パッチ差は問題にならないため)
        var majors = efCorePackages.Select(MajorVersionOf).Distinct().ToList();

        // メジャー版が 1 種類であること(2 種類以上あれば、どれがどの版かを添えて落とす)
        Assert.True(majors.Count == 1,
            "EF Core 系パッケージのメジャー版が揃っていません。プロバイダ実装は EF Core 本体と同じ"
            + "メジャー版でしか動作保証がなく、揃っていない組み合わせは PostgreSQL 配備でだけ実行時に壊れます"
            + "(ビルドもテストも通るため気付けません)。全て同時に上げてください:\n"
            + Describe(efCorePackages));
    }

    [Fact]
    public void DependabotPatterns_CoverEveryEntityFrameworkCorePackage()
    {
        // dependabot.yml が定める「EF Core 系」の判定パターンを読み出す
        var patterns = ReadGroupList(EfCoreGroupName, PatternsKey);
        // 名前から EF Core 系と分かるのに、パターンに拾われていないパッケージを集める
        var uncovered = ResolvedPackages.Value
            .Where(package => EfCoreIdMarkers.Any(marker =>
                package.Id.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            .Where(package => !MatchesAnyPattern(package.Id, patterns))
            .DistinctBy(package => package.Id)
            .ToList();

        // 漏れが無いこと。これが無いと、パターンからパッケージを 1 行消すだけで
        // 「そのパッケージは EF Core 系ではない」ことになり、上の版揃えテストも
        // Dependabot の束ねも同時に無効化できてしまう(検出網の自己無効化を防ぐ)
        Assert.True(uncovered.Count == 0,
            $"名前に {string.Join(" / ", EfCoreIdMarkers)} を含むのに dependabot.yml の "
            + $"{EfCoreGroupName}.{PatternsKey} で拾われていないパッケージがあります。"
            + "パターンから外すと版揃えの検査対象からも外れ、"
            + "Dependabot も単独の major PR を作るようになります。パターンへ追加してください:\n"
            + Describe(uncovered));
    }

    [Fact]
    public void EveryProject_HasCommittedLockFile()
    {
        // ソリューションに登録されたプロジェクトを対象にする。
        // 【なぜリポジトリ全走査ではないか】*.csproj をリポジトリ全体から拾うと node_modules や
        // ベンダーディレクトリに紛れ込んだ第三者の csproj まで対象になり、開発者が直しようのない
        // ファイルを指して CI が赤くなる。CI が restore / build / test する範囲＝ソリューションを
        // 正本にすれば、検査対象と「ロックが強制される範囲」が原理的に一致する
        var projects = SolutionProjects.Value;

        // 隣にロックファイルが無いプロジェクト(＝版の記録が残らないプロジェクト)を集める
        var missing = projects
            .Where(project => !File.Exists(Path.Combine(Path.GetDirectoryName(project)!, LockFileName)))
            .Select(project => Path.GetRelativePath(RepositoryRoot, project))
            .ToList();

        // 漏れが無いこと。ロックファイルが無いプロジェクトは、この検査の対象から外れるだけでなく
        // CI の locked-mode restore もすり抜ける(RestorePackagesWithLockFile を宣言していない
        // プロジェクトに対して dotnet restore --locked-mode はロックファイルを作らず正常終了する)。
        // つまり EF Core 9 を参照する新プロジェクトを足すと、版ズレが誰にも気付かれないまま通る
        Assert.True(missing.Count == 0,
            $"{LockFileName} が無いプロジェクトがあります。ロックファイルが無いと本テストの検査対象から"
            + "外れるうえ、CI の locked-mode restore もすり抜けます(未宣言のプロジェクトに対しては"
            + "ロックファイルを生成せず正常終了するため)。csproj に RestorePackagesWithLockFile を"
            + "追加して restore し、生成されたロックファイルをコミットしてください:\n"
            + string.Join("\n", missing.Select(path => $"  {path}")));
    }

    [Fact]
    public void DependabotConfig_BundlesEfCorePackagesForVersionAndSecurityUpdates()
    {
        // 通常の版更新を束ねるグループの対象一覧
        var versionUpdatePatterns = ReadGroupList(EfCoreGroupName, PatternsKey);
        // セキュリティ更新を束ねるグループの対象一覧
        var securityUpdatePatterns = ReadGroupList(EfCoreSecurityGroupName, PatternsKey);
        // minor / patch グループが束ねから外している一覧
        var excludedPatterns = ReadGroupList(MinorAndPatchGroupName, ExcludePatternsKey);

        // 3 つの一覧が同じ集合であること。どれか 1 つにだけパッケージを足すと、その
        // パッケージは更新の種類(minor / major / セキュリティ)によって入るグループが変わり、
        // 結局どこかの経路だけが単独 PR に戻ってしまう。
        // 並び順は Dependabot の挙動に影響しないため集合として比較する(整列しただけで CI が
        // 赤くなると、規約が守られていないのではなく検査が硬すぎるという偽陽性になる)
        AssertSameSet($"{EfCoreGroupName}.{PatternsKey}", versionUpdatePatterns,
            $"{EfCoreSecurityGroupName}.{PatternsKey}", securityUpdatePatterns);
        AssertSameSet($"{EfCoreGroupName}.{PatternsKey}", versionUpdatePatterns,
            $"{MinorAndPatchGroupName}.{ExcludePatternsKey}", excludedPatterns);

        // 2 つのグループが実際に別々の更新種別を受け持っていること。
        // applies-to の既定は version-updates なので、セキュリティ側で指定を忘れると
        // 両グループとも通常の版更新を見に行き、CVE 対応の更新が束ねを素通りする
        Assert.Equal(VersionUpdates, ReadGroupScalar(EfCoreGroupName, AppliesToKey));
        Assert.Equal(SecurityUpdates, ReadGroupScalar(EfCoreSecurityGroupName, AppliesToKey));

        // 束ねる範囲を後から狭めるキーが足されていないこと。
        // patterns が正しくても update-types や exclude-patterns を書き足せば束ねを骨抜きにできる
        // (update-types: [minor, patch] にすると major が再びプロバイダごとの単独 PR に戻る)
        AssertOnlyAllowedKeys(EfCoreGroupName);
        AssertOnlyAllowedKeys(EfCoreSecurityGroupName);
    }

    // EF Core 系グループに、許可したキー以外が書かれていないことを確認する
    private static void AssertOnlyAllowedKeys(string groupName)
    {
        // そのグループ直下に書かれているキーのうち、許可一覧に無いものを集める
        var unexpected = ReadGroupKeys(groupName)
            .Where(key => !AllowedEfCoreGroupKeys.Contains(key, StringComparer.Ordinal))
            .ToList();

        // 余計なキーが無いこと(あれば、どのキーが束ねを狭めうるかを示す)
        Assert.True(unexpected.Count == 0,
            $"dependabot.yml の {groupName} に想定外のキーがあります: [{string.Join(", ", unexpected)}]\n"
            + $"このグループは EF Core 系を「全ての更新をまとめて 1 本の PR にする」ために置いています。"
            + $"{ExcludePatternsKey} や update-types を足すと束ねる範囲が狭まり、"
            + "プロバイダごとの単独 PR が再び作られるようになります"
            + $"(書いてよいのは {string.Join(" / ", AllowedEfCoreGroupKeys)} だけです)。");
    }

    // 2 つのパターン一覧が同じ集合であることを確認する。違えば「どちらにだけ有るか」を示して落とす
    private static void AssertSameSet(string leftName, IReadOnlyList<string> left, string rightName, IReadOnlyList<string> right)
    {
        // NuGet のパッケージ ID は大文字小文字を区別しないため、比較も区別しない集合にする
        var leftSet = new HashSet<string>(left, StringComparer.OrdinalIgnoreCase);
        // 比較相手も同じ規則の集合にする
        var rightSet = new HashSet<string>(right, StringComparer.OrdinalIgnoreCase);
        // 左にしか無いものを列挙する
        var onlyLeft = leftSet.Except(rightSet, StringComparer.OrdinalIgnoreCase).ToList();
        // 右にしか無いものを列挙する
        var onlyRight = rightSet.Except(leftSet, StringComparer.OrdinalIgnoreCase).ToList();

        // 差が無いこと(あれば、どちらにだけ有るのかを具体的に示す)
        Assert.True(onlyLeft.Count == 0 && onlyRight.Count == 0,
            $"dependabot.yml の {leftName} と {rightName} の対象が一致していません。"
            + "EF Core 系を追加・削除するときは両方を同じ内容に保ってください:\n"
            + $"  {leftName} にのみ有り : [{string.Join(", ", onlyLeft)}]\n"
            + $"  {rightName} にのみ有り: [{string.Join(", ", onlyRight)}]");
    }

    // 失敗メッセージ用に「どのプロジェクトの・どのパッケージが・直接か推移か・どの版か」を並べる
    private static string Describe(IEnumerable<ResolvedPackage> packages) =>
        // 1 件 1 行の読みやすい形へ整形する
        string.Join("\n", packages.Select(p => $"  {p.Project}: {p.Id} = {p.Version} ({p.Kind})"));

    // 版文字列("8.0.29" など)からメジャー番号を取り出す。解釈できない形式は
    // 黙って 0 として扱わず、どのパッケージが原因かを示して失敗させる(fail-closed)
    private static int MajorVersionOf(ResolvedPackage package)
    {
        // '.' より前の部分がメジャー番号にあたる(区切りが無ければ全体を見る)
        var head = package.Version.Split('.')[0];
        // 数値として解釈できることを確認しつつ値を得る
        Assert.True(int.TryParse(head, out var major),
            $"{package.Project} の {package.Id} のバージョン \"{package.Version}\" からメジャー番号を読み取れませんでした。");
        // 読み取れたメジャー番号を返す
        return major;
    }

    // パッケージ ID が patterns のいずれかに当てはまるかを判定する。
    // dependabot の patterns は末尾 '*' のワイルドカードを使うため、正規表現へ変換して照合する
    // (パターンはリポジトリ内の設定ファイル由来で外部入力ではないが、記号は必ずエスケープする)
    private static bool MatchesAnyPattern(string packageId, IReadOnlyList<string> patterns) =>
        // いずれか 1 つでも一致すれば EF Core 系とみなす
        patterns.Any(pattern => Regex.IsMatch(
            packageId,
            // '*' だけをワイルドカードとして扱い、それ以外の記号は literal として扱う
            "^" + string.Join(".*", pattern.Split('*').Select(Regex.Escape)) + "$",
            // NuGet のパッケージ ID は大文字小文字を区別しないため、照合も区別しない
            RegexOptions.IgnoreCase));

    // ソリューションに登録された全プロジェクトの packages.lock.json から、解決済みパッケージを
    // 漏れなく読み出す。プロジェクトを増やしたときに一覧へ追記し忘れて検査対象から外れる事故は、
    // 探索元をソリューション(CI が restore する範囲そのもの)にすることで防ぐ
    private static IReadOnlyList<ResolvedPackage> ReadAllResolvedPackages()
    {
        // 見つかったパッケージを溜める入れ物
        var packages = new List<ResolvedPackage>();
        // 各プロジェクトの隣にあるロックファイルを 1 つずつ読む
        foreach (var projectFile in SolutionProjects.Value)
        {
            // プロジェクトと同じディレクトリのロックファイルを指す
            var lockFile = Path.Combine(Path.GetDirectoryName(projectFile)!, LockFileName);
            // 欠けている場合は EveryProject_HasCommittedLockFile が専任で報告するのでここでは飛ばす
            // (同じ事実で 2 つのテストが落ちると、原因が 2 種類あるように見えて読み手を惑わせる)
            if (!File.Exists(lockFile)) continue;
            // 失敗メッセージ用に、リポジトリルートからの相対パスにしておく
            var project = Path.GetRelativePath(RepositoryRoot, lockFile);
            // ロックファイルを JSON として解析する
            using var document = JsonDocument.Parse(File.ReadAllText(lockFile));
            // 解決結果はターゲットフレームワークごとに入れ子になっている。
            // 書式が変わって dependencies が無いときは、素の KeyNotFoundException ではなく
            // どのファイルが読めなかったかを示して落とす(このファイルの他の異常系と扱いを揃える)
            Assert.True(document.RootElement.TryGetProperty("dependencies", out var dependencies),
                $"{project} に dependencies がありません。{LockFileName} の書式が変わった可能性があります"
                + "(読み取れないと、そのプロジェクトだけ検査対象から静かに外れます)。");
            // ターゲットフレームワークごとに解決結果を見る
            foreach (var framework in dependencies.EnumerateObject())
            {
                // そのフレームワーク配下のパッケージを 1 件ずつ取り出す
                foreach (var entry in framework.Value.EnumerateObject())
                {
                    // 直接参照(Direct)か推移依存(Transitive)かを控える。壊れる主役は推移依存なので、
                    // 失敗メッセージで「どこを直せばよいか」が分かるよう残しておく
                    var kind = entry.Value.TryGetProperty("type", out var type) ? type.GetString() ?? "" : "";
                    // 実際に解決された版を取り出す(Project 参照など resolved を持たない項目は対象外)
                    if (!entry.Value.TryGetProperty("resolved", out var resolved)) continue;
                    // 1 件分として記録する
                    packages.Add(new ResolvedPackage(project, entry.Name, kind, resolved.GetString() ?? ""));
                }
            }
        }

        // ロックファイルが 1 つも読めないのは異常(全プロジェクトで欠落している等)なので落とす
        Assert.True(packages.Count > 0,
            $"{LockFileName} から解決済みパッケージを 1 件も読み取れませんでした。"
            + "RestorePackagesWithLockFile が外れているか、ロックファイルがコミットされていません。");
        // 集めた一覧を返す
        return packages;
    }

    // ソリューションファイルから、登録されているプロジェクトの絶対パスを読み出す。
    // ソリューション行の形は Project("{型GUID}") = "表示名", "相対パス.csproj", "{GUID}" で、
    // ソリューションフォルダ(仮想フォルダ)の行は .csproj を含まないため自然に除外される
    private static IReadOnlyList<string> ReadSolutionProjects()
    {
        // ソリューションファイルの絶対パスを組み立てる
        var solutionPath = Path.Combine(RepositoryRoot, SolutionFileName);
        // ソリューションが見つからないのは探索の前提が崩れている状態なので落とす
        Assert.True(File.Exists(solutionPath), $"{solutionPath} が見つかりません。");

        // 各行から csproj の相対パスを抜き出し、絶対パスへ直す
        var projects = SolutionProjectRegex.Matches(File.ReadAllText(solutionPath))
            // ソリューションは Windows 形式の区切りで書かれるため、実行環境の区切りへ直す
            .Select(match => match.Groups["path"].Value.Replace('\\', Path.DirectorySeparatorChar))
            // リポジトリルートからの絶対パスにする
            .Select(relativePath => Path.Combine(RepositoryRoot, relativePath))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // プロジェクトが 1 つも読み取れないのは書式変更などの異常なので落とす
        Assert.True(projects.Count > 0,
            $"{SolutionFileName} からプロジェクトを 1 つも読み取れませんでした。書式が変わった可能性があります。");
        // 登録されているのに実体が無いプロジェクトは、ソリューションの記述ずれとして落とす
        var missing = projects.Where(path => !File.Exists(path)).ToList();
        Assert.True(missing.Count == 0,
            $"{SolutionFileName} に登録されたプロジェクトが見つかりません:\n"
            + string.Join("\n", missing.Select(path => $"  {Path.GetRelativePath(RepositoryRoot, path)}")));
        // 読み取ったプロジェクト一覧を返す
        return projects;
    }

    // dependabot.yml から「指定グループの指定キー」の箇条書きを読み出す
    private static IReadOnlyList<string> ReadGroupList(string groupName, string key)
    {
        // グループの本文(そのグループに属する行だけ)を取り出す
        var block = ReadGroupBlock(groupName);
        // 読み取った値を溜める入れ物
        var values = new List<string>();
        // 目的のキー配下を読んでいる最中かどうか
        var insideKey = false;

        // グループ本文を 1 行ずつ見る
        foreach (var line in block)
        {
            // 目的のキーの開始行なら、以降の箇条書きを読み取る状態へ移る
            if (line.Trim() == $"{key}:")
            {
                // 読み取り開始(この行自体に値は無い)
                insideKey = true;
                continue;
            }
            // キーの外側にいる間は何もしない
            if (!insideKey) continue;
            // 箇条書き("- ...")でなくなったら、そのキーの一覧は終わり
            if (!line.TrimStart().StartsWith("- ", StringComparison.Ordinal)) break;
            // ダブルクォートで囲まれた値だけを取り出す(行末のコメントは含めない)
            var quoted = Regex.Match(line, @"-\s*""(?<value>[^""]*)""");
            // 想定した書式(引用符付き)でなければ、読み飛ばさず異常として落とす
            Assert.True(quoted.Success, $"dependabot.yml の {groupName}.{key} に想定外の記述があります: {line.Trim()}");
            // 取り出したパターン文字列を記録する
            values.Add(quoted.Groups["value"].Value);
        }

        // 値が 1 つも無いのは設定が壊れている(または書式が変わった)状態なので失敗させる
        Assert.True(values.Count > 0, $"dependabot.yml の {groupName}.{key} から値を読み取れませんでした。");
        // 読み取ったパターン一覧を返す
        return values;
    }

    // dependabot.yml の指定グループ直下に書かれているキー名を列挙する
    // (そのグループに「何が書かれていないか」を検査するために使う)
    private static IReadOnlyList<string> ReadGroupKeys(string groupName)
    {
        // グループの本文(そのグループに属する行だけ)を取り出す
        var block = ReadGroupBlock(groupName);
        // グループ直下のインデント幅(本文の先頭行が必ず直下のキーになる)
        var keyIndent = IndentOf(block[0]);
        // 直下の階層にある "キー:" だけを拾う(配下の箇条書きや入れ子は対象外)
        return block
            .Where(line => IndentOf(line) == keyIndent)
            .Select(line => Regex.Match(line.Trim(), @"^(?<key>[A-Za-z][A-Za-z0-9-]*):"))
            .Where(match => match.Success)
            .Select(match => match.Groups["key"].Value)
            .ToList();
    }

    // dependabot.yml から「指定グループの指定キー」の単一値(applies-to など)を読み出す
    private static string ReadGroupScalar(string groupName, string key)
    {
        // グループの本文を取り出す
        var block = ReadGroupBlock(groupName);
        // "key: value" 形式の行を探す(値は引用符の有無どちらでも読めるようにする)
        var match = block
            .Select(line => Regex.Match(line.Trim(), $@"^{Regex.Escape(key)}:\s*""?(?<value>[^""#]+?)""?\s*(#.*)?$"))
            .FirstOrDefault(m => m.Success);

        // キーが無ければ既定値へ落ちて意図と食い違うため、存在しないこと自体を失敗として扱う
        Assert.True(match is not null, $"dependabot.yml の {groupName} に {key} が指定されていません。");
        // 読み取った値を返す
        return match!.Groups["value"].Value;
    }

    // dependabot.yml から指定グループに属する行だけを切り出す。
    //
    // YAML パーサを新しく依存に足さず、既存テスト(AnalyticsScriptContractTests 等)と同じく
    // ソースを直接走査する。対象は自分たちが書いた既知の形だけで、想定外の形なら黙って
    // 空を返さず失敗させる(空を返すと「対象 0 件」で検査が素通りしてしまう)
    //
    // 【探索範囲を nuget エコシステムに限定する理由】グループ名だけをファイル全体から探すと、
    // 2 つの EF Core グループが npm など別のエコシステム配下へ移動しても見つかってしまう。
    // その状態では NuGet パッケージに一切効かない(nuget 側に残るのは EF Core 系を除外している
    // グループだけなので、プロバイダごとの単独 major PR に逆戻りする)のに検査は通る。
    // 「どこに書いてあるか」まで含めて固定する
    private static IReadOnlyList<string> ReadGroupBlock(string groupName)
    {
        // nuget エコシステムの groups: 配下の行だけを対象にする
        var groupsBlock = NuGetGroupsBlock.Value;

        // グループ名の行を探す。コメント行は対象外にし、前後の空白を除いた完全一致だけを認める
        // (EndsWith で拾うと「# 束ねているのは nuget-ef-core:」のような説明文が先に一致し、
        //  そこを起点に走査してしまう)
        var groupLine = groupsBlock.FindIndex(line =>
            !IsIgnorable(line) && line.Trim() == $"{groupName}:");
        // グループが消えている(または別エコシステムへ移った)＝束ねが外れているので、明示して落とす
        Assert.True(groupLine >= 0,
            $"dependabot.yml の package-ecosystem: \"{NuGetEcosystem}\" 配下に {groupName} グループが"
            + "見つかりません。EF Core 系をまとめて更新する設定が外れる(または別のエコシステムへ"
            + "移る)と、プロバイダごとに単独の PR が作られます。");

        // グループのインデント幅(この幅以下の行が現れたらグループの範囲を抜けたと判断する)
        var groupIndent = IndentOf(groupsBlock[groupLine]);
        // グループ行の次の行から、より深いインデントが続く範囲を本文として切り出す
        var block = TakeNestedBlock(groupsBlock, groupLine + 1, groupIndent);

        // 本文が空のグループは設定として意味を成さないので落とす
        Assert.True(block.Count > 0, $"dependabot.yml の {groupName} グループに中身がありません。");
        // 切り出した本文を返す
        return block;
    }

    // dependabot.yml の「nuget エコシステムの groups: 配下」の行だけを切り出す
    private static List<string> ReadNuGetGroupsBlock()
    {
        // 読み込み済みの設定ファイルの行を取り出す(1 回のテスト実行につき読み込みは 1 度だけ)
        var lines = DependabotLines.Value.ToList();

        // nuget エコシステムの設定エントリの開始行を探す
        var ecosystemLine = lines.FindIndex(line =>
            !IsIgnorable(line) && line.Trim() == $"- {EcosystemKey}: \"{NuGetEcosystem}\"");
        // エントリが無ければ NuGet の更新設定そのものが失われている
        Assert.True(ecosystemLine >= 0,
            $"dependabot.yml に {EcosystemKey}: \"{NuGetEcosystem}\" のエントリが見つかりません。");

        // エントリ本文(次のエントリが始まるまで)を切り出す
        var entryBlock = TakeNestedBlock(lines, ecosystemLine + 1, IndentOf(lines[ecosystemLine]));
        // そのエントリの groups: の開始行を探す
        var groupsLine = entryBlock.FindIndex(line => line.Trim() == $"{GroupsKey}:");
        // グループ定義そのものが無ければ、束ねは一切行われない
        Assert.True(groupsLine >= 0,
            $"dependabot.yml の {EcosystemKey}: \"{NuGetEcosystem}\" エントリに {GroupsKey}: がありません。");

        // groups: 配下の行を返す
        return TakeNestedBlock(entryBlock, groupsLine + 1, IndentOf(entryBlock[groupsLine]));
    }

    // 指定位置から、基準インデントより深い行が続く範囲を切り出す(空行・コメント行は捨てる)
    private static List<string> TakeNestedBlock(IReadOnlyList<string> lines, int startIndex, int parentIndent)
    {
        // 切り出した行を溜める入れ物
        var block = new List<string>();
        // 開始位置から順に走査する
        for (var i = startIndex; i < lines.Count; i++)
        {
            // 空行とコメント行は入れ子の判断材料にならないので読み飛ばす
            if (IsIgnorable(lines[i])) continue;
            // 基準と同じかそれより浅いインデントに戻ったら範囲は終わり
            if (IndentOf(lines[i]) <= parentIndent) break;
            // 範囲内の 1 行として記録する
            block.Add(lines[i]);
        }
        // 切り出した範囲を返す
        return block;
    }

    // dependabot.yml を行単位で読み込む(インデントで入れ子を判断するため行の並びを保つ)
    private static string[] ReadDependabotLines()
    {
        // 設定ファイルの絶対パスを組み立てる
        var path = Path.Combine(RepositoryRoot, ".github", "dependabot.yml");
        // 設定ファイルの存在を確認する
        Assert.True(File.Exists(path), $"{path} が見つかりません。");
        // 全行を読み込んで返す
        return File.ReadAllLines(path);
    }

    // 入れ子の判断材料にならない行(空行・コメント行)かどうかを返す
    private static bool IsIgnorable(string line) =>
        // 空白だけの行か、'#' で始まる行であれば読み飛ばしてよい
        line.Trim().Length == 0 || line.TrimStart().StartsWith('#');

    // 行頭の空白文字数(インデントの深さ)を返す
    private static int IndentOf(string line) =>
        // 先頭から空白でない文字が現れるまでの長さを数える
        line.Length - line.TrimStart().Length;

    // テスト実行ディレクトリから上へ辿り、リポジトリルート(src/IncidentInsight.Web と .github を
    // 併せ持つ階層)を見つける。既存テストは Web プロジェクトだけを探すが、本テストは
    // .github/dependabot.yml と全プロジェクトのロックファイルを読むためルートまで遡る必要がある
    private static string FindRepositoryRoot()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ルートに達するまで親を遡る
        while (dir != null)
        {
            // Web プロジェクトと .github の両方を持つ階層がリポジトリルート
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "IncidentInsight.Web"))
                && Directory.Exists(Path.Combine(dir.FullName, ".github")))
            {
                // 見つかったのでその絶対パスを返す
                return dir.FullName;
            }
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException("リポジトリルート(src/IncidentInsight.Web と .github を持つ階層)がテスト実行位置から見つかりません。");
    }
}
