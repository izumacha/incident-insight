// packages.lock.json を読むために取り込む
using System.Text.Json;
// dependabot.yml のパターン照合に正規表現を使うため取り込む
using System.Text.RegularExpressions;
// dependabot.yml を構造として読むための YAML パーサ
using YamlDotNet.Core;
// YAML の各ノード型(マッピング / 一覧 / スカラー)を扱うため取り込む
using YamlDotNet.RepresentationModel;

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
//   (2) 本テストが版ズレそのものを検出する(手動編集や設定変更で束ねが外れた場合の最後の砦)。
//       設定側は dependabot.yml を YAML として構造で読み、書き方の揺れ(フロー記法・引用符・
//       行末コメント・キーの並び順)に左右されずに「何が設定されているか」だけを見る
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

    // 更新設定のエントリを並べる最上位の YAML キー名
    private const string UpdatesKey = "updates";

    // グループが受け持つ更新の大きさを絞る YAML キー名
    private const string UpdateTypesKey = "update-types";

    // 更新の大きさのうち「メジャー」を表す値(この不変条件が守るのはメジャー版の一致)
    private const string MajorUpdateType = "major";

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

    // 名前に上の目印を含むが、EF Core 本体とメジャー版を揃える必要が「ない」パッケージ。
    //
    // 【なぜ除外するのか】これらは EF Core の公開 API しか使わず、メジャー版は EF Core ではなく
    // .NET のリリース (net8.0 → net9.0) に追随する。実際 9.0.0 は net9.0 のみを対象としており、
    // net8.0 のこのアプリでは復元できない。同じ束ね・同じ版揃えの対象にすると、
    // 「EF Core 9 へ上げる」という支援された更新経路が net9.0 専用パッケージに引きずられて
    // 塞がれる。プロバイダ実装(EF Core の内部 API に結び付く)とは版の動き方が違う。
    // 【追加するときの判断基準】EF Core の内部 API に結び付くか(＝プロバイダか)で決める。
    // 判断が付かないものは除外せず、束ねる側に入れる(見逃しより誤検出の方が安全)
    private static readonly string[] DotNetReleaseTrainPackages =
    {
        "Microsoft.AspNetCore.Identity.EntityFrameworkCore",                // Identity の EF Core ストア
        "Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore" // DbContext ヘルスチェック
    };

    // NuGet が解決済みの版を記録するロックファイルの名前
    private const string LockFileName = "packages.lock.json";

    // ロックファイルで、ターゲットフレームワークごとの解決結果をまとめている JSON キー
    private const string DependenciesKey = "dependencies";

    // ロックファイルで、直接参照か推移依存かを表す JSON キー
    private const string TypeKey = "type";

    // ロックファイルで、実際に解決された版を表す JSON キー
    private const string ResolvedKey = "resolved";

    // Dependabot 設定ファイルのリポジトリルートからの位置
    private static readonly string DependabotConfigPath = Path.Combine(".github", "dependabot.yml");

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
            // .NET のリリースに追随する(EF Core とメジャー版を揃える必要がない)ものは対象外
            .Where(package => !DotNetReleaseTrainPackages.Contains(package.Id, StringComparer.OrdinalIgnoreCase))
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

        // 2 つの EF Core グループは同じ顔ぶれであること。片方にだけ足すと、そのパッケージは
        // 通常の版更新とセキュリティ更新で扱いが変わり、片方の経路だけ単独 PR に戻ってしまう。
        // 並び順は Dependabot の挙動に影響しないため集合として比較する(整列しただけで CI が
        // 赤くなると、規約が守られていないのではなく検査が硬すぎるという偽陽性になる)
        AssertSameSet($"{EfCoreGroupName}.{PatternsKey}", versionUpdatePatterns,
            $"{EfCoreSecurityGroupName}.{PatternsKey}", securityUpdatePatterns);

        // minor / patch グループ側は「EF Core 系がすべて除外に含まれていること」だけを求める。
        // 【なぜ完全一致にしないか】ここでの不変条件は「EF Core 系が minor/patch の束ねへ
        // 紛れ込まないこと」であって、除外一覧に他のパッケージが載っていること自体は問題ない。
        // 完全一致を求めると、無関係なパッケージを除外しただけで「EF Core 系を追加・削除する
        // ときは両方を同じ内容に保ってください」という的外れなメッセージで CI が赤くなる
        AssertIsSubsetOf($"{EfCoreGroupName}.{PatternsKey}", versionUpdatePatterns,
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

    [Fact]
    public void EfCoreGroups_AreNotShadowedByAnEarlierGroup()
    {
        // nuget エコシステムに定義されているグループ名を、書かれている順に読み出す
        var groupNames = ReadNuGetGroupNamesInOrder();

        // 2 つの EF Core グループそれぞれについて、先に定義されたグループに横取りされないことを確認する
        // (通常の版更新とセキュリティ更新は別々に解決されるため、片方だけ守っても意味がない)
        //
        // なお同名グループの重複定義は、YAML の解析時点で弾かれる(ReadNuGetGroups の catch)。
        // 重複キーは YAML では後勝ちのため、素朴に読むと「検査は 1 つ目・Dependabot は 2 つ目」を
        // 見る食い違いが起きうるが、構造として読むようにしたことでその経路自体が無くなった
        AssertNotShadowed(groupNames, EfCoreGroupName);
        AssertNotShadowed(groupNames, EfCoreSecurityGroupName);
    }

    // 指定した EF Core グループが、先に定義された別のグループに横取りされないことを確認する。
    //
    // 【なぜ重要か】Dependabot は「最初に一致したグループ」にだけ依存関係を入れる。
    // 例えば patterns: ["Microsoft.*"] のグループを上に置くと、EF Core 本体とプロバイダは
    // そちらへ吸い込まれ、束ねは無効化されてプロバイダごとの単独 major PR に戻る
    private static void AssertNotShadowed(List<string> groupNames, string groupName)
    {
        // 対象グループが「グループ定義の直下」に居ることを確かめる。
        // 【なぜ確認が要るか】インデントを 1 段深くすると、そのグループは別グループの子キーになり
        // 実質グループでなくなるが、名前で引く読み取りは通ってしまう。位置が取れないまま先へ
        // 進むと「先行グループ 0 件」となり、検査が何も見ずに合格する空振りになる
        var index = groupNames.IndexOf(groupName);
        Assert.True(index >= 0,
            $"dependabot.yml の {groupName} がグループ定義の直下に見つかりません"
            + "(インデントが深く、別グループの子になっていないか確認してください)。");

        // このグループが受け持つ更新種別(通常の版更新 / セキュリティ更新)
        var scope = GroupScopeOf(groupName);
        // 検査対象グループ自身の対象パターンから、EF Core 系として解決されているパッケージ ID を
        // 重複なく用意する。【なぜ groupName か】ここで版更新側のパターンを固定で読むと、
        // セキュリティ側だけが持つパターン(将来 Pomelo 等を足した場合)が視野に入らず、
        // そのパッケージの横取りを見逃す。2 つのパターンが一致していることは別のテストの責務で、
        // この検査がそれに依存すると防御が二重に効かなくなる
        // (パターンの読み出しはループの外で 1 度だけ行う。§8)
        var efCorePatterns = ReadGroupList(groupName, PatternsKey);
        var efCorePackageIds = ResolvedPackages.Value
            .Where(package => MatchesAnyPattern(package.Id, efCorePatterns))
            .Select(package => package.Id)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 先に定義されたグループのうち、EF Core 系を横取りしうるものを探す
        var shadowing = groupNames
            .Take(index)
            // 更新種別が違うグループ同士は解決の土俵が別なので横取りしない
            .Where(name => string.Equals(GroupScopeOf(name), scope, StringComparison.Ordinal))
            // メジャー更新を受け持たないグループは、この不変条件(メジャー版の一致)を壊さない
            .Where(TakesMajorUpdates)
            // 【dependency-type で絞り込まない理由】「開発依存だけのグループは本番依存の
            // EF Core 系を拾わない」と考えたくなるが、前提が成り立たない。
            // Microsoft.EntityFrameworkCore.Design は csproj で PrivateAssets=all を指定して
            // おり、Dependabot からは開発依存に見える。この除外を入れると、開発依存に絞った
            // 先行グループが Design を吸い込む経路を見逃す。Design は Relational を推移依存に
            // 持つため、その単独 major PR をマージすれば版ズレが再発する。
            // 絞り込みキーの解釈を増やすほど見逃しが生まれるので、ここは保守的に倒す
            // (誤検出はレビューで気付けるが、見逃しは PostgreSQL 配備でしか現れない)
            // 実際に EF Core 系パッケージを拾ってしまうか
            .Where(name => efCorePackageIds.Any(id => GroupWouldMatch(name, id)))
            .ToList();

        // 横取りするグループが無いこと(あれば、どのグループが原因かを示す)
        Assert.True(shadowing.Count == 0,
            $"dependabot.yml で {groupName}({scope}) より前に、EF Core 系パッケージに一致するグループが"
            + $"定義されています: [{string.Join(", ", shadowing)}]\n"
            + "Dependabot は最初に一致したグループにだけ依存関係を入れるため、EF Core 系がそちらへ"
            + $"吸い込まれ、束ねが無効になります。{groupName} をより前に置くか、"
            + "先行グループ側で EF Core 系を除外してください。");
    }

    // 指定グループが受け持つ更新種別を返す(applies-to 未指定なら既定の version-updates)
    private static string GroupScopeOf(string groupName) =>
        // 明示されていればその値、無ければ Dependabot の既定値
        TryReadGroupScalar(groupName, AppliesToKey) ?? VersionUpdates;

    // 指定グループがメジャー更新を受け持つかどうかを返す(update-types 未指定なら全種別が対象)
    private static bool TakesMajorUpdates(string groupName) =>
        // 種別が絞られていなければ全て受け持つ。絞られていれば major が含まれるかを見る
        TryReadGroupList(groupName, UpdateTypesKey) is not { } updateTypes
        || updateTypes.Contains(MajorUpdateType, StringComparer.OrdinalIgnoreCase);

    // 指定グループが、そのパッケージ ID を自分のものとして拾うかどうかを判定する。
    // patterns が無いグループは「すべてに一致」が既定なので、除外指定だけを見る
    private static bool GroupWouldMatch(string groupName, string packageId)
    {
        // 除外指定に当てはまるなら、そのグループは拾わない
        if (TryReadGroupList(groupName, ExcludePatternsKey) is { } excluded && MatchesAnyPattern(packageId, excluded))
        {
            // 除外されているので一致しない
            return false;
        }
        // 対象指定が書かれていれば、それに当てはまるかを見る。書かれていなければ全てに一致する
        return TryReadGroupList(groupName, PatternsKey) is not { } patterns || MatchesAnyPattern(packageId, patterns);
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

    // 左の一覧が右の一覧にすべて含まれることを確認する。欠けていれば、どれが漏れているかを示して落とす
    private static void AssertIsSubsetOf(string leftName, IReadOnlyList<string> left, string rightName, IReadOnlyList<string> right)
    {
        // NuGet のパッケージ ID は大文字小文字を区別しないため、比較も区別しない集合にする
        var rightSet = new HashSet<string>(right, StringComparer.OrdinalIgnoreCase);
        // 右に無いものを漏れとして集める
        var missing = left.Where(pattern => !rightSet.Contains(pattern)).ToList();

        // 漏れが無いこと(あれば、どれが足りないのかを具体的に示す)
        Assert.True(missing.Count == 0,
            $"dependabot.yml の {leftName} にあるのに {rightName} に無い対象があります: "
            + $"[{string.Join(", ", missing)}]\n"
            + "EF Core 系が minor / patch の束ねへ紛れ込まないよう、除外にも同じ対象を並べてください。");
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
            // NuGet のパッケージ ID は大文字小文字を区別しないため、照合も区別しない。
            // CultureInvariant を併せるのは、トルコ語ロケール等で I/i の対応が変わると
            // 一致しなくなり、エラーではなく「対象から静かに外れる」fail-open になるため
            // (このファイルの他の比較も Ordinal 系で揃えている)
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

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
            Assert.True(document.RootElement.TryGetProperty(DependenciesKey, out var dependencies),
                $"{project} に {DependenciesKey} がありません。{LockFileName} の書式が変わった可能性があります"
                + "(読み取れないと、そのプロジェクトだけ検査対象から静かに外れます)。");
            // ターゲットフレームワークごとに解決結果を見る
            foreach (var framework in dependencies.EnumerateObject())
            {
                // そのフレームワーク配下のパッケージを 1 件ずつ取り出す
                foreach (var entry in framework.Value.EnumerateObject())
                {
                    // 直接参照(Direct)か推移依存(Transitive)かを控える。壊れる主役は推移依存なので、
                    // 失敗メッセージで「どこを直せばよいか」が分かるよう残しておく
                    var kind = entry.Value.TryGetProperty(TypeKey, out var type) ? type.GetString() ?? "" : "";
                    // 実際に解決された版を取り出す(Project 参照など resolved を持たない項目は対象外)
                    if (!entry.Value.TryGetProperty(ResolvedKey, out var resolved)) continue;
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

    // dependabot.yml の nuget エコシステムに定義されたグループ(名前 → 設定)。
    //
    // 【なぜ YAML パーサを使うのか】当初はインデントを数える自前の走査で読んでいたが、
    // YAML には同じ意味を表す書き方が多数あり(フロー記法 {a: b} / 引用符付きキー / 行末コメント /
    // キーの並び順 / 重複キーの後勝ち)、そのすべてを自前で網羅するのは現実的でなかった。
    // 実際、想定していない書き方をされると (a) 検査が対象を見落として素通りする、
    // (b) 正しい設定なのに CI が赤くなる、のどちらかが起きた。構造として読めば、
    // 「どう書かれているか」ではなく「何が設定されているか」だけを見られる。
    // 依存は YamlDotNet(MIT・.NET の標準的な YAML ライブラリ)をテストプロジェクトにのみ追加する
    private static readonly Lazy<YamlMappingNode> NuGetGroups = new(ReadNuGetGroups);

    // グループ名を定義順に並べた一覧(Dependabot は「最初に一致したグループ」に入れるため順序に意味がある)
    private static List<string> ReadNuGetGroupNamesInOrder() =>
        // マッピングのキーを、書かれている順に文字列として取り出す
        NuGetGroups.Value.Children.Keys.Select(key => ((YamlScalarNode)key).Value ?? "").ToList();

    // 指定グループの設定(マッピング)を取り出す
    private static YamlMappingNode ReadGroup(string groupName)
    {
        // グループ名で引く(見つからなければ束ねが外れているということ)
        var found = NuGetGroups.Value.Children
            .FirstOrDefault(entry => ((YamlScalarNode)entry.Key).Value == groupName).Value;
        // 見つからない、またはマッピングでない場合は、その事実を明示して落とす
        Assert.True(found is YamlMappingNode,
            $"dependabot.yml の {EcosystemKey}: \"{NuGetEcosystem}\" 配下に {groupName} グループが"
            + "見つかりません。EF Core 系をまとめて更新する設定が外れる(または別のエコシステムへ"
            + "移る)と、プロバイダごとに単独の PR が作られます。");
        // マッピングとして返す
        return (YamlMappingNode)found!;
    }

    // 指定グループ直下に書かれているキー名を列挙する(「他に何も書かれていないこと」の検査に使う)
    private static IReadOnlyList<string> ReadGroupKeys(string groupName) =>
        // マッピングのキーを文字列として取り出す
        ReadGroup(groupName).Children.Keys.Select(key => ((YamlScalarNode)key).Value ?? "").ToList();

    // 指定グループの指定キーを一覧として読み出す(キーが無ければ null)。
    // ブロック記法(- a)とフロー記法([a, b])のどちらで書かれていても同じ結果になる
    private static IReadOnlyList<string>? TryReadGroupList(string groupName, string key)
    {
        // そのキーが書かれていなければ「指定なし」として null を返す
        if (!ReadGroup(groupName).Children.TryGetValue(new YamlScalarNode(key), out var node)) return null;
        // 一覧として書かれていることを確かめる(単一値だった場合は設定ミスなので落とす)
        Assert.True(node is YamlSequenceNode, $"dependabot.yml の {groupName}.{key} が一覧ではありません。");
        // 各要素を文字列として取り出す
        return ((YamlSequenceNode)node).Children.Select(item => ((YamlScalarNode)item).Value ?? "").ToList();
    }

    // 指定グループの指定キーを一覧として読み出す(キーが無ければ落とす)
    private static IReadOnlyList<string> ReadGroupList(string groupName, string key)
    {
        // 任意読み取りを試みる
        var values = TryReadGroupList(groupName, key);
        // 無ければ、設定が壊れている状態として落とす
        Assert.True(values is { Count: > 0 }, $"dependabot.yml の {groupName}.{key} から値を読み取れませんでした。");
        // 読み取った一覧を返す
        return values!;
    }

    // 指定グループの指定キーを単一値として読み出す(キーが無ければ null)
    private static string? TryReadGroupScalar(string groupName, string key) =>
        // スカラーとして書かれていればその値、書かれていなければ null
        ReadGroup(groupName).Children.TryGetValue(new YamlScalarNode(key), out var node) && node is YamlScalarNode scalar
            ? scalar.Value
            : null;

    // 指定グループの指定キーを単一値として読み出す(キーが無ければ落とす)
    private static string ReadGroupScalar(string groupName, string key)
    {
        // 任意読み取りを試みる
        var value = TryReadGroupScalar(groupName, key);
        // キーが無ければ既定値へ落ちて意図と食い違うため、存在しないこと自体を失敗として扱う
        Assert.True(value is not null, $"dependabot.yml の {groupName} に {key} が指定されていません。");
        // 読み取った値を返す
        return value!;
    }

    // dependabot.yml を構造として読み込み、nuget エコシステムの groups: を取り出す
    private static YamlMappingNode ReadNuGetGroups()
    {
        // 設定ファイルの絶対パスを組み立てる
        var path = Path.Combine(RepositoryRoot, DependabotConfigPath);
        // 設定ファイルの存在を確認する
        Assert.True(File.Exists(path), $"{path} が見つかりません。");

        // YAML として解析する。同名キーの重複などで解析できない場合は、原因を添えて落とす
        // (重複キーは YAML では後勝ちで、検査と Dependabot が別の定義を見る食い違いの元になる)
        var stream = new YamlStream();
        try
        {
            using var reader = new StringReader(File.ReadAllText(path));
            stream.Load(reader);
        }
        catch (YamlException e)
        {
            Assert.Fail($"dependabot.yml を YAML として解析できませんでした: {e.Message}");
        }

        // 文書が 1 つも無い(空ファイル・コメントのみ)場合は、素の添字範囲外ではなく状況を示して落とす
        Assert.True(stream.Documents.Count > 0, "dependabot.yml に YAML 文書がありません(空か、コメントだけの可能性があります)。");
        // 最上位のマッピングから updates: の一覧を取り出す
        var root = Assert.IsType<YamlMappingNode>(stream.Documents[0].RootNode);
        Assert.True(root.Children.TryGetValue(new YamlScalarNode(UpdatesKey), out var updates)
            && updates is YamlSequenceNode,
            $"dependabot.yml に {UpdatesKey}: の一覧がありません。");

        // nuget エコシステムの設定エントリを集める
        var nugetEntries = ((YamlSequenceNode)updates!).Children
            .OfType<YamlMappingNode>()
            .Where(entry => entry.Children.TryGetValue(new YamlScalarNode(EcosystemKey), out var ecosystem)
                && (ecosystem as YamlScalarNode)?.Value == NuGetEcosystem)
            .ToList();

        // エントリが無ければ NuGet の更新設定そのものが失われている
        Assert.True(nugetEntries.Count > 0,
            $"dependabot.yml に {EcosystemKey}: {NuGetEcosystem} のエントリが見つかりません。");
        // 2 つ以上ある場合、この検査は最初の 1 つしか見ないため、見ていないエントリが
        // 束ねの無い状態で残りうる。読み飛ばさず「検査を広げてから追加せよ」と落とす(fail-closed)
        Assert.True(nugetEntries.Count == 1,
            $"dependabot.yml に {EcosystemKey}: {NuGetEcosystem} のエントリが {nugetEntries.Count} 個あります。"
            + "本テストは 1 つ目しか検査しないため、2 つ目以降は束ねが無いまま見逃されます。"
            + "エントリを増やすときは先に本テストを複数エントリ対応へ広げてください。");

        // そのエントリの groups: を取り出す
        Assert.True(nugetEntries[0].Children.TryGetValue(new YamlScalarNode(GroupsKey), out var groups)
            && groups is YamlMappingNode,
            $"dependabot.yml の {EcosystemKey}: {NuGetEcosystem} エントリに {GroupsKey}: がありません。");
        // 中身が空なら束ねが 1 つも無い状態なので、何が起きているかを示して落とす
        var groupsNode = (YamlMappingNode)groups!;
        Assert.True(groupsNode.Children.Count > 0,
            $"dependabot.yml の {EcosystemKey}: {NuGetEcosystem} エントリの {GroupsKey}: に"
            + "グループが 1 つも定義されていません。束ねが全て失われた状態です。");
        // 読み取ったグループ定義を返す
        return groupsNode;
    }

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
