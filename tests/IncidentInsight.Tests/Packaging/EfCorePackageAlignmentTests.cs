// packages.lock.json を読むために取り込む
using System.Text.Json;
// dependabot.yml のパターン照合に正規表現を使うため取り込む
using System.Text.RegularExpressions;
// dependabot.yml を構造として読むための YAML パーサ
using YamlDotNet.Core;
// YAML の各ノード型(マッピング / 一覧 / スカラー)を扱うため取り込む
using YamlDotNet.RepresentationModel;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

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

    // minor / patch グループが受け持つべき更新の大きさ。
    // どちらかが抜けると、その種別の更新だけ束ねから外れて単独 PR に戻る
    private static readonly string[] MinorAndPatchUpdateTypes = { "minor", "patch" };

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
    // ないため、両方を並べる必要がある)。
    //
    // 【既知の限界】プロバイダ実装と版が連動するのに、名前にどちらの目印も含まないパッケージがある。
    //   - Microsoft.Data.Sqlite.Core — EF Core と同じリポジトリ・同じ版で出荷
    //     (同系の Microsoft.Data.Sqlite を直接参照した場合も同じ穴に落ちる)
    //   - Npgsql — Npgsql.EntityFrameworkCore.PostgreSQL の土台で、メジャー版が連動する
    // いずれも現在は上位プロバイダが要求する推移依存としてのみ入っており、推移依存に対して
    // Dependabot は単独 PR を作らないため実害はない。ただし csproj から直接参照した時点で、
    // これらだけが単独の major PR として現れうる(例えば Npgsql 9.x を 8.x のプロバイダの下に
    // 置く PR が緑のまま作られる)。目印を名前だけに頼る限りこの穴は塞げないため、
    // 直接参照を足すときは patterns への追記も併せて検討する
    private static readonly string[] EfCoreIdMarkers = { "EntityFrameworkCore", "EFCore" };

    // 名前に上の目印を含むが、EF Core 本体とメジャー版を揃える必要が「ない」パッケージ。
    //
    // 【なぜ除外するのか】これらは EF Core の公開 API しか使わず、メジャー版は EF Core ではなく
    // .NET のリリース (net8.0 → net9.0) に追随する。実際 9.0.0 は net9.0 のみを対象としており、
    // net8.0 のこのアプリでは復元できない。同じ束ね・同じ版揃えの対象にすると、
    // 「EF Core 9 へ上げる」という支援された更新経路が net9.0 専用パッケージに引きずられて
    // 塞がれる。プロバイダ実装(EF Core の内部 API に結び付く)とは版の動き方が違う。
    // 【追加するときの判断基準】EF Core の内部 API に結び付くか(＝プロバイダか)で決める。
    // 判断が付かないものは除外せず、束ねる側に入れる(見逃しより誤検出の方が安全)。
    // 【この配列が正本】同じ顔ぶれは dependabot.yml と CLAUDE.md の散文にも出てくるが、
    // 実際に効くのはこの配列だけで、散文は判断材料として読まれる場所にすぎない。
    // 配列へ追加したのに散文が古いままになるのを防ぐため、散文側にも名前が載っていることを
    // DotNetReleaseTrainPackages_AreDocumentedWhereBundlingIsDecided が機械的に固定する。
    // 【この固定は「名前が載っていること」までしか言えない】検査は本文全体に対する部分文字列
    // 照合なので、(a) 配列から名前を削ったとき散文に残った説明、(b) 名前は出てくるが
    // 「束ねる側だ」と逆の説明をしている文、のどちらも検出できない。防げるのは
    // 「配列にだけ足して散文に一言も書かない」という取りこぼしで、説明の中身が正しいかは
    // レビューの仕事として残る。束ねる/束ねないの判断を変えたときは散文も手で直す
    private static readonly string[] DotNetReleaseTrainPackages =
    {
        "Microsoft.AspNetCore.Identity.EntityFrameworkCore",                // Identity の EF Core ストア
        "Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore" // DbContext ヘルスチェック
    };

    // SQL Server 用の ADO.NET ドライバ。EF Core の SqlServer プロバイダが内部で使う実体
    private const string SqlClientPackageId = "Microsoft.Data.SqlClient";

    // 上のドライバを推移的に要求する EF Core の SqlServer プロバイダ
    private const string EfCoreSqlServerPackageId = "Microsoft.EntityFrameworkCore.SqlServer";

    // Dependabot 設定で、更新を無視する対象を並べるキー
    private const string IgnoreKey = "ignore";

    // ignore の各エントリで、対象パッケージを指定するキー
    private const string DependencyNameKey = "dependency-name";

    // ignore の各エントリで、無視する更新の種別を並べるキー
    private const string IgnoreUpdateTypesKey = "update-types";

    // ignore の各エントリで、版の範囲を絞り込むキー(保留の範囲を静かに変えるので置かせない)
    private const string IgnoreVersionsKey = "versions";

    // Dependabot で「メジャー更新」を表す update-type の名前
    private const string SemverMajorUpdateType = "version-update:semver-major";

    // NuGet が解決済みの版を記録するロックファイルの名前
    private const string LockFileName = "packages.lock.json";

    // ロックファイルで、ターゲットフレームワークごとの解決結果をまとめている JSON キー
    private const string DependenciesKey = "dependencies";

    // ロックファイルで、直接参照か推移依存かを表す JSON キー
    private const string TypeKey = "type";

    // ロックファイルで、実際に解決された版を表す JSON キー
    private const string ResolvedKey = "resolved";

    // ロックファイルの type が「csproj に直接書かれた参照」を表すときの値
    // (推移依存なら "Transitive"、ProjectReference なら "Project" になる)
    private const string DirectPackageKind = "Direct";

    // Dependabot 設定ファイルのリポジトリルートからの位置
    private static readonly string DependabotConfigPath = Path.Combine(".github", "dependabot.yml");

    // リポジトリの規約・不変条件をまとめたガイド(束ねる/束ねないの判断根拠が書かれている)
    private const string ClaudeGuideFileName = "CLAUDE.md";

    // 「このリポジトリのプロジェクト」の正本。CI の dotnet restore / build / test もこれを対象にする
    private const string SolutionFileName = "IncidentInsight.sln";

    // ソリューションファイルからプロジェクトの相対パスを抜き出す正規表現。
    // 行の形は Project("{型GUID}") = "表示名", "相対パス.csproj", "{GUID}"
    private static readonly Regex SolutionProjectRegex =
        new(@"""(?<path>[^""]+\.csproj)""", RegexOptions.None);

    // EF Core 系を束ねるグループの一覧(通常の版更新とセキュリティ更新)。
    // 【なぜ配列にするか】この 2 つを並べる箇所が「除外対象を拾っていないか」
    // 「許可キー以外が無いか」「先行グループに横取りされないか」の 3 つに増えた。
    // グループを足したとき 1 箇所だけ直して他が素通りするのを防ぐ(§6)
    private static readonly string[] EfCoreGroupNames = { EfCoreGroupName, EfCoreSecurityGroupName };

    // EF Core 系グループに書いてよいキー。
    // 【なぜ限定するか】patterns と applies-to が正しくても、同じグループに update-types や
    // exclude-patterns を足せば束ねる範囲を後から狭められる(例: update-types を minor/patch に
    // すると major が再びプロバイダごとの単独 PR に戻り、この PR が防いだ状態そのものに戻る)。
    // 「何が書いてあるか」だけでなく「他に何も書かれていないこと」まで固定する
    private static readonly string[] AllowedEfCoreGroupKeys = { AppliesToKey, PatternsKey };

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
    public void DotNetReleaseTrainPackages_AreAllResolved()
    {
        // 除外一覧が実在するパッケージを指していること。ロックファイルに無い名前が並んでいると、
        // 綴り違いや削除済みパッケージが「除外できているつもり」で残り、
        // DependabotPatterns_CoverEveryEntityFrameworkCorePackage の網に穴を空けたまま気付けない。
        // 【なぜ束ね検査と分けるか】これは「配列の掃除漏れ」であって束ねの不変条件ではない。
        // 同じ Fact に同居させると、参照をやめただけで先頭の Assert が throw し、
        // 本来の不変条件(patterns が除外対象を拾っていないこと)がその実行では一切検証されない。
        //
        // ロックファイルが欠けているプロジェクトを控えておく。
        // 【なぜ検査を飛ばさないか】黙って return すると「何も確かめずに緑」になり、
        // 配列の掃除漏れが素通りする。かといって素の失敗文では、実際の原因が
        // ロックファイルの未コミットなのに「配列を直せ」と誤って案内してしまう。
        // 検査は必ず行い、案内する原因の方を状況で切り替える
        var projectsWithoutLockFile = SolutionProjects.Value
            .Where(project => !File.Exists(LockFilePathOf(project)))
            .Select(project => Path.GetRelativePath(RepositoryPaths.Root, project))
            .ToList();

        // ロックファイルに解決されているパッケージ ID を、大小文字を区別しない集合にまとめる
        var resolvedIds = ResolvedPackages.Value
            .Select(package => package.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        // 除外一覧のうち、どのロックファイルにも現れない名前を集める
        var unknown = DotNetReleaseTrainPackages.Where(id => !resolvedIds.Contains(id)).ToList();
        // 存在しない名前が無いこと(あれば、どれが宙に浮いているかを示す)
        Assert.True(unknown.Count == 0,
            $"{nameof(DotNetReleaseTrainPackages)} に、{LockFileName} のどこにも解決されていない"
            + $"パッケージがあります: [{string.Join(", ", unknown)}]\n"
            + (projectsWithoutLockFile.Count > 0
                // ロックファイルが欠けているなら、読み飛ばされたプロジェクトが原因の可能性が高い
                ? $"ただし {LockFileName} が無いプロジェクトがあり"
                  + $"({string.Join(" / ", projectsWithoutLockFile)})、その分が読み飛ばされています。"
                  + $"まず {nameof(EveryProject_HasCommittedLockFile)} の指摘を直してください。"
                // すべて揃っているなら、配列側の掃除漏れ
                : "参照をやめたのなら配列からも削り、綴り違いなら直してください"
                  + "(実在しない名前は何も除外せず、網羅性検査の穴になります)。"));
    }

    [Fact]
    public void DotNetReleaseTrainPackages_AreNotBundledWithEfCore()
    {
        // 2 つの EF Core グループそれぞれについて、除外対象を拾っていないか調べる。
        // 【なぜループの中で Assert しないか】1 グループ目で throw すると 2 グループ目は
        // 検証されず、片方を直して再実行して初めてもう片方の違反を知ることになる。
        // 全グループ分を集めてから 1 度だけ落とし、1 回の実行で全体が分かるようにする
        var bundled = EfCoreGroupNames
            // そのグループの patterns を 1 度だけ読み出す(§8)。
            // 【なぜ ReadGroupMatcher を使わないか】この 2 グループは AssertOnlyAllowedKeys により
            // exclude-patterns を書けない。除外込みで判定すると、仮に誰かが exclude-patterns を
            // 足したとき「除外されているから拾わない」と読んで静かに通ってしまい、
            // しかも失敗メッセージは patterns を名指しする形になって実態と食い違う。
            // このテストが言いたいのは「patterns が拾っていないこと」なので、patterns だけを見る
            .Select(groupName => (GroupName: groupName, Patterns: ReadGroupList(groupName, PatternsKey)))
            // 「どのグループが・どのパッケージを」拾っているかの組を並べる
            .SelectMany(group => DotNetReleaseTrainPackages
                .Where(id => MatchesAnyPattern(id, group.Patterns))
                .Select(id => $"{group.GroupName}.{PatternsKey}: {id}"))
            .ToList();

        // 拾われていないこと。【なぜこの向きの検査が要るか】既存の検査は
        // 「EF Core 系がパターンから漏れていないか」しか見ておらず、逆に
        // .NET リリース列のパッケージを patterns へ足す方向は素通りしていた。
        // 束ねてしまうと「EF Core 9 へ上げる PR」が net9.0 専用パッケージを巻き込み、
        // net8.0 のこのアプリでは復元できない PR になる(＝更新経路が塞がれる)
        Assert.True(bundled.Count == 0,
            "dependabot.yml の EF Core 系グループが、EF Core とメジャー版を揃える必要の"
            + $"ないパッケージを拾っています:\n{string.Join("\n", bundled.Select(entry => $"  {entry}"))}\n"
            + "これらは EF Core の公開 API しか使わず、メジャー版は .NET のリリース"
            + "(net8.0 → net9.0)に追随します。束ねに入れると EF Core 9 への更新 PR が"
            + $"net9.0 専用パッケージを巻き込んで復元不能になります({nameof(DotNetReleaseTrainPackages)} 参照)。");
    }

    [Fact]
    public void DotNetReleaseTrainPackages_StayInTheMinorAndPatchBundle()
    {
        // 裏返しの不変条件: これらは minor / patch の束ねには「入っていてほしい」。
        // 【なぜ両方向を見るか】EF Core 側の patterns から外すだけでは足りない。
        // 例えば nuget-minor-and-patch の除外を "*EntityFrameworkCore*" と広く書くと、
        // EF Core 系の漏れは無くなる一方でこの 2 つまで minor / patch から外れ、
        // 通常運転の更新がパッケージごとの単独 PR に戻ってレビュー負荷が上がる
        // (束ねを広げる方向の事故は、狭める方向と違って赤くならないので気付きにくい)。
        // 【なぜ別の Fact か】「束ねに入っていないこと」とは独立した条件で、同居させると
        // 片方が throw したときもう片方が検証されない(このファイルで繰り返し避けている形)
        // 「どのパッケージの・どの種別が・どこへ入るか」を定義順に解決し、
        // minor / patch の束ね以外へ流れるものを集める
        var droppedFromMinorAndPatch = DotNetReleaseTrainPackages
            // 「パッケージ × 更新の大きさ」の組を作る(Dependabot は種別ごとに帰属を決める)
            .SelectMany(id => MinorAndPatchUpdateTypes.Select(type => (Id: id, Type: type)))
            // 組ごとに、定義順で最初に一致するグループ(＝実際の入り先)を求める
            .Select(target => (target.Id, target.Type, Owner: OwningGroupOf(target.Id, target.Type)))
            // 入り先が minor / patch の束ねでないものだけを残す
            .Where(result => result.Owner != MinorAndPatchGroupName)
            // 失敗メッセージ用に「何の・どの種別が・どこへ」を 1 行にする
            .Select(result => $"{result.Id} の {result.Type} → "
                + (result.Owner is null ? "どのグループにも入らない" : $"{result.Owner} に入る"))
            .ToList();

        // 外れていないこと(あれば、どのパッケージが束ねから落ちたかを示す)
        Assert.True(droppedFromMinorAndPatch.Count == 0,
            "dependabot.yml で、まとめて更新したいパッケージが "
            + $"{MinorAndPatchGroupName} の束ねに入っていません:\n"
            + $"{string.Join("\n", droppedFromMinorAndPatch.Select(entry => $"  {entry}"))}\n"
            // 手前の別グループへ流れているなら、直す先はそのグループ側
            + (droppedFromMinorAndPatch.Any(entry => entry.Contains(" に入る", StringComparison.Ordinal))
                ? $"手前のグループが先に拾っています。{MinorAndPatchGroupName} をより前に置くか、"
                  + "そのグループ側でこれらを除外してください"
                  + "(Dependabot は最初に一致したグループにだけ依存関係を入れます)。\n"
                : "")
            // どこにも入らないなら、minor / patch グループ自身の条件が合っていない
            + (droppedFromMinorAndPatch.Any(entry => entry.Contains("どのグループにも入らない", StringComparison.Ordinal))
                ? $"どのグループにも入らないものは、{MinorAndPatchGroupName} の "
                  + $"{ExcludePatternsKey} / {PatternsKey} / {UpdateTypesKey} のいずれかが"
                  + "これらを外していないか確認してください。"
                : ""));
    }

    [Fact]
    public void MinorAndPatchGroup_TakesBothMinorAndPatchUpdates()
    {
        // 束ねが minor と patch の両方を受け持っていること。
        // 【なぜ update-types も見るか】除外に当たらなくても、update-types を ["patch"] へ
        // 狭めれば minor 更新はこの束ねから外れ、結局パッケージごとの単独 PR に戻る。
        // パターンだけを見ていると、この経路の後退が緑のまま通ってしまう。
        // 【なぜ別の Fact か】上の帰属検査も update-types を経由するため結果は重なるが、
        // 「種別の指定が足りない」という原因を名指しする方が直す場所が分かりやすい。
        // 同居させると片方が throw したときもう片方が検証されない
        // 【なぜ TryReadGroupList か】update-types を書かない場合、Dependabot は全種別を
        // 受け持つ。つまり minor / patch も束ねられており、この不変条件は満たされている。
        // ReadGroupList で必須にすると「読み取れませんでした」と、成立している設定を
        // 別の理由で落とすことになる
        if (TryReadGroupList(MinorAndPatchGroupName, UpdateTypesKey) is not { } updateTypes) return;
        // 受け持つべき更新の大きさのうち、指定から漏れているものを集める
        var missingUpdateTypes = MinorAndPatchUpdateTypes
            .Where(type => !updateTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            .ToList();

        // 漏れが無いこと(あれば、どの種別が抜けているかを示す)
        Assert.True(missingUpdateTypes.Count == 0,
            $"dependabot.yml の {MinorAndPatchGroupName}.{UpdateTypesKey} に"
            + $"[{string.Join(", ", missingUpdateTypes)}] が含まれていません。"
            + "抜けた種別の更新は束ねから外れ、パッケージごとの単独 PR に戻ります。");
    }

    [Fact]
    public void DotNetReleaseTrainPackages_AreDocumentedWhereBundlingIsDecided()
    {
        // 「このパッケージを束ねに入れるべきか」を判断する人が読む場所。
        // 配列(正本)だけが増えて散文が古くなると、判断の入口が誤った一覧を示すことになる
        var documents = new[] { DependabotConfigPath, ClaudeGuideFileName };

        // 「どのドキュメントに・どの名前が無いか」の組を集める。
        // 【なぜドキュメントごとに Assert しないか】1 つ目で throw すると 2 つ目は検証されず、
        // 片方を直して再実行して初めてもう片方の漏れを知ることになる。
        // 全ドキュメント分を集めてから 1 度だけ落とし、1 回の実行で全体が分かるようにする
        var undocumented = documents
            // 本文を読み込む(判断材料として読まれるのは散文なので、書式は問わず名前の有無だけを見る)
            .Select(document => (Document: document, Text: ReadRepositoryFile(document)))
            // 本文に名前が出てこないパッケージを拾う。
            // NuGet のパッケージ ID は大文字小文字を区別しないため、照合も区別しない
            // (散文側で綴りの大小が揺れただけで「説明がありません」と落ちるのは、
            // 規約違反ではなく検査が硬すぎる偽陽性。このファイルの他の比較とも揃える)
            .SelectMany(source => DotNetReleaseTrainPackages
                .Where(id => !MentionsPackageName(source.Text, id))
                .Select(id => $"{source.Document}: {id}"))
            .ToList();

        // 漏れが無いこと(あれば、どのファイルへどの名前を書き足せばよいかを示す)
        Assert.True(undocumented.Count == 0,
            "束ねから除外しているパッケージの説明が、判断のよりどころとなる文書にありません:\n"
            + $"{string.Join("\n", undocumented.Select(entry => $"  {entry}"))}\n"
            + $"実際に効くのは {nameof(DotNetReleaseTrainPackages)} だけですが、"
            + "束ねる/束ねないの判断はこの散文を読んで行われます。"
            + "配列へ追加したら、除外する理由も併せて書いてください"
            + "(照合は 1 行の中で名前がそのまま現れるかを見るので、"
            + "説明済みなのに落ちる場合は名前が改行で分断されていないか確認してください)。");
    }

    // 代表値の作り方を、現行の dependabot.yml に無い書き方まで含めて固定する。
    //
    // 【なぜ設定ファイル経由の検査だけでは足りないか】今の patterns は末尾 '*' 付きと
    // ワイルドカード無しの 2 通りしかなく、途中に '*' を含む場合や "*" だけの場合の分岐は
    // 一度も実行されない。ここが壊れても 8 本のテストは緑のままなので、
    // 純粋ロジックとして入力→期待出力を直接固定する(§11)
    [Theory]
    // ワイルドカードが無ければ、そのパターン自身がただ 1 つの一致例
    [InlineData("Npgsql.EntityFrameworkCore.PostgreSQL", "Npgsql.EntityFrameworkCore.PostgreSQL")]
    // 末尾 '*' は「続きがある」場合と「続きが無い」場合の 2 つを代表にする
    [InlineData("Microsoft.EntityFrameworkCore*", "Microsoft.EntityFrameworkCore" + WildcardPlaceholder, "Microsoft.EntityFrameworkCore")]
    // 途中の '*' も目印へ置き換えれば一致例になる(前置詞は作れないので 1 つだけ)
    [InlineData("*EFCore*", WildcardPlaceholder + "EFCore" + WildcardPlaceholder)]
    // 先頭だけが '*' の場合も同様
    [InlineData("*.EntityFrameworkCore.MySql", WildcardPlaceholder + ".EntityFrameworkCore.MySql")]
    // "*" だけのパターンは、空文字列を代表にしても何も伝わらないので目印だけ返す
    [InlineData("*", WildcardPlaceholder)]
    // 空のパターンからは代表値を作らない(TryReadGroupList が空要素を弾くので設定からは
    // 届かないが、代表値を作る側でも空を持ち込まないことを二重に固定しておく)
    [InlineData("")]
    public void RepresentativeIdsOf_CoversTheWholePatternSet(string pattern, params string[] expected)
    {
        // 実際に作られる代表値を取り出す
        var actual = RepresentativeIdsOf(pattern).ToList();

        // 期待した代表値と順序も含めて一致すること
        Assert.Equal(expected, actual);

        // どの代表値も、元のパターンに実際に一致すること(集合の要素であることの確認)。
        // ここが崩れると「パターンが表す範囲の代表」という前提そのものが失われる
        Assert.All(actual, id => Assert.True(MatchesAnyPattern(id, new[] { pattern }),
            $"代表値 \"{id}\" が元のパターン \"{pattern}\" に一致しません。"));
    }

    // 散文への言及判定を、より長いパッケージ名に埋もれる場合まで含めて固定する
    [Theory]
    // 名前がそのまま出てくれば言及とみなす
    [InlineData("Npgsql は EF Core とは版の動き方が違う", "Npgsql", true)]
    // 記号で囲まれていても言及とみなす
    [InlineData("`Npgsql` を直接参照する場合", "Npgsql", true)]
    // より長いパッケージ名の一部でしかない場合は言及とみなさない
    [InlineData("Npgsql.EntityFrameworkCore.PostgreSQL を束ねる", "Npgsql", false)]
    // 逆向き(前側が続いている)も同様
    [InlineData("Foo.Npgsql を束ねる", "Npgsql", false)]
    // 日本語の助詞が直後に続いても言及とみなす(語間に空白を置かないため)
    [InlineData("Npgsqlは EF Core に追随する", "Npgsql", true)]
    // 前後とも日本語で挟まれていても同様
    [InlineData("土台のNpgsqlは版が連動する", "Npgsql", true)]
    // 文末の句点は名前の続きではない
    [InlineData("土台は Npgsql. 版が連動する", "Npgsql", true)]
    // 箇条書きの区切りに続く場合も名前の続きではない
    [InlineData("# - Npgsql: 束ねない理由", "Npgsql", true)]
    // 区切り文字のあとに ID が続くなら、やはり長い名前の一部
    [InlineData("Npgsql.EntityFrameworkCore を束ねる", "Npgsql", false)]
    // 箇条書きのハイフンが直前に付く形も言及とみなす(前側も後ろ側と対称に判定する)
    [InlineData("-Npgsql: 束ねない理由", "Npgsql", true)]
    // 前に区切り文字、さらにその手前に ID があるなら長い名前の途中
    [InlineData("Foo.Npgsql.Bar", "Npgsql", false)]
    // 本文の先頭が区切り文字の場合(その手前に文字が無い)も言及とみなす
    [InlineData(".Npgsql は版が連動する", "Npgsql", true)]
    // 長い名前の言及と埋もれた出現が混在するなら、独立した言及がある方を採る
    [InlineData("Npgsql.EntityFrameworkCore.PostgreSQL と、土台の Npgsql", "Npgsql", true)]
    // どこにも出てこなければ言及なし
    [InlineData("EF Core の話しかしていない", "Npgsql", false)]
    public void MentionsPackageName_IgnoresMatchesBuriedInLongerNames(string text, string packageId, bool expected)
    {
        // 判定結果が期待どおりであること
        Assert.Equal(expected, MentionsPackageName(text, packageId));
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
            .Where(project => !File.Exists(LockFilePathOf(project)))
            .Select(project => Path.GetRelativePath(RepositoryPaths.Root, project))
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
    public void SqlClientPin_StaysWithinEfCoreDeclaredMajor()
    {
        // EF Core の SqlServer プロバイダが「自分はこの版のドライバを前提にしている」と
        // 宣言している版を、ロックファイルの dependencies から読み出す
        var declared = ReadDeclaredDependencyVersion(EfCoreSqlServerPackageId, SqlClientPackageId);
        // 実際に解決されている(= 実行時に読み込まれる)ドライバの版を読み出す
        var resolved = ReadResolvedVersion(SqlClientPackageId);

        // メジャー版が一致していること。
        // 【なぜメジャーを固定するのか】EF Core の SqlServer プロバイダはドライバの内部挙動に
        // 結び付いており、動作保証があるのは自分が宣言したメジャー版に対してだけ。ところが
        // このリポジトリのテストは InMemory / SQLite しか触らないため、ドライバだけを別メジャーへ
        // 上げても「ビルドも全テストも緑のまま、SQL Server 配備でだけ実行時に壊れる」。
        // これは EF Core 本体とプロバイダ実装を 1 本の PR に束ねている理由(このファイル冒頭)と
        // まったく同じ無言の破壊で、違うのは壊れる層がドライバだという点だけ。
        // dependabot.yml の ignore で major を保留しているのはこの検査と対になっている
        Assert.True(MajorOf(resolved) == MajorOf(declared),
            $"{SqlClientPackageId} の解決版 {resolved} が、{EfCoreSqlServerPackageId} の宣言する "
            + $"{declared} と別のメジャー版になっています。\n"
            + "EF Core の SqlServer プロバイダが動作保証するのは、自身が宣言したメジャー版の"
            + "ドライバに対してだけです。テストは InMemory / SQLite しか触らないため、ここがずれても"
            + "ビルドもテストも緑のまま、SQL Server 配備でだけ実行時に壊れます。\n"
            + $"ドライバのメジャーを上げたいときは、それを宣言する版の {EfCoreSqlServerPackageId} へ"
            + "同じ変更セットで上げてください(この検査は期待値を宣言側から読むので自動で追随します)。");

        // 解決版が宣言版を下回らないこと(csproj の直接参照は「床値のピン留め」が目的)。
        // 【なぜ下限も見るのか】この直接参照は、EF Core が推移的に引く版が古いサービシング
        // パッチだったため、セキュリティ更新を後退させない床値として置かれている(csproj の
        // コメント参照)。同じメジャーの中で下げる変更はメジャー一致の検査を素通りするため、
        // 「なぜこのピンがあるのか」の側もここで固定する
        Assert.True(CompareVersions(resolved, declared) >= 0,
            $"{SqlClientPackageId} の解決版 {resolved} が、{EfCoreSqlServerPackageId} の宣言する "
            + $"{declared} を下回っています。\n"
            + "この直接参照は、推移的に引かれる版が古いサービシングパッチであるために"
            + "セキュリティ更新を後退させない床値として置かれています。下げないでください。");
    }

    [Fact]
    public void SqlClientPin_StaysADirectReference()
    {
        // 全ロックファイルから、このドライバの記録(どのプロジェクトが・直接か推移か)を集める
        var entries = LockEntriesFor(SqlClientPackageId);

        // 1 件も無いのは、参照そのものが消えたか検出網が劣化したかのどちらか(fail-closed)
        Assert.True(entries.Count > 0,
            $"{LockFileName} に {SqlClientPackageId} の記録がありません。参照が外れた可能性があります。");

        // csproj に直接書かれた参照として記録しているプロジェクトを取り出す
        var direct = entries
            .Where(package => string.Equals(package.Kind, DirectPackageKind, StringComparison.OrdinalIgnoreCase))
            .ToList();

        // 【なぜ「直接参照であること」まで固定するのか】
        // 上の SqlClientPin_StaysWithinEfCoreDeclaredMajor が床値の比較相手にするのは
        // EF Core SqlServer の宣言(現在 5.1.6)であって、csproj に書かれたピンの値ではない。
        // そのためピンを「冗長だから」と削除すると、解決版が EF Core の宣言どおりに落ちても
        // 5.1.6 >= 5.1.6 で床値検査を素通りし、ビルドもテストも緑のまま SQL Server 配備だけが
        // 古いドライバに戻る(このリポジトリで最も起きやすい形の無言の後退)。
        // ここで type が Direct であることを見ておけば、削除も「推移依存に戻す」リファクタも
        // 検出できる。期待する版をテストに書かずに済むので、期待値を宣言側から読む方針とも両立する
        Assert.True(direct.Count > 0,
            $"{SqlClientPackageId} が {LockFileName} のどこにも {DirectPackageKind} として記録されていません。"
            + "csproj の直接参照(床値のピン)が外れた可能性があります。\n"
            + "このピンは、EF Core SqlServer が推移的に引く版が古いサービシングパッチであるために"
            + "置かれています。外すと解決版はその古い版まで落ちますが、床値検査の比較相手が"
            + "EF Core の宣言そのものであるため検査は素通りし、SQL Server 配備でだけ古いドライバが"
            + "読み込まれます。\n"
            + "意図して外すのであれば、EF Core SqlServer の宣言版が十分新しくなったことを確認し、"
            + "csproj のコメントと本テストを同じ変更セットで畳んでください。\n"
            + "現在の記録:\n" + Describe(entries));
    }

    [Fact]
    public void DependabotConfig_HoldsSqlClientMajorUpdates()
    {
        // nuget エコシステムの ignore: からドライバの保留エントリを集める
        var entries = ReadIgnoreEntriesFor(SqlClientPackageId);

        // エントリがちょうど 1 件あること。
        // 0 件なら保留が消えて major の単独 PR が再び作られる。2 件以上は Dependabot が
        // すべて適用するため、意図より広い範囲が止まる(minor / patch のセキュリティ修正まで
        // 届かなくなる)。どちらも静かに壊れるので件数まで固定する
        Assert.True(entries.Count == 1,
            $"dependabot.yml の {EcosystemKey}: {NuGetEcosystem} の {IgnoreKey}: に "
            + $"{SqlClientPackageId} の保留がちょうど 1 件あることを期待しましたが {entries.Count} 件でした。\n"
            + $"0 件なら保留の消失({nameof(SqlClientPin_StaysWithinEfCoreDeclaredMajor)} が守る不変条件を"
            + "破る PR が毎週作られます)。2 件以上は Dependabot が全て適用するため効きすぎです。");

        // 唯一のエントリを取り出して中身を検査する
        var entry = entries[0];

        // update-types が書かれていること。省くと「全ての更新を無視」になり、
        // 同じメジャー内のセキュリティ修正(床値を上げる更新)まで届かなくなる
        Assert.True(entry.Children.TryGetValue(new YamlScalarNode(IgnoreUpdateTypesKey), out var updateTypesNode)
            && updateTypesNode is YamlSequenceNode,
            $"dependabot.yml の {SqlClientPackageId} の保留に {IgnoreUpdateTypesKey}: がありません。"
            + "省くと全ての更新の無視になり、同じメジャー内のセキュリティ修正まで止まります。");

        // 止めるのは major だけであること(他の種別まで並べると効きすぎる)
        var updateTypes = ((YamlSequenceNode)updateTypesNode!).Children
            .OfType<YamlScalarNode>()
            .Select(node => node.Value ?? "")
            .ToList();
        Assert.Equal(new[] { SemverMajorUpdateType }, updateTypes);

        // versions による追加の絞り込みが無いこと(保留の範囲を静かに変えるため置かせない)
        Assert.False(entry.Children.ContainsKey(new YamlScalarNode(IgnoreVersionsKey)),
            $"dependabot.yml の {SqlClientPackageId} の保留に {IgnoreVersionsKey}: を足さないでください。"
            + $"{IgnoreUpdateTypesKey} だけでメジャー更新を止めます。");
    }

    [Fact]
    public void DependabotConfig_BundlesEfCorePackagesForVersionAndSecurityUpdates()
    {
        // 通常の版更新を束ねるグループの対象一覧
        var versionUpdatePatterns = ReadGroupList(EfCoreGroupName, PatternsKey);
        // セキュリティ更新を束ねるグループの対象一覧
        var securityUpdatePatterns = ReadGroupList(EfCoreSecurityGroupName, PatternsKey);

        // 2 つの EF Core グループは同じ顔ぶれであること。片方にだけ足すと、そのパッケージは
        // 通常の版更新とセキュリティ更新で扱いが変わり、片方の経路だけ単独 PR に戻ってしまう。
        // 並び順は Dependabot の挙動に影響しないため集合として比較する(整列しただけで CI が
        // 赤くなると、規約が守られていないのではなく検査が硬すぎるという偽陽性になる)
        AssertSameSet($"{EfCoreGroupName}.{PatternsKey}", versionUpdatePatterns,
            $"{EfCoreSecurityGroupName}.{PatternsKey}", securityUpdatePatterns);

        // 2 つのグループが実際に別々の更新種別を受け持っていること。
        // applies-to の既定は version-updates なので、セキュリティ側で指定を忘れると
        // 両グループとも通常の版更新を見に行き、CVE 対応の更新が束ねを素通りする
        Assert.Equal(VersionUpdates, ReadGroupScalar(EfCoreGroupName, AppliesToKey));
        Assert.Equal(SecurityUpdates, ReadGroupScalar(EfCoreSecurityGroupName, AppliesToKey));

        // 束ねる範囲を後から狭めるキーが足されていないこと。
        // patterns が正しくても update-types や exclude-patterns を書き足せば束ねを骨抜きにできる
        // (update-types: [minor, patch] にすると major が再びプロバイダごとの単独 PR に戻る)
        foreach (var groupName in EfCoreGroupNames) AssertOnlyAllowedKeys(groupName);
    }

    [Fact]
    public void EfCorePackages_DoNotLeakIntoTheMinorAndPatchBundle()
    {
        // 2 つの EF Core グループが「EF Core 系」と定義しているパターンを読み出す。
        // 【なぜ別の Fact か】同じ Fact に置くと、先に走る AssertSameSet(2 グループの
        // 一致検査)が throw した時点でこの検査は実行されない。実際、セキュリティ側にだけ
        // パターンを足して除外を書き忘れると、集合の不一致を直して再実行するまで
        // 漏れが見えなかった。独立させて 1 回の実行で両方が分かるようにする
        // minor / patch グループが EF Core 系を 1 つも拾わないこと。
        // 【なぜパターン文字列を突き合わせないか】ここでの不変条件は「EF Core 系が minor/patch の
        // 束ねへ紛れ込まないこと」であって、除外一覧の書き方ではない。文字列集合として比べると、
        // 例えば除外を "Npgsql*" と広めに書いた設定は不変条件を満たしているのに
        // "Npgsql.EntityFrameworkCore.PostgreSQL" と一致しないという理由だけで CI が赤くなる
        // (規約違反ではなく検査が硬すぎる偽陽性)。実際のパッケージ ID が拾われるかどうかで
        // 判定すれば、書き方の揺れに左右されず不変条件そのものを固定できる。
        //
        // 判定対象は MatchTargetsOf に任せる(解決済み ID ＋ パターンが表す範囲の代表値)
        // minor / patch グループの判定器をキャッシュから引く(§8)
        var minorAndPatchMatcher = MatcherOf(MinorAndPatchGroupName);
        // 【なぜ全グループの和集合を見るか】版更新側だけを見ると、セキュリティ側にだけ
        // 足されたパターンの除外漏れが視野に入らない。しかも AssertSameSet(別 Fact)が
        // 先に落ちても、こちらは独立に走って漏れを報告できる
        // 【なぜ EfCoreGroupNames を回すか】2 グループを直に書くと、グループを足したとき
        // ここだけ更新から漏れて、そのグループのパターンが除外検査の対象外になる(§6)
        var allEfCorePatterns = EfCoreGroupNames
            // 各グループが「EF Core 系」と定義しているパターンを集める
            .SelectMany(groupName => ReadGroupList(groupName, PatternsKey))
            // 同じパターンを 2 度照合しないよう重複を除く
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        // 解決済みの EF Core 系 ID と、各パターンが表す範囲の代表値を突き合わせ対象にする
        var leakedIntoMinorAndPatch = MatchTargetsOf(allEfCorePatterns)
            // minor / patch グループに拾われてしまうものだけを残す
            .Where(minorAndPatchMatcher.Matches)
            .ToList();
        // 紛れ込みが無いこと(あれば、どのパッケージが拾われているかを示す)
        Assert.True(leakedIntoMinorAndPatch.Count == 0,
            $"EF Core 系パッケージが dependabot.yml の {MinorAndPatchGroupName} に拾われています: "
            + $"[{string.Join(", ", leakedIntoMinorAndPatch)}]\n"
            + $"{MinorAndPatchGroupName}.{ExcludePatternsKey} に当てはまるパターンを追加して、"
            + "EF Core 系が minor / patch の束ねへ紛れ込まないようにしてください。"
            // 代表値が 1 つも含まれないのに注記だけ出ると、読み手は在りもしない
            // 目印を一覧から探すことになるので、含まれるときだけ添える
            + (leakedIntoMinorAndPatch.Any(id => id.Contains(WildcardPlaceholder, StringComparison.Ordinal))
                ? $"\n({WildcardPlaceholder} を含むものは実在のパッケージ名ではなく、"
                  + "そのパターンが表す同族すべてを表す代表値です。)"
                : ""));
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
        foreach (var groupName in EfCoreGroupNames) AssertNotShadowed(groupNames, groupName);
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
        // 解決済みの ID と、各パターンが表す範囲の代表値をあわせて対象にする
        var efCorePackageIds = MatchTargetsOf(efCorePatterns);

        // 先に定義されたグループのうち、EF Core 系を横取りしうるものを探す
        var shadowing = groupNames
            .Take(index)
            // 更新種別が違うグループ同士は解決の土俵が別なので横取りしない
            .Where(name => string.Equals(GroupScopeOf(name), scope, StringComparison.Ordinal))
            // メジャー更新を受け持たないグループは、この不変条件(メジャー版の一致)を壊さない
            .Where(name => TakesUpdateType(name, MajorUpdateType))
            // 【dependency-type で絞り込まない理由】「開発依存だけのグループは本番依存の
            // EF Core 系を拾わない」と考えたくなるが、前提が成り立たない。
            // Microsoft.EntityFrameworkCore.Design は csproj で PrivateAssets=all を指定して
            // おり、Dependabot からは開発依存に見える。この除外を入れると、開発依存に絞った
            // 先行グループが Design を吸い込む経路を見逃す。Design は Relational を推移依存に
            // 持つため、その単独 major PR をマージすれば版ズレが再発する。
            // 絞り込みキーの解釈を増やすほど見逃しが生まれるので、ここは保守的に倒す
            // (誤検出はレビューで気付けるが、見逃しは PostgreSQL 配備でしか現れない)
            // 判定器は 1 度だけ読み出したキャッシュから引く(§8)
            .Select(name => (Name: name, Matcher: MatcherOf(name)))
            // 実際に EF Core 系パッケージを拾ってしまうか
            .Where(candidate => efCorePackageIds.Any(candidate.Matcher.Matches))
            .Select(candidate => candidate.Name)
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

    // 指定グループが、その大きさの更新を受け持つかどうかを返す(update-types 未指定なら全種別が対象)
    private static bool TakesUpdateType(string groupName, string updateType) =>
        // 種別が絞られていなければ全て受け持つ。絞られていれば、その種別が含まれるかを見る
        TryReadGroupList(groupName, UpdateTypesKey) is not { } updateTypes
        || updateTypes.Contains(updateType, StringComparer.OrdinalIgnoreCase);

    // その大きさの更新で、指定パッケージを実際に受け取るグループ名を返す(どれにも入らなければ null)。
    // 【なぜ先頭から探すか】Dependabot は「最初に一致したグループ」にだけ依存関係を入れる。
    // 名指ししたグループへ直接尋ねると、手前に置かれた別のグループが先に攫っていく経路を見逃す
    private static string? OwningGroupOf(string packageId, string updateType) =>
        // 定義順に並べたグループを順に見て、種別と対象の両方に当てはまる最初のものを返す
        VersionUpdateGroups.Value
            // その大きさの更新を受け持たないグループは、この更新を奪わない
            .Where(name => TakesUpdateType(name, updateType))
            // 対象に当てはまる最初のグループが、実際の入り先になる
            .FirstOrDefault(name => MatcherOf(name).Matches(packageId));

    // 通常の版更新を受け持つグループを、定義順に並べたもの。
    // 【なぜ applies-to で絞るか】セキュリティ更新専用のグループは通常の版更新を奪わない。
    // 絞らずに先勝ち判定をすると、"applies-to: security-updates" の広いグループを
    // 手前に置いただけで「そちらへ入る」と誤判定する(AssertNotShadowed と同じ考え方)
    private static readonly Lazy<IReadOnlyList<string>> VersionUpdateGroups =
        new(() => ReadNuGetGroupNamesInOrder()
            // 通常の版更新を受け持つグループだけを、定義順のまま残す
            .Where(name => GroupScopeOf(name) == VersionUpdates)
            .ToList());

    // キャッシュから判定器を引く。見つからないときは、生の KeyNotFoundException ではなく
    // 「どのグループが失われたか」と、その結果どうなるかを示して落とす
    // (グループ名を変えた場合に、原因の分からない例外だけが飛ぶのを避ける)
    private static GroupMatcher MatcherOf(string groupName)
    {
        // 名前で引けたらそれを返す
        if (GroupMatchers.Value.TryGetValue(groupName, out var matcher)) return matcher;
        // 引けないのは、そのグループが消えたか名前が変わったということ
        Assert.Fail($"dependabot.yml の {EcosystemKey}: \"{NuGetEcosystem}\" 配下に {groupName} グループが"
            + "見つかりません。束ねの設定が外れると、パッケージごとに単独の PR が作られます。");
        // Assert.Fail は必ず throw するのでここには到達しない
        return default;
    }

    // グループ名 → 判定器。1 度だけ読み出して使い回す(§8)
    private static readonly Lazy<IReadOnlyDictionary<string, GroupMatcher>> GroupMatchers =
        new(() => ReadNuGetGroupNamesInOrder().ToDictionary(name => name, ReadGroupMatcher, StringComparer.Ordinal));

    // 1 つのグループが「どのパッケージを自分のものとして拾うか」を表す判定器。
    //
    // 【なぜ判定のたびに YAML を読まないのか】判定は「候補グループ × パッケージ ID」の組で行うため、
    // 呼び出しのたびに読み直すと 1 グループあたりパッケージ数だけ YAML マッピングの線形探索と
    // List の再生成が走る。読み出しを一度きりにして、以降は純粋な照合だけにする(§8)
    private readonly record struct GroupMatcher(IReadOnlyList<string>? Patterns, IReadOnlyList<string>? ExcludePatterns)
    {
        // そのパッケージ ID をこのグループが拾うかどうかを返す
        public bool Matches(string packageId) =>
            // 除外指定に当てはまるなら拾わない
            (ExcludePatterns is not { } excluded || !MatchesAnyPattern(packageId, excluded))
            // 対象指定が書かれていれば当てはまるかを見る。書かれていなければ全てに一致する
            && (Patterns is not { } patterns || MatchesAnyPattern(packageId, patterns));
    }

    // 指定グループの patterns / exclude-patterns を 1 度だけ読み出して判定器を作る
    private static GroupMatcher ReadGroupMatcher(string groupName) =>
        // どちらのキーも「書かれていなければ null」で、その意味づけは GroupMatcher が持つ
        new(TryReadGroupList(groupName, PatternsKey), TryReadGroupList(groupName, ExcludePatternsKey));

    // 指定パターンについて「グループが拾うかどうか」を確かめる対象を返す。
    //
    // 【なぜ解決済み ID だけでは足りないか】まだ csproj に無いプロバイダを patterns へ
    // 先に書いた場合、解決済み ID が 1 つも無いので検査が空振りし、除外の書き忘れや
    // 横取りが「実際にそのパッケージを参照する PR」まで検出されない。その PR の作者は
    // 「パッケージを足しただけ」なのに無関係に見える失敗を受け取ることになる。
    // パターンが表す範囲の代表値も混ぜて、パターンを足した時点で分かるようにする
    private static IReadOnlyList<string> MatchTargetsOf(IReadOnlyList<string> patterns) =>
        // 解決済みの ID と代表値を合わせ、重複を除いて返す
        EfCorePackageIdsMatching(patterns)
            .Concat(patterns.SelectMany(RepresentativeIdsOf))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    // 指定パターンに一致する、ロックファイル上のパッケージ ID を重複なく返す。
    // 【なぜ読み出し済みのパターンを受け取るか】呼び出し側が既に patterns を読んでいる場面が
    // あり、グループ名を渡す形にすると同じキーを 2 度読むことになるため(§8)
    // (重複除去は呼び出し側の MatchTargetsOf がまとめて行う)
    private static IEnumerable<string> EfCorePackageIdsMatching(IReadOnlyList<string> patterns) =>
        // 解決済みパッケージのうちパターンに当てはまるものの ID を返す
        ResolvedPackages.Value
            .Where(package => MatchesAnyPattern(package.Id, patterns))
            .Select(package => package.Id);

    // ワイルドカードの位置に差し込む目印。実在の ID ではなく「ここには何が来てもよい」ことを
    // 表す代表値の一部で、失敗メッセージにそのまま出るため、読み手が
    // 「これは代表値であって実在のパッケージ名ではない」と分かる字面にしている
    private const string WildcardPlaceholder = "<任意>";

    // パターンが表す集合から、除外の網を確かめるための代表値を返す。
    //
    // 【何のために使うか】まだロックファイルに現れていないパターンでも、除外の書き忘れを
    // その場で検出できるようにする。返すのはいずれもパターンが表す集合の実際の要素なので、
    // どれかが除外に当たらなければ集合の少なくとも 1 要素が漏れている＝本物の漏れになる。
    // 【なぜ前置詞だけでは足りないか】"Pomelo.EntityFrameworkCore.MySql*" に対して前置詞だけを
    // 見ると、除外に "Pomelo.EntityFrameworkCore.MySql"(末尾 '*' 無し)と書いただけで通ってしまう。
    // 実際には .Design や .NetTopologySuite といった同族が minor / patch へ流れるのに、
    // 前置詞は「最も狭い除外にも覆われる要素」なので漏れを代表できない。
    // 【なぜ末尾以外の '*' も対象にするか】"*EFCore*" のような書き方を代表値なしで素通りさせると、
    // そのパターンがロックファイルに現れるまで除外の書き忘れを誰も検出できない。
    // '*' を目印へ置き換えた文字列は位置によらずパターンの一致例なので、同じ理屈で漏れを問える
    private static IEnumerable<string> RepresentativeIdsOf(string pattern)
    {
        // 空のパターン(YAML に `- ` とだけ書いた場合など)は代表値を作らない。
        // 空文字列を返すと失敗メッセージに空要素が並ぶだけで何も伝わらない
        if (pattern.Length == 0) return Array.Empty<string>();
        // ワイルドカードが無ければ、そのパターン自身がただ 1 つの一致例
        if (!pattern.Contains('*')) return new[] { pattern };
        // '*' を目印へ置き換えると、パターンが表す集合の要素が 1 つ得られる
        var representatives = new List<string> { pattern.Replace("*", WildcardPlaceholder) };
        // 末尾の '*' を取り除いた前置詞。「続きが何も無い」場合を表す
        var prefix = pattern.EndsWith('*') ? pattern[..^1] : null;
        // 前置詞が空でなく、かつワイルドカードが残らないときだけ代表に加える。
        // 残る場合(例: "*EFCore*" → "*EFCore")は ID ではなくパターンに見えて読み手を惑わせるうえ、
        // 目印へ置き換えた側が同じ集合をすでに代表している。空になる場合(パターンが "*" だけ)は
        // 失敗メッセージに空要素が並ぶだけで何も伝えないので載せない
        if (prefix is { Length: > 0 } && !prefix.Contains('*')) representatives.Add(prefix);
        // 集めた代表値を返す
        return representatives;
    }

    // 指定パッケージについて、nuget エコシステムの ignore: に書かれたエントリを集める。
    // ignore: 自体が無ければ空一覧を返す(「保留が消えた」ことは呼び出し側が件数で報告する)
    private static IReadOnlyList<YamlMappingNode> ReadIgnoreEntriesFor(string packageId)
    {
        // エントリ直下の ignore: を引く。無ければ保留が 1 つも無い状態
        if (!NuGetEcosystemEntry.Value.Children.TryGetValue(new YamlScalarNode(IgnoreKey), out var ignore))
            return Array.Empty<YamlMappingNode>();
        // 一覧として書かれていることを確かめる(単一値なら設定ミスなので場所を示して落とす)
        Assert.True(ignore is YamlSequenceNode,
            $"dependabot.yml の {EcosystemKey}: {NuGetEcosystem} の {IgnoreKey}: が一覧ではありません。");
        // 対象パッケージ名が一致するエントリだけを集める。
        // NuGet のパッケージ ID は大文字小文字を区別しないので比較も区別しない
        return ((YamlSequenceNode)ignore!).Children
            .OfType<YamlMappingNode>()
            .Where(entry => entry.Children.TryGetValue(new YamlScalarNode(DependencyNameKey), out var name)
                && string.Equals((name as YamlScalarNode)?.Value, packageId, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    // あるパッケージが「自分はこの版を前提にしている」と宣言している依存の版を、
    // ロックファイルの dependencies から読み出す。
    // 【なぜ resolved ではなく宣言側を読むのか】期待値をテストへ書き写すと、EF Core を
    // 上げたときに 2 か所を直す必要が生まれ、直し忘れた側が静かに古い前提を主張し続ける。
    // 宣言側から読めば、EF Core の更新に検査が自動で追随する(§6 の唯一の真実の源)
    private static string ReadDeclaredDependencyVersion(string dependentId, string dependencyId)
    {
        // 見つかった宣言を溜める入れ物(プロジェクトごとに別々に書かれうるので集めて突き合わせる)
        var declarations = new List<string>();
        // 各プロジェクトの隣にあるロックファイルを 1 つずつ読む
        foreach (var projectFile in SolutionProjects.Value)
        {
            // プロジェクトと同じディレクトリのロックファイルを指す
            var lockFile = LockFilePathOf(projectFile);
            // 欠けている場合は EveryProject_HasCommittedLockFile が専任で報告するので飛ばす
            if (!File.Exists(lockFile)) continue;
            // ロックファイルを JSON として解析する
            using var document = JsonDocument.Parse(File.ReadAllText(lockFile));
            // 解決結果が無い書式変更は ReadAllResolvedPackages が報告するのでここでは飛ばす
            if (!document.RootElement.TryGetProperty(DependenciesKey, out var frameworks)) continue;
            // ターゲットフレームワークごとに解決結果を見る
            foreach (var framework in frameworks.EnumerateObject())
            {
                // 対象パッケージの項目が無ければ、このフレームワークには宣言が無い
                if (!framework.Value.TryGetProperty(dependentId, out var dependent)) continue;
                // その項目が持つ依存の一覧を引く(依存を持たないパッケージもある)
                if (!dependent.TryGetProperty(DependenciesKey, out var declared)) continue;
                // 探している依存の版が書かれていれば控える
                if (declared.TryGetProperty(dependencyId, out var version))
                    declarations.Add(version.GetString() ?? "");
            }
        }

        // 宣言が 1 つも読めないのは検出網の劣化(パッケージ名の変更・書式変更)なので落とす
        Assert.True(declarations.Count > 0,
            $"{LockFileName} から {dependentId} が宣言する {dependencyId} の版を読み取れませんでした。"
            + "パッケージ名かロックファイルの書式が変わった可能性があります"
            + "(読み取れないまま素通りさせると、検査があるのに何も見ていない状態になります)。");

        // 複数のプロジェクトで宣言が食い違う場合、どれを正とするか決められないので落とす(fail-closed)
        var distinct = declarations.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        Assert.True(distinct.Count == 1,
            $"{dependentId} が宣言する {dependencyId} の版がロックファイル間で食い違っています: "
            + $"[{string.Join(", ", distinct)}]");

        // 一意に定まった宣言版を返す
        return distinct[0];
    }

    // 指定パッケージの解決済みの版を読み出す(複数プロジェクトで食い違えば落とす)
    private static string ReadResolvedVersion(string packageId)
    {
        // 全ロックファイルから、その ID で解決されている版を集める
        var versions = LockEntriesFor(packageId)
            .Select(package => package.Version)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 1 件も無いのは、参照が消えたか検出網が劣化したかのどちらか
        Assert.True(versions.Count > 0,
            $"{LockFileName} に {packageId} の解決済みの版がありません。参照が外れた可能性があります。");
        // 食い違う版が同居しているとどれが読み込まれるか決まらないので落とす
        Assert.True(versions.Count == 1,
            $"{packageId} の解決済みの版がロックファイル間で食い違っています: [{string.Join(", ", versions)}]");

        // 一意に定まった解決版を返す
        return versions[0];
    }

    // 指定パッケージが全ロックファイルでどう記録されているかを集める。
    // 【なぜ切り出すか】「ID で照合して該当行を集める」は解決版の読み出しと
    // 直接参照の検査の 2 箇所で必要になる。照合規則(大文字小文字を無視する等)を
    // 書き写すと、片方だけ直したときにもう片方の検査が静かに意味を変える(§6 DRY)
    private static IReadOnlyList<ResolvedPackage> LockEntriesFor(string packageId) =>
        // ID が一致する行だけを残して一覧にする
        ResolvedPackages.Value
            .Where(package => string.Equals(package.Id, packageId, StringComparison.OrdinalIgnoreCase))
            .ToList();

    // 版文字列からメジャー版(最初のドットまで)を取り出す
    private static int MajorOf(string version)
    {
        // 先頭からドットまでを切り出す(ドットが無ければ全体をメジャーとみなす)
        var dot = version.IndexOf('.');
        var head = dot < 0 ? version : version[..dot];
        // 数値として読めなければ、版の書式が想定外なので落とす(fail-closed)
        Assert.True(int.TryParse(head, out var major),
            $"版 \"{version}\" からメジャー版を読み取れませんでした。");
        // 読み取ったメジャー版を返す
        return major;
    }

    // 2 つの版文字列を数値として比較する(左が大きければ正、等しければ 0、小さければ負)。
    // 【なぜ文字列比較にしないか】"5.1.10" と "5.1.7" を文字列で比べると前者が小さくなり、
    // 床値が下がったことを見逃す
    private static int CompareVersions(string left, string right)
    {
        // プレリリース表記(-preview 等)を落としてから数値部分だけを比べる
        static int[] Parts(string version) => version.Split('-')[0]
            .Split('.')
            .Select(part => int.TryParse(part, out var value) ? value : 0)
            .ToArray();

        // 左右それぞれの数値列を得る
        var l = Parts(left);
        var r = Parts(right);
        // 長い方の桁数まで、上位から順に比べる(足りない桁は 0 として扱う)
        for (var i = 0; i < Math.Max(l.Length, r.Length); i++)
        {
            // その桁の値を取り出す(範囲外は 0)
            var a = i < l.Length ? l[i] : 0;
            var b = i < r.Length ? r[i] : 0;
            // 差があればその時点で大小が決まる
            if (a != b) return a.CompareTo(b);
        }
        // すべての桁が等しければ同じ版
        return 0;
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
            + $"{ExcludePatternsKey} や {UpdateTypesKey} を足すと束ねる範囲が狭まり、"
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

    // パッケージ ID の一部として使われうる文字(この文字が前後に続く一致は、
    // 別のもっと長いパッケージ名の一部を拾っただけとみなす)。
    // 【なぜ char.IsLetterOrDigit を使わないか】日本語の仮名・漢字も「文字」と判定されるため、
    // 「Microsoft.AspNetCore.Identity.EntityFrameworkCore は公開 API しか使わず」のように
    // 助詞が続く自然な日本語(語間に空白を置かない)を「名前の一部」と誤読し、
    // きちんと説明されているのに「説明がありません」で落ちる。NuGet のパッケージ ID に
    // 使えるのは ASCII の英数字と . _ - だけなので、その範囲に限って判定する
    private static bool IsPackageIdChar(char c) =>
        c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or '-';

    // 指定位置から step 方向へ見て、そこに「名前の続き」があるかどうかを返す。
    // 【なぜ方向を引数にするか】前側と後ろ側で同じ規則を使う必要があり(片方だけ直すと
    // 判定が非対称になる)、違いは走査の向きだけだったため 1 つにまとめる
    private static bool HasPackageIdNeighbor(string text, int index, int step)
    {
        // 範囲外なら隣接する ID の文字は無い
        if (index < 0 || index >= text.Length) return false;
        // ID を構成しない文字なら、そこで名前は途切れている
        if (!IsPackageIdChar(text[index])) return false;
        // 区切り文字以外なら、それ自体が名前の一部
        if (text[index] is not ('.' or '_' or '-')) return true;
        // 区切り文字は、さらにその先にも ID の文字があるときだけ「名前の途中」とみなす
        var next = index + step;
        return next >= 0 && next < text.Length && IsPackageIdChar(text[next]);
    }

    // 本文がそのパッケージ名に「言及している」かを返す。
    //
    // 【なぜ単純な部分文字列照合では足りないか】例えば "Npgsql" を除外一覧へ足したとき、
    // 散文に "Npgsql.EntityFrameworkCore.PostgreSQL" と書いてあるだけで
    // 「説明済み」と判定されてしまう。実際にはなぜ Npgsql を束ねないのかが一言も書かれていない
    // のに検査が通り、しかもそれは最も説明が要る場面。前後がパッケージ ID の続きに見えない
    // 位置で現れたときだけ、その名前について書かれているとみなす
    private static bool MentionsPackageName(string text, string packageId)
    {
        // 見つかった位置から順に、次の候補を探していく
        for (var index = text.IndexOf(packageId, StringComparison.OrdinalIgnoreCase);
             index >= 0;
             index = text.IndexOf(packageId, index + 1, StringComparison.OrdinalIgnoreCase))
        {
            // 直前にも ID の続きが無いこと。区切り文字( . _ - )は、そのさらに手前に
            // ID の文字があるときだけ「長い名前の途中」とみなす(箇条書きの "- Npgsql" や
            // 文の区切りの ".Npgsql" を名前の一部と誤読しないため。後ろ側と対称にする)
            var startsCleanly = !HasPackageIdNeighbor(text, index - 1, step: -1);
            // 直後の位置を求める
            var end = index + packageId.Length;
            // 直後にも ID の続きが無いこと(文末の句点などは「続き」とみなさない)
            var endsCleanly = !HasPackageIdNeighbor(text, end, step: 1);
            // 前後とも区切れていれば、その名前そのものへの言及とみなす
            if (startsCleanly && endsCleanly) return true;
        }
        // 独立した言及が 1 つも無かった
        return false;
    }

    // そのプロジェクトの隣にあるロックファイルの絶対パスを返す。
    // 【なぜ共通化するか】同じ組み立てが「欠落の検査」「解決済みの読み出し」「除外一覧の
    // 実在検査」の 3 箇所に現れていた。ロックファイルの置き場所が変わったとき、
    // 直し漏れた検査だけが静かに意味を変えるのを防ぐ
    private static string LockFilePathOf(string projectFile) =>
        // プロジェクトファイルと同じディレクトリに置かれる決まり
        Path.Combine(Path.GetDirectoryName(projectFile)!, LockFileName);

    // リポジトリルートからの相対パスでファイルを読む。存在しなければ、その事実を示して落とす。
    // 【なぜ共通化するか】「絶対パスを組み立てる → 存在を確かめる → 読む」の 3 行が
    // ソリューション・dependabot.yml・散文の 3 箇所に現れ、失敗メッセージの言い回しだけが
    // 少しずつ違っていた。ファイルが無いときの報告を 1 箇所に揃える(§6)
    private static string ReadRepositoryFile(string relativePath)
    {
        // リポジトリルートからの絶対パスを組み立てる
        var path = Path.Combine(RepositoryPaths.Root, relativePath);
        // 見つからないまま先へ進むと検査が空振りするので、ここで落とす。
        // 絶対パスも示す(リポジトリルートの解決自体がずれている場合、
        // 相対パスだけでは「移動した」のか「探す場所を間違えた」のかが分からない)
        Assert.True(File.Exists(path),
            $"{relativePath} が見つかりません(移動・リネーム、または探索の起点がずれている"
            + $"可能性があります)。探した場所: {path}");
        // 本文をすべて読み出して返す
        return File.ReadAllText(path);
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
            var lockFile = LockFilePathOf(projectFile);
            // 欠けている場合は EveryProject_HasCommittedLockFile が専任で報告するのでここでは飛ばす
            // (同じ事実で 2 つのテストが落ちると、原因が 2 種類あるように見えて読み手を惑わせる)
            if (!File.Exists(lockFile)) continue;
            // 失敗メッセージ用に、リポジトリルートからの相対パスにしておく
            var project = Path.GetRelativePath(RepositoryPaths.Root, lockFile);
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
        // 各行から csproj の相対パスを抜き出し、絶対パスへ直す
        var projects = SolutionProjectRegex.Matches(ReadRepositoryFile(SolutionFileName))
            // ソリューションは Windows 形式の区切りで書かれるため、実行環境の区切りへ直す
            .Select(match => match.Groups["path"].Value.Replace('\\', Path.DirectorySeparatorChar))
            // リポジトリルートからの絶対パスにする
            .Select(relativePath => Path.Combine(RepositoryPaths.Root, relativePath))
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
            + string.Join("\n", missing.Select(path => $"  {Path.GetRelativePath(RepositoryPaths.Root, path)}")));
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
    private static readonly Lazy<YamlMappingNode> NuGetEcosystemEntry = new(ReadNuGetEcosystemEntry);

    // nuget エコシステムの groups: 定義。解析結果を複数のテストで共有する(§8)
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
        // 要素のうち、単一値として書かれていないものを集める。
        // 【なぜ素のキャストで済ませないか】`- name: "Npgsql..."` のような書き間違いがあると
        // InvalidCastException だけが飛び、どのファイルのどのキーが原因かが分からない。
        // このファイルの他の異常系と同じく、場所を示して落とす
        // 以降で 2 度参照するので、一覧として 1 度だけ受け取っておく
        var sequence = (YamlSequenceNode)node;
        // 何番目の要素かと YAML 上の行番号を添える(件数だけでは一覧を目視で追う羽目になる)
        var malformed = sequence.Children
            .Select((item, index) => (Item: item, Index: index))
            .Where(entry => entry.Item is not YamlScalarNode)
            .Select(entry => $"{entry.Index + 1} 番目(行 {entry.Item.Start.Line})")
            .ToList();
        // 単一値でない要素が無いこと(あれば、何番目の何行目かを示す)
        Assert.True(malformed.Count == 0,
            $"dependabot.yml の {groupName}.{key} に、単一値でない要素があります: "
            + $"[{string.Join(", ", malformed)}]\n"
            + "一覧の各要素はパターン文字列などの単一値である必要があります。");

        // 各要素を文字列として取り出す
        var values = sequence.Children.Select(item => ((YamlScalarNode)item).Value ?? "").ToList();
        // 中身が空の要素を集める。
        // 【なぜ空を拒むか】プロバイダの行を消したあとに `- ` だけが残ると、空パターンは
        // どのパッケージにも一致せず、どこからも文句が出ないまま静かに無効な行として居座る。
        // `- name: x` のような書き間違いは落とすのに空だけ通すのは方針が揃わない(fail-closed)
        var blank = values
            .Select((value, index) => (Value: value, Index: index))
            .Where(entry => string.IsNullOrWhiteSpace(entry.Value))
            .Select(entry => $"{entry.Index + 1} 番目")
            .ToList();

        // 空の要素が無いこと(あれば、何番目かを示す)
        Assert.True(blank.Count == 0,
            $"dependabot.yml の {groupName}.{key} に、中身が空の要素があります: "
            + $"[{string.Join(", ", blank)}]\n"
            + "空のパターンはどのパッケージにも一致しないため、消し忘れた行の可能性があります。");

        // 検査を通った一覧を返す
        return values;
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
    private static string? TryReadGroupScalar(string groupName, string key)
    {
        // そのキーが書かれていなければ「指定なし」として null を返す
        if (!ReadGroup(groupName).Children.TryGetValue(new YamlScalarNode(key), out var node)) return null;
        // 単一値として書かれていることを確かめる。
        // 【なぜ握り潰さないか】ここで null を返すと、呼び出し元の GroupScopeOf が既定値
        // version-updates へ落ちる。applies-to: ["security-updates"] のような一覧記法で
        // 書かれたセキュリティ更新のグループは「通常の版更新のグループ」と誤認され、
        // 横取り検査の対象から静かに外れる(実際に横取りしていても green のまま通る)。
        // 同ファイルの TryReadGroupList / MajorVersionOf と同じく fail-closed に倒す
        Assert.True(node is YamlScalarNode,
            $"dependabot.yml の {groupName}.{key} が単一値ではありません。"
            + "一覧やマッピングで書かれていると既定値として扱われ、検査対象から静かに外れます。");
        // 値を文字列として取り出す
        return ((YamlScalarNode)node).Value;
    }

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
        // nuget エコシステムの設定エントリを取り出し、そこから groups: を読む
        var nugetEntry = NuGetEcosystemEntry.Value;
        // そのエントリの groups: を取り出す
        Assert.True(nugetEntry.Children.TryGetValue(new YamlScalarNode(GroupsKey), out var groups)
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

    // dependabot.yml から nuget エコシステムの設定エントリそのものを読み出す。
    // 【なぜ groups: の取り出しと分けるか】エントリ直下には groups: のほかに ignore: も置かれ、
    // 後者は SqlClient の major 保留(SqlClientPin_StaysWithinEfCoreDeclaredMajor 参照)が読む。
    // 以前はこの関数が groups: だけを返してエントリを捨てていたため、同じ YAML を
    // もう一度解析しないと ignore: へ辿り着けなかった(§6 DRY)
    private static YamlMappingNode ReadNuGetEcosystemEntry()
    {
        // YAML として解析する。同名キーの重複などで解析できない場合は、原因を添えて落とす
        // (重複キーは YAML では後勝ちで、検査と Dependabot が別の定義を見る食い違いの元になる)
        var stream = new YamlStream();
        try
        {
            using var reader = new StringReader(ReadRepositoryFile(DependabotConfigPath));
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

        // 読み取ったエントリを返す(groups: / ignore: の取り出しは呼び出し側が行う)
        return nugetEntries[0];
    }
}
