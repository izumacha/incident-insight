// csproj を XML として読むために取り込む
using System.Xml.Linq;

// リポジトリ内のパスとロックファイルを読む共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Packaging;

// Guard-rail test: 本番プロジェクトが直接参照する NuGet パッケージを、理由付きの表と突き合わせる。
//
// 【発端】Dependabot の nuget updater は、ロックファイルを持つプロジェクトの推移依存を更新するために
// その依存を「直接参照へ昇格させる」。実際 PR #267 は、テストプロジェクトが「本番アセンブリには入らない」と
// 明記している解析用の依存 Microsoft.CodeAnalysis.CSharp を、本番の Web プロジェクトの直接参照として
// 足していた(Web 側では Microsoft.EntityFrameworkCore.Design 経由の推移依存だったため更新対象として
// 掴まれた)。つまりこの形は「テスト専用のはずの依存が本番プロジェクトへ入る」経路になる。
//
// 【なぜ既存の検出網では足りないか】あの PR が赤くなったのは偶然にすぎない。
// Microsoft.EntityFrameworkCore.Design が Microsoft.CodeAnalysis.Common を完全一致 (= 4.8.0) でピンして
// いたため NU1107 の版衝突になり、本番プロジェクト単体を locked-mode で復元する Docker ジョブが落ちた。
// 完全一致のピンを持たない推移依存が同じ形で昇格した場合、復元は成功するので
// ビルドも全テストも Docker イメージも緑のまま、本番イメージに解析器やコンパイラが同梱される
// (サイズと供給網の面が黙って広がる。§9「新規依存は最小限に絞って出所・メンテ状況を確認する」)。
// しかも実測では、あの PR で build-and-test は 0 Warning / 0 Error で緑だった
// (solution 単位の locked-mode restore はロックファイルと一致していれば版衝突を報告しない)。
// 赤くなったのは Docker ジョブ 1 本だけで、診断も Docker のレイヤ内の NU1107 だった。
// だから「昇格そのもの」を、版衝突が起きるかどうかとは無関係に、速くて読みやすい形で落とす。
//
// 【なぜ csproj ではなく packages.lock.json で顔ぶれを見るのか】ロックファイルは「実際に直接参照として
// 解決されたもの」の唯一の記録で、csproj の記述ゆれ(属性の並び・条件付き ItemGroup・将来の
// Directory.Build.props)に左右されない。ロックファイルだけを書き換える差分も同じ土俵で捕まる。
// CI と Dockerfile の locked-mode restore が、この記録と csproj の一致そのものを強制している。
//
// 【ただし「資産が実行時へ流れるか」はロックファイルに書かれていない】そこだけは csproj を読む。
// 詳しくは AssetFlow と ProductionProjects の説明を参照。
//
// 【表は人が判断するエスケープハッチ】「その依存を本番へ入れてよいか」は機械では決められないので、
// 判断の記録として理由を必須にしてある(AuditedEntityModel.LengthGovernanceExclusions と同じ扱い)。
// エントリが増える差分は、出所・メンテ状況・本番に入れる必要があることをレビューで必ず確認する。
public class ProductionDirectDependencyTests
{
    // その依存の資産(アセンブリ等)が、公開した本番出力へ流れるかどうか。
    //
    // 【なぜ表に持たせるか】ロックファイルは PrivateAssets / IncludeAssets を一切記録しない
    // (実測: Design の項目は contentHash / dependencies / requested / resolved / type だけを持つ)。
    // つまり csproj から PrivateAssets=all を落とす差分は、ロックファイルを 1 バイトも変えずに
    // 「Design の実行時資産とその推移閉包(Microsoft.CodeAnalysis.CSharp / .Common /
    // .CSharp.Workspaces / .Workspaces.MSBuild / Microsoft.Build.Framework)」を本番出力へ流す。
    // 顔ぶれの検査だけだと、この検査が塞いだと宣言しているのとまったく同じ結末(本番イメージに
    // コンパイラが同梱される)へ、別の経路で到達できてしまう。しかも表の理由欄が
    // 「ビルド時専用だから安全」と読み手に説明してしまうので、散文のままにはできない。
    private enum AssetFlow
    {
        // 実行時アセンブリとして本番出力へ流れる(通常のライブラリ参照)
        Runtime,

        // ビルド時にしか使わず、本番出力へ流れない(csproj で PrivateAssets=all を宣言する)
        BuildTimeOnly,
    }

    // 表の 1 行。理由は人が読むための記録で、資産の流れ方は下の検査が csproj と突き合わせる
    private record IntendedDependency(string Reason, AssetFlow Flow);

    // MSBuild で「その依存の資産を参照元へ流さない」ことを宣言するメタデータ名
    private const string PrivateAssetsMetadata = "PrivateAssets";

    // PrivateAssets / IncludeAssets で「すべての資産」を表す値
    private const string AllAssets = "all";

    // csproj で NuGet パッケージへの参照を表す要素名
    private const string PackageReferenceElement = "PackageReference";

    // 上記要素でパッケージ ID を指す属性名
    private const string IncludeAttribute = "Include";

    // csproj で「このプロジェクトはテストプロジェクトである」と宣言するプロパティ名。
    // この宣言を持つプロジェクトは本番出力に含まれないため、この不変条件の対象外になる
    private const string IsTestProjectProperty = "IsTestProject";

    // 本番プロジェクトが直接参照してよいパッケージと、その理由・資産の流れ方。
    // 外側のキーはプロジェクト名(csproj の拡張子を除いたファイル名)。
    //
    // 【なぜプロジェクトごとに分けるか】ID だけをキーにすると、2 つ目の本番プロジェクトが増えたときに
    // 1 つ目のために書いた承認がそのまま効いてしまう。issue #224 が同じ形の穴を記録している
    // (除外表のキーに画面を含めていなかったため、同名の引数を別の画面へ足すだけで根拠の無い除外が
    // 効き、差分にもテスト件数にも現れなかった)。プロジェクトを含めれば、2 つ目の本番プロジェクトは
    // 必ず「表に無い」として落ちる。
    //
    // 【版はここで管理しない】メジャー版の揃えは EfCorePackageAlignmentTests、床値と保留は
    // dependabot.yml と同テストが受け持つ。ここが見るのは「本番へ入れる顔ぶれと資産の流れ方」だけ。
    //
    // 【プロジェクト名をリテラルで書かない】リポジトリ構成の目印を書いてよいのは RepositoryPaths だけで、
    // RepositoryPathsUsageTests がそれを検査している。目印は共有ヘルパーの定数から読む
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, IntendedDependency>>
        IntendedProductionDependencies =
            // プロジェクト名も NuGet の ID も大文字小文字を区別しないため、引き方も区別しない
            new Dictionary<string, IReadOnlyDictionary<string, IntendedDependency>>(StringComparer.OrdinalIgnoreCase)
            {
                [RepositoryPaths.WebProjectDirectoryName] =
                    new Dictionary<string, IntendedDependency>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Microsoft.AspNetCore.Identity.EntityFrameworkCore"] = new(
                            "ASP.NET Core Identity を EF Core で永続化する(ApplicationUser と 3 ロールの基盤)。",
                            AssetFlow.Runtime),
                        ["Microsoft.Data.SqlClient"] = new(
                            "SQL Server 配備向け ADO.NET ドライバ。セキュリティ更新の床値として直接参照で"
                            + "ピンしている(理由は csproj のコメントと CLAUDE.md §3 が正本)。",
                            AssetFlow.Runtime),
                        ["Microsoft.EntityFrameworkCore.Design"] = new(
                            "EF Core マイグレーションの追加に必要。ビルド時専用で、実行時資産は本番出力へ"
                            + "流さない(この主張は下の DeclaredAssetFlow_MatchesTheTable が csproj と"
                            + "突き合わせる)。",
                            AssetFlow.BuildTimeOnly),
                        ["Microsoft.EntityFrameworkCore.Sqlite"] = new(
                            "既定の DB プロバイダ(単一ファイルの SQLite 配備)。", AssetFlow.Runtime),
                        ["Microsoft.EntityFrameworkCore.SqlServer"] = new(
                            "オンプレ病院向けの DB プロバイダ(既存 SQL Server 配備)。", AssetFlow.Runtime),
                        ["Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore"] = new(
                            "/health が DB 接続まで確認するためのヘルスチェック。", AssetFlow.Runtime),
                        ["Npgsql.EntityFrameworkCore.PostgreSQL"] = new(
                            "Linux / マネージド配備向けの DB プロバイダ(PostgreSQL)。", AssetFlow.Runtime),
                    },
            };

    // 本番プロジェクト(テストプロジェクトでないもの)の csproj。走査は 1 回で済むので結果を保持する
    private static readonly Lazy<IReadOnlyList<string>> ProductionProjects = new(FindProductionProjects);

    [Fact]
    public void EveryProductionProject_IsListedInTheTable()
    {
        // 表に無い本番プロジェクトを集める
        var unlisted = ProductionProjects.Value
            .Select(path => NameOf(path))
            .Where(name => !IntendedProductionDependencies.ContainsKey(name))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 本番プロジェクトが増えたのに登録を忘れると、そのプロジェクトだけが黙って検査から外れる
        Assert.True(unlisted.Count == 0,
            $"{nameof(IntendedProductionDependencies)} に登録されていない本番プロジェクトがあります:\n"
            + string.Join("\n", unlisted.Select(name => $"  {name}"))
            + "\n\n登録しないままだと、そのプロジェクトの直接参照は誰にも照合されません"
            + "(Dependabot が推移依存を直接参照へ昇格させても、この検査は何も言いません)。"
            + "直接参照の顔ぶれを理由付きで登録してください。");
    }

    [Fact]
    public void ProductionProjects_DeclareOnlyIntendedDirectDependencies()
    {
        // 表に載っていない直接参照を「プロジェクト名: パッケージ ID」の形で集める
        var unlisted = new List<string>();
        // 本番プロジェクトを 1 つずつ確認する
        foreach (var project in ProductionProjects.Value)
        {
            // そのプロジェクトの表(未登録なら空として扱い、専任の検査に報告を任せる)
            var intended = IntendedFor(project);
            // ロックファイルに直接参照として記録されているパッケージを 1 件ずつ見る
            foreach (var id in DirectPackagesOf(project))
            {
                // 表に無ければ違反として控える
                if (!intended.ContainsKey(id)) unlisted.Add($"{NameOf(project)}: {id}");
            }
        }

        // 1 件でもあれば、直し方(本番に入れるのか、入れないのか)を名指しして落とす
        Assert.True(unlisted.Count == 0,
            $"本番プロジェクトが、{nameof(IntendedProductionDependencies)} に無いパッケージを"
            + "直接参照しています:\n"
            + string.Join("\n", unlisted.OrderBy(line => line, StringComparer.Ordinal).Select(line => $"  {line}"))
            + "\n\nDependabot はロックファイルを持つプロジェクトの推移依存を更新するとき、その依存を"
            + "直接参照へ昇格させます(PR #267 がその実例で、テスト専用の解析パッケージが"
            + "本番プロジェクトへ入っていました)。心当たりがその PR なら、本番側の追加は取り消し、"
            + "宣言を持つプロジェクト(多くはテストプロジェクト)だけを上げてください。"
            + $"\n本当に本番へ入れる依存なら、{nameof(IntendedProductionDependencies)} へ理由と"
            + $"{nameof(AssetFlow)} を添えて登録してください"
            + "(出所とメンテ状況の確認はレビューで行います。§9)。");
    }

    [Fact]
    public void EveryIntendedDependency_IsStillADirectReference()
    {
        // ロックファイルに直接参照として残っていない表の行を集める
        var stale = new List<string>();
        // 表に登録されているプロジェクトを 1 つずつ見る
        foreach (var (projectName, intended) in IntendedProductionDependencies)
        {
            // 対応する csproj を探す(見つからないプロジェクトは表ごと古くなっている)
            var project = ProductionProjects.Value
                .FirstOrDefault(path => string.Equals(NameOf(path), projectName, StringComparison.OrdinalIgnoreCase));
            // プロジェクトそのものが無ければ、その行すべてを古い行として報告する
            if (project is null)
            {
                stale.AddRange(intended.Keys.Select(id => $"{projectName}: {id} (プロジェクトが見つかりません)"));
                continue;
            }

            // そのプロジェクトの直接参照を読み出す
            var direct = DirectPackagesOf(project);
            // 表にあってロックファイルに無い行を控える
            stale.AddRange(intended.Keys
                .Where(id => !direct.Contains(id, StringComparer.OrdinalIgnoreCase))
                .Select(id => $"{projectName}: {id}"));
        }

        // 古い行を残すと「今は無いパッケージの事前承認」になり、後から黙って昇格できてしまう
        Assert.True(stale.Count == 0,
            $"{nameof(IntendedProductionDependencies)} に、{ProjectLockFile.FileName} で"
            + $"{ProjectLockFile.DirectKind} として解決されていない行があります:\n"
            + string.Join("\n", stale.OrderBy(line => line, StringComparer.Ordinal).Select(line => $"  {line}"))
            + "\n\n参照を外したのなら、この表の行も同じ変更セットで消してください。残しておくと"
            + "「今は存在しないパッケージへの事前承認」になり、後で同じ ID が直接参照へ昇格しても"
            + "この検査は何も言いません(fail-open)。");
    }

    [Fact]
    public void EveryIntendedDependency_HasAReason()
    {
        // 理由が空・空白だけの行を集める
        var withoutReason = IntendedProductionDependencies
            .SelectMany(project => project.Value.Select(entry => (Project: project.Key, Package: entry.Key, entry.Value.Reason)))
            .Where(row => string.IsNullOrWhiteSpace(row.Reason))
            .Select(row => $"{row.Project}: {row.Package}")
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToList();

        // 理由を空にできると、この表が「検出網を黙らせるだけの口」になる
        Assert.True(withoutReason.Count == 0,
            $"{nameof(IntendedProductionDependencies)} の理由が空(または空白だけ)です:\n"
            + string.Join("\n", withoutReason.Select(line => $"  {line}"))
            + "\n\nこの表はレビューで読むための記録なので、なぜ本番へ入れるのかを書いてください。");
    }

    [Fact]
    public void DeclaredAssetFlow_MatchesTheTable()
    {
        // 表の宣言と csproj の宣言が食い違う行を集める
        var mismatches = new List<string>();
        // 表に登録されているプロジェクトを 1 つずつ見る
        foreach (var (projectName, intended) in IntendedProductionDependencies)
        {
            // 対応する csproj を探す(無い場合は EveryIntendedDependency_IsStillADirectReference が報告する)
            var project = ProductionProjects.Value
                .FirstOrDefault(path => string.Equals(NameOf(path), projectName, StringComparison.OrdinalIgnoreCase));
            // 見つからなければここでは何も言わない(同じ事実で 2 つのテストが落ちると原因が二重に見える)
            if (project is null) continue;

            // csproj の PackageReference を読み、ID ごとに PrivateAssets=all の有無を控える
            var privateAssets = ReadPrivateAssetsFlags(project);
            // 表の行を 1 つずつ csproj の宣言と突き合わせる
            foreach (var (id, dependency) in intended)
            {
                // csproj に宣言が無い ID は、この検査では扱えないので飛ばす
                // (顔ぶれのずれは専任の検査が報告する)
                if (!privateAssets.TryGetValue(id, out var declaredPrivate)) continue;
                // 表が「ビルド時専用」と言うなら PrivateAssets=all が宣言されていなければならない
                var expectedPrivate = dependency.Flow == AssetFlow.BuildTimeOnly;
                // 一致していれば問題なし
                if (declaredPrivate == expectedPrivate) continue;
                // 食い違いは、どちら向きなのかを添えて控える
                mismatches.Add(declaredPrivate
                    ? $"{projectName}: {id} — csproj は {PrivateAssetsMetadata}={AllAssets} を宣言しているのに、"
                      + $"表は {nameof(AssetFlow)}.{dependency.Flow} と書いています。"
                    : $"{projectName}: {id} — 表は {nameof(AssetFlow)}.{AssetFlow.BuildTimeOnly} なのに、"
                      + $"csproj が {PrivateAssetsMetadata}={AllAssets} を宣言していません。");
            }
        }

        // 食い違いを放置すると、表の理由欄が読み手に嘘を説明する
        Assert.True(mismatches.Count == 0,
            $"{nameof(IntendedProductionDependencies)} の {nameof(AssetFlow)} と csproj の"
            + $"{PrivateAssetsMetadata} が食い違っています:\n"
            + string.Join("\n", mismatches.OrderBy(line => line, StringComparer.Ordinal).Select(line => $"  {line}"))
            + $"\n\n{PrivateAssetsMetadata}={AllAssets} が外れると、その依存の実行時資産と推移閉包が"
            + "本番出力へ流れます(ロックファイルには一切現れないので、顔ぶれの検査では捕まりません)。"
            + $"本番出力へ流してよいなら表を {nameof(AssetFlow)}.{AssetFlow.Runtime} へ直し、"
            + "流さないなら csproj の宣言を戻してください。");
    }

    // 表のうち、そのプロジェクト向けの行を返す(未登録なら空)
    private static IReadOnlyDictionary<string, IntendedDependency> IntendedFor(string projectPath) =>
        IntendedProductionDependencies.TryGetValue(NameOf(projectPath), out var intended)
            ? intended
            // 未登録は EveryProductionProject_IsListedInTheTable が専任で報告する
            : new Dictionary<string, IntendedDependency>(StringComparer.OrdinalIgnoreCase);

    // csproj のパスからプロジェクト名(拡張子を除いたファイル名)を取り出す。
    // 渡されるのは走査で見つけた実在するファイルのパスなので、名前が取れない形にはならない
    private static string NameOf(string projectPath) => Path.GetFileNameWithoutExtension(projectPath)!;

    // そのプロジェクトのロックファイルから、直接参照のパッケージ ID を読み出す
    private static IReadOnlyList<string> DirectPackagesOf(string projectPath)
    {
        // ロックファイルはプロジェクトファイルと同じディレクトリに置かれる
        var lockFile = ProjectLockFile.PathFor(Path.GetDirectoryName(projectPath)!);
        // 共有ヘルパーに読ませる(書式が読めない場合はヘルパーが fail-closed で落とす)
        var direct = ProjectLockFile.ReadEntries(lockFile)
            // 直接参照だけが対象(推移依存はこの不変条件の対象ではない)
            .Where(entry => string.Equals(entry.Kind, ProjectLockFile.DirectKind, StringComparison.OrdinalIgnoreCase))
            // multi-target では同じ ID が複数のフレームワークに現れるので重ねない
            .Select(entry => entry.Id)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 直接参照が 1 件も無いのは異常(ロックファイルは読めたのに顔ぶれが空)で、
        // 放置すると顔ぶれの検査が空振りする
        Assert.True(direct.Count > 0,
            $"{Path.GetRelativePath(RepositoryPaths.Root, lockFile)} から "
            + $"{ProjectLockFile.DirectKind} のパッケージを 1 件も読み取れませんでした。"
            + "この状態では顔ぶれの検査が空振りします。");
        // 読み取った一覧を返す
        return direct;
    }

    // csproj の PackageReference を読み、パッケージ ID ごとに PrivateAssets=all を宣言しているかを返す。
    // PrivateAssets は属性でも子要素でも書けるため、両方を見る
    private static IReadOnlyDictionary<string, bool> ReadPrivateAssetsFlags(string projectPath)
    {
        // csproj を XML として解析する(SDK 形式なので既定の名前空間は無いが、念のため要素名の局所名で照合する)
        var document = XDocument.Load(projectPath);
        // ID ごとの判定を溜める入れ物
        var flags = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        // PackageReference 要素を 1 つずつ見る
        foreach (var reference in document.Descendants().Where(e => e.Name.LocalName == PackageReferenceElement))
        {
            // パッケージ ID は Include 属性が持つ(無い書き方は対象外)
            var id = reference.Attributes()
                .FirstOrDefault(a => a.Name.LocalName == IncludeAttribute)?.Value;
            // ID が読めない要素は判定できないので飛ばす
            if (string.IsNullOrWhiteSpace(id)) continue;

            // 属性で書かれた PrivateAssets を探す
            var fromAttribute = reference.Attributes()
                .FirstOrDefault(a => a.Name.LocalName == PrivateAssetsMetadata)?.Value;
            // 子要素で書かれた PrivateAssets を探す
            var fromElement = reference.Elements()
                .FirstOrDefault(e => e.Name.LocalName == PrivateAssetsMetadata)?.Value;
            // どちらかに all が含まれていればビルド時専用の宣言とみなす
            var isPrivate = DeclaresAllAssets(fromAttribute) || DeclaresAllAssets(fromElement);

            // 同じ ID が条件付き ItemGroup で複数回現れることがあるので、1 つでも all があれば true にする
            flags[id!] = flags.TryGetValue(id!, out var already) ? already || isPrivate : isPrivate;
        }

        // 読み取った判定を返す
        return flags;
    }

    // PrivateAssets の値が「すべての資産」を表しているかを返す。値は ';' 区切りで並べられる
    private static bool DeclaresAllAssets(string? value) =>
        // 未指定は「宣言していない」(null 条件演算子で false に落ちる)
        value?.Split(';')
            // 前後の空白を落としてから比較する
            .Any(token => string.Equals(token.Trim(), AllAssets, StringComparison.OrdinalIgnoreCase)) ?? false;

    // リポジトリ配下の csproj のうち、テストプロジェクトでないもの(= 本番プロジェクト)を探す。
    //
    // 【なぜソリューションではなくファイルシステムから導くか】EfCorePackageAlignmentTests は
    // IncidentInsight.sln を手がかりにしている。同じ手がかりでこちらも導くと、ソリューションの
    // 読み取りが狭まったときに両方の検査が同時に狭まる。手がかりを変えておけば、
    // ソリューションへの登録漏れ(CI が restore しない本番プロジェクト)もここで現れる。
    //
    // 【なぜ「テストプロジェクトでない」で切るか】本番出力に入らないのはテストプロジェクトだけで、
    // その宣言は csproj の IsTestProject として構造に現れる。ディレクトリ名や命名規則で切ると、
    // 置き場所を変えた瞬間に対象から静かに外れる(この repo が繰り返し避けている形)。
    private static IReadOnlyList<string> FindProductionProjects()
    {
        // リポジトリ配下の csproj をすべて集め、ビルド生成物配下は除く
        var projects = Directory.EnumerateFiles(RepositoryPaths.Root, "*.csproj", SearchOption.AllDirectories)
            .Where(path => !RepositoryPaths.IsBuildArtifact(path))
            // テストプロジェクトは本番出力に入らないので対象外
            .Where(path => !IsTestProject(path))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // 本番プロジェクトが 1 つも見つからないのは異常で、放置すると全検査が空振りする(fail-closed)
        Assert.True(projects.Count > 0,
            $"本番プロジェクト(テストプロジェクトでない csproj)が {RepositoryPaths.Root} の配下に"
            + "1 つも見つかりませんでした。走査の起点か csproj の置き場所がずれている可能性があります"
            + "(この状態では、この検査はすべて空振りします)。");
        // 見つかった一覧を返す
        return projects;
    }

    // その csproj が IsTestProject を true として宣言しているかを返す
    private static bool IsTestProject(string projectPath) =>
        // csproj を XML として読み、プロパティ要素を局所名で探す
        XDocument.Load(projectPath).Descendants()
            .Where(e => e.Name.LocalName == IsTestProjectProperty)
            // MSBuild の真偽値は大文字小文字を区別しない
            .Any(e => string.Equals(e.Value.Trim(), "true", StringComparison.OrdinalIgnoreCase));
}
