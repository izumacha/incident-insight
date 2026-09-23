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
// ビルドも全テストも Docker イメージも緑のまま、依存が 1 つ静かに増える
// (§9「新規依存は最小限に絞って出所・メンテ状況を確認する」)。しかも実測では、あの PR で
// build-and-test は 0 Warning / 0 Error で緑だった(solution 単位の locked-mode restore は
// ロックファイルと一致していれば版衝突を報告しない)。赤くなったのは Docker ジョブ 1 本だけで、
// 診断も Docker のレイヤ内の NU1107 だった。
// だから「昇格そのもの」を、版衝突が起きるかどうかとは無関係に、速くて読みやすい形で落とす。
//
// 【なぜ csproj ではなく packages.lock.json を読むのか】ロックファイルは「実際に直接参照として
// 解決されたもの」の唯一の記録で、csproj の記述ゆれ(属性の並び・条件付き ItemGroup・将来の
// Directory.Build.props)に左右されない。ロックファイルだけを書き換える差分も同じ土俵で捕まる。
// CI と Dockerfile の locked-mode restore が、この記録と csproj の一致そのものを強制している。
//
// 【この検査が見るのは「顔ぶれ」だけ ―― 残っている境界】
// 「その依存の資産が publish 出力に入るか」はここでは見ていない。理由は、判定の手がかりが
// ロックファイルにも csproj の 1 つのメタデータにも無いため。
//   - PrivateAssets は「このプロジェクトを参照する側へ資産を流すか」を決めるもので、
//     publish されるトップレベルのアプリ(この Web プロジェクト)には参照元が無いので効かない。
//     実際に自分の出力へ何が入るかを決めるのは IncludeAssets / ExcludeAssets の側。
//   - どれもロックファイルには一切記録されない(実測: Design の項目は contentHash /
//     dependencies / requested / resolved / type だけ)。
// 一度 PrivateAssets=all の有無で代用する検査を書いたが、(a) publish 出力を決めていない
// メタデータを根拠にしてしまい、(b) 出力から確実に外す正しい綴り(ExcludeAssets=runtime)を
// 逆に違反として報告する、という両方向の外れ方をしたため取り下げた。
// 綴りを 1 つずつ足して当てる形はこの repo が繰り返し避けている近似で、
// 正しいコードを赤くする検査はいずれ緩められる。
// 塞ぐなら手がかりを変えて「publish した出力に何が入っているか」を直接見るしかなく、
// それは Docker ジョブ(publish を実際に走らせる唯一の場所)の仕事になる。
// それまでは、ビルド時専用のつもりの依存については資産メタデータをレビューで確認する。
//
// 【表は人が判断するエスケープハッチ】「その依存を本番へ入れてよいか」は機械では決められないので、
// 判断の記録として理由を必須にしてある(AuditedEntityModel.LengthGovernanceExclusions と同じ扱い)。
// エントリが増える差分は、出所・メンテ状況・本番に入れる必要があることをレビューで必ず確認する。
public class ProductionDirectDependencyTests
{
    // csproj で「このプロジェクトはテストプロジェクトである」と宣言するプロパティ名。
    // この宣言を持つプロジェクトは本番出力に含まれないため、この不変条件の対象外になる
    private const string IsTestProjectProperty = "IsTestProject";

    // 走査でプロジェクトファイルを探すときのパターン。
    // 拡張子の綴りは RepositoryPaths が正本で、そこから組み立てて綴りを分けない
    private static readonly string ProjectFileSearchPattern = "*" + RepositoryPaths.ProjectFileExtension;

    // MSBuild でプロパティをまとめる要素名
    private const string PropertyGroupElement = "PropertyGroup";

    // MSBuild で評価条件を指定する属性名
    private const string ConditionAttribute = "Condition";

    // MSBuild の真を表す値(比較は大文字小文字を区別しない)
    private const string MsBuildTrue = "true";

    // 本番プロジェクトが直接参照してよいパッケージと、その理由。
    // 外側のキーは csproj のリポジトリルートからの相対パス(区切りは '/' に正規化する)。
    //
    // 【なぜプロジェクトごとに分けるか】ID だけをキーにすると、2 つ目の本番プロジェクトが増えたときに
    // 1 つ目のために書いた承認がそのまま効いてしまう。issue #224 が同じ形の穴を記録している
    // (除外表のキーに画面を含めていなかったため、同名の引数を別の画面へ足すだけで根拠の無い除外が
    // 効き、差分にもテスト件数にも現れなかった)。
    //
    // 【なぜ単純名ではなく相対パスをキーにするか】同じファイル名の csproj が別ディレクトリに増えると
    // (src/Api/Shared.csproj と src/Worker/Shared.csproj)、単純名では同じバケットへ畳まれて
    // 1 つ目の承認が 2 つ目にも黙って効く。CLAUDE.md が別の表について
    // 「キーは完全修飾名にする — 単純名だと同名のものが同じバケットに畳まれ、既存エントリの除外が
    // 新しいものにも黙って効く」と記録しているのと同じ理由(issue #227)。
    //
    // 【版はここで管理しない】メジャー版の揃えは EfCorePackageAlignmentTests、床値と保留は
    // dependabot.yml と同テストが受け持つ。ここが見るのは「本番へ入れる顔ぶれ」だけ。
    //
    // 【キーの比較は Ordinal にする】パッケージ ID は NuGet の規則で大文字小文字を区別しないが、
    // パスは区別する。CI が動く Linux では src/Foo/A.csproj と src/foo/A.csproj は別のプロジェクトで、
    // 区別せずに引くと同じバケットへ畳まれて 1 つ目の承認が 2 つ目にも黙って効く
    // (相対パスをキーにした理由そのものが 1 段下で崩れる)。
    //
    // 【プロジェクトのパスをリテラルで書かない】リポジトリ構成の目印を書いてよいのは RepositoryPaths だけ。
    // csproj のパスも構成の知識なので RepositoryPaths.WebProjectFile から読む
    // 【なぜ Lazy か】初期化子が WebProjectKey 経由で RepositoryPaths.Root を解決するため、
    // 直接初期化すると探索が型初期化子の中で走る。失敗すると「リポジトリルートが見つかりません」という
    // 原因を名指しした例外が TypeInitializationException に包まれ、見出しには
    // 「型の初期化子が例外をスローしました」しか出ない(RepositoryPaths 自身が同じ理由で Lazy にしている)
    private static readonly Lazy<IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>>
        IntendedProductionDependencies = new(() =>
            // 外側のキーはパスなので大文字小文字を区別する(内側のパッケージ ID は区別しない)
            new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.Ordinal)
            {
                [WebProjectKey] =
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Microsoft.AspNetCore.Identity.EntityFrameworkCore"] =
                            "ASP.NET Core Identity を EF Core で永続化する(ApplicationUser と 3 ロールの基盤)。",
                        ["Microsoft.Data.SqlClient"] =
                            "SQL Server 配備向け ADO.NET ドライバ。セキュリティ更新の床値として直接参照で"
                            + "ピンしている(理由は csproj のコメントと CLAUDE.md §3 が正本)。",
                        ["Microsoft.EntityFrameworkCore.Design"] =
                            "EF Core マイグレーションの追加に必要。ビルド時にしか使わないつもりの依存で、"
                            + "資産の流れ方は csproj の IncludeAssets / ExcludeAssets が決める"
                            + "(この検査は顔ぶれしか見ない。上の「残っている境界」を参照)。",
                        ["Microsoft.EntityFrameworkCore.Sqlite"] =
                            "既定の DB プロバイダ(単一ファイルの SQLite 配備)。",
                        ["Microsoft.EntityFrameworkCore.SqlServer"] =
                            "オンプレ病院向けの DB プロバイダ(既存 SQL Server 配備)。",
                        ["Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore"] =
                            "/health が DB 接続まで確認するためのヘルスチェック。",
                        ["Npgsql.EntityFrameworkCore.PostgreSQL"] =
                            "Linux / マネージド配備向けの DB プロバイダ(PostgreSQL)。",
                    },
            });

    // 本番プロジェクト(ソリューションに登録されていて、テストプロジェクトでないもの)の csproj。
    // 走査は 1 回で済むので結果を保持する
    private static readonly Lazy<IReadOnlyList<string>> ProductionProjects = new(FindProductionProjects);

    // Web プロジェクトの csproj を指す表のキー。csproj のパスは共有ヘルパーが持つ
    private static string WebProjectKey => KeyOf(RepositoryPaths.WebProjectFile);

    [Fact]
    public void EveryProductionProject_IsListedInTheTable()
    {
        // 表に無い本番プロジェクトを集める
        var unlisted = ProductionProjects.Value
            .Select(KeyOf)
            .Where(key => !IntendedProductionDependencies.Value.ContainsKey(key))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToList();

        // 本番プロジェクトが増えたのに登録を忘れると、そのプロジェクトだけが黙って検査から外れる。
        // 直し方は 2 通りあるので両方を案内する(片方だけ書くと、テストプロジェクトが
        // ここへ現れたときに「解析用の依存を本番の表へ登録する」という逆向きの直し方へ誘導してしまう)
        Assert.True(unlisted.Count == 0,
            $"{nameof(IntendedProductionDependencies)} に登録されていないプロジェクトが、"
            + "本番プロジェクトとして扱われています:\n"
            + string.Join("\n", unlisted.Select(key => $"  {key}"))
            + "\n\n本番プロジェクトなら、直接参照の顔ぶれを理由付きで表へ登録してください"
            + "(登録しないままだと、Dependabot が推移依存を直接参照へ昇格させても何も言いません)。"
            + $"\nテストプロジェクトなら、その csproj に {IsTestProjectProperty} を true として"
            + "宣言してください。この走査はその宣言だけを手がかりに本番と切り分けています"
            + "(表へ登録すると、テスト専用の依存を本番向けに承認したことになります)。");
    }

    [Fact]
    public void ProductionProjects_DeclareOnlyIntendedDirectDependencies()
    {
        // 表に載っていない直接参照を「プロジェクト: パッケージ ID」の形で集める
        var unlisted = new List<string>();
        // 本番プロジェクトを 1 つずつ確認する
        foreach (var project in ProductionProjects.Value)
        {
            // 表に無いプロジェクトはここでは何も言わない。空の表として扱うと全依存が違反として並び、
            // 「Dependabot の昇格を取り消してください」という当てはまらない直し方を案内してしまう
            // (正しい直し方は表への登録で、EveryProductionProject_IsListedInTheTable が専任で報告する)
            if (!IntendedProductionDependencies.Value.TryGetValue(KeyOf(project), out var intended)) continue;
            // ロックファイルに直接参照として記録されているパッケージを 1 件ずつ見る
            foreach (var id in DirectPackagesOf(project))
            {
                // 表に無ければ違反として控える
                if (!intended.ContainsKey(id)) unlisted.Add($"{KeyOf(project)}: {id}");
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
            + $"\n本当に本番へ入れる依存なら、{nameof(IntendedProductionDependencies)} へ理由を添えて"
            + "登録してください(出所とメンテ状況の確認はレビューで行います。§9)。");
    }

    [Fact]
    public void EveryIntendedDependency_IsStillADirectReference()
    {
        // ロックファイルに直接参照として残っていない表の行を集める
        var stale = new List<string>();
        // 表に登録されているプロジェクトを 1 つずつ見る
        foreach (var (projectKey, intended) in IntendedProductionDependencies.Value)
        {
            // 対応する csproj を探す(見つからないなら表ごと古くなっている)
            var project = ProductionProjects.Value
                .FirstOrDefault(path => string.Equals(KeyOf(path), projectKey, StringComparison.Ordinal));
            // プロジェクトそのものが無ければ、その行すべてを古い行として報告する。
            // 【行が 0 件でも 1 件報告する】`intended.Keys` が空だと AddRange は何も足さず、
            // 「実在しないプロジェクトへの空の承認」が黙って通る。それを残すと、後でその名前の
            // プロジェクトが PackageReference ゼロで作られたときに「登録済み」として扱われ、
            // 誰も承認の理由を書いていないまま表を通過する(この表を置いた意味が消える)
            if (project is null)
            {
                stale.Add($"{projectKey} (プロジェクトが見つかりません)");
                stale.AddRange(intended.Keys.Select(id => $"{projectKey}: {id}"));
                continue;
            }

            // そのプロジェクトの直接参照を読み出す
            var direct = DirectPackagesOf(project);
            // 表にあってロックファイルに無い行を控える
            stale.AddRange(intended.Keys
                .Where(id => !direct.Contains(id, StringComparer.OrdinalIgnoreCase))
                .Select(id => $"{projectKey}: {id}"));
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
    public void EveryProjectUnderSourceRoots_IsRegisteredInTheSolution()
    {
        // 導出はソリューションを正本にしているので、照合はファイルシステムという別の手がかりで行う。
        // 【なぜ登録漏れを問題にするか】ソリューションに無いプロジェクトは CI が restore / build / test
        // しないが、Web プロジェクトから ProjectReference すれば publish には入る。つまり
        // 「出荷されるのにこの guard の視界に無い」状態が作れてしまう
        var registered = SolutionLayout.ProjectFiles.ToHashSet(StringComparer.Ordinal);
        // src / tests の配下に実在する csproj を集める
        var onDisk = ProjectFilesUnderSourceRoots()
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // 1 つも見つからないのは走査の起点がずれた状態で、照合が空振りする(fail-closed)
        Assert.True(onDisk.Count > 0,
            $"{RepositoryPaths.SrcRoot} と {RepositoryPaths.TestsRoot} の配下に csproj が"
            + "1 つも見つかりませんでした。この状態ではソリューションへの登録漏れを照合できません。");

        // 実在するのにソリューションへ登録されていないものを集める
        var unregistered = onDisk.Where(path => !registered.Contains(path)).Select(KeyOf).ToList();

        // 登録漏れは「CI が触らないのに出荷されうる」状態なので落とす
        Assert.True(unregistered.Count == 0,
            $"{SolutionLayout.FileName} に登録されていない csproj があります:\n"
            + string.Join("\n", unregistered.Select(key => $"  {key}"))
            + $"\n\nこの guard は {SolutionLayout.FileName} を正本に本番プロジェクトを導出するので、"
            + "登録されていないプロジェクトは直接参照の顔ぶれが誰にも照合されません"
            + "(CI の restore / build / test もそのプロジェクトを触りません)。"
            + "ソリューションへ登録してください。");
    }

    [Fact]
    public void ProjectClassification_AgreesWithTheDirectoryLayout()
    {
        // 分類（IsTestProject）を置き場所の慣習と突き合わせる。
        // 【なぜこれが要るか】導出も照合も IsTestProject を手がかりにすると、分類を取り違えた
        // プロジェクト（テストプロジェクトの csproj をテンプレートにして src へ置き、旗を消し忘れる形）は
        // 両方から同時に外れ、直接参照が 1 つも照合されないまま全件緑になる。
        // 置き場所は分類とは独立な手がかりなので、取り違えをここで落とせる。
        // 慣習を変えたときは黙って外れるのではなくこの検査が落ちる（安全な向き）
        var mismatches = new List<string>();
        // src / tests の配下の csproj を 1 つずつ見る
        foreach (var project in ProjectFilesUnderSourceRoots())
        {
            // その csproj がテストプロジェクトを名乗っているか
            var classifiedAsTest = IsTestProject(project);
            // tests 配下に置かれているか
            var underTests = project.StartsWith(RepositoryPaths.TestsRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);
            // src 配下に置かれているか
            var underSrc = project.StartsWith(RepositoryPaths.SrcRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);

            // src 配下なのにテストプロジェクトを名乗っている（この guard から静かに外れる向き）
            if (underSrc && classifiedAsTest)
                mismatches.Add($"{KeyOf(project)} — src 配下なのに {IsTestProjectProperty} を true と"
                    + "宣言しています。本番プロジェクトならこの宣言を外してください"
                    + "(宣言が残っていると直接参照の顔ぶれが照合されません)。");
            // tests 配下なのに本番プロジェクトとして扱われる（本番の表への登録を要求される向き）
            if (underTests && !classifiedAsTest)
                mismatches.Add($"{KeyOf(project)} — tests 配下なのに {IsTestProjectProperty} を"
                    + "無条件に true と宣言していません。テストプロジェクトなら宣言してください"
                    + "(宣言が無いと本番プロジェクトとして扱われ、テスト専用の依存を本番の表へ"
                    + "登録するよう促されます)。");
        }

        // 分類と置き場所の食い違いは、どちらの向きでも guard の意味を壊す
        Assert.True(mismatches.Count == 0,
            "プロジェクトの分類が置き場所の慣習と食い違っています:\n"
            + string.Join("\n", mismatches.OrderBy(line => line, StringComparer.Ordinal).Select(line => $"  {line}")));
    }

    [Theory]
    // 無条件の宣言は拾う(実在する tests プロジェクトがこの形)
    [InlineData("<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>", true)]
    // MSBuild の真偽値は大文字小文字を区別しないので綴りの揺れも拾う
    [InlineData("<Project><PropertyGroup><IsTestProject> TRUE </IsTestProject></PropertyGroup></Project>", true)]
    // 条件付きの PropertyGroup は「評価されうる」だけなので根拠にしない
    // (Release では一度も評価されない宣言で本番プロジェクトが検査対象から外れるのを防ぐ)
    [InlineData("<Project><PropertyGroup Condition=\"'$(Configuration)'=='Test'\">"
        + "<IsTestProject>true</IsTestProject></PropertyGroup></Project>", false)]
    // 要素そのものに条件が付いている形も同じ
    [InlineData("<Project><PropertyGroup>"
        + "<IsTestProject Condition=\"'$(X)'=='1'\">true</IsTestProject></PropertyGroup></Project>", false)]
    // Choose / When の中はルート直下ではないので見ない(条件付きと同じ扱い)
    [InlineData("<Project><Choose><When Condition=\"true\"><PropertyGroup>"
        + "<IsTestProject>true</IsTestProject></PropertyGroup></When></Choose></Project>", false)]
    // Target の中の宣言はビルド中にしか効かないので見ない
    [InlineData("<Project><Target Name=\"X\"><PropertyGroup>"
        + "<IsTestProject>true</IsTestProject></PropertyGroup></Target></Project>", false)]
    // false と書いてあれば本番プロジェクト
    [InlineData("<Project><PropertyGroup><IsTestProject>false</IsTestProject></PropertyGroup></Project>", false)]
    // 宣言が無ければ本番プロジェクト(既定)
    [InlineData("<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>", false)]
    // MSBuild のプロパティは後勝ちなので、true のあとの false が効く(本番プロジェクト)
    [InlineData("<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup>"
        + "<PropertyGroup><IsTestProject>false</IsTestProject></PropertyGroup></Project>", false)]
    // 逆向き(false のあとの true)も後勝ちで拾う
    [InlineData("<Project><PropertyGroup><IsTestProject>false</IsTestProject></PropertyGroup>"
        + "<PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>", true)]
    public void DeclaresIsTestProject_OnlyAcceptsUnconditionalDeclarations(string projectXml, bool expected) =>
        // 合成した csproj を読ませ、両方向の判定を固定する
        Assert.Equal(expected, DeclaresIsTestProject(XDocument.Parse(projectXml)));

    [Fact]
    public void EveryIntendedDependency_HasAReason()
    {
        // 理由が空・空白だけの行を集める
        var withoutReason = IntendedProductionDependencies.Value
            .SelectMany(project => project.Value.Select(entry => (Project: project.Key, Package: entry.Key, Reason: entry.Value)))
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

    // csproj のパスを表のキー(リポジトリルートからの相対パス。区切りは '/')へ直す。
    // 区切りを正規化するのは、実行環境によって '\' と '/' が混ざるとキーが一致しなくなるため
    private static string KeyOf(string projectPath) =>
        Path.GetRelativePath(RepositoryPaths.Root, projectPath).Replace('\\', '/');

    // そのプロジェクトのロックファイルから、直接参照のパッケージ ID を読み出す。
    //
    // 【0 件を異常として落とさない】PackageReference を 1 つも持たない本番プロジェクト
    // (ProjectReference と POCO だけのクラスライブラリ等)は正当な状態で、そこで落とすと
    // 「表へ登録しても直らない赤」になる。ロックファイルが「読めない」形(ファイルが無い /
    // dependencies が無い)は ProjectLockFile.ReadEntries が fail-closed で落とす。
    //
    // 【この走査が丸ごと空振りしたときに気付けるのは EveryIntendedDependency_IsStillADirectReference だけ】
    // 対象プロジェクトの導出が狭まったり、本番プロジェクトが誤ってテスト扱いになったりすると、
    // 顔ぶれを見る 2 つの検査は「見るものが 0 件」で緑になる。表の行が実在することを要求する
    // あの検査だけが、そのとき落ちる。**冗長に見えても消さないこと**(消すとこの guard 全体が
    // 何も見ていない状態で緑になる)
    private static IReadOnlyList<string> DirectPackagesOf(string projectPath) =>
        ProjectLockFile.ReadEntries(ProjectLockFile.PathFor(projectPath))
            // 直接参照だけが対象(推移依存はこの不変条件の対象ではない)
            .Where(entry => string.Equals(entry.Kind, ProjectLockFile.DirectKind, StringComparison.OrdinalIgnoreCase))
            // multi-target では同じ ID が複数のフレームワークに現れるので重ねない
            .Select(entry => entry.Id)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    // 本番プロジェクト(ソリューションに登録されていて、テストプロジェクトでないもの)を求める。
    //
    // 【なぜソリューションを正本にするか】CI が restore / build / test する範囲そのもので、
    // 検査対象と「実際に出荷されうる範囲」が原理的に一致する。以前はリポジトリ全体を
    // 再帰で走査していたが、それは EfCorePackageAlignmentTests.EveryProject_HasCommittedLockFile が
    // 「node_modules やベンダーディレクトリに紛れ込んだ第三者の csproj まで対象になり、
    // 開発者が直しようのないファイルを指して CI が赤くなる」と理由まで書いて避けている形だった
    // (除外表で塞ぐと、今度は「登録するだけで黙らせられる口」になる)。
    //
    // 【なぜ「テストプロジェクトでない」で切るか】本番出力に入らないのはテストプロジェクトだけで、
    // その宣言は csproj の IsTestProject として構造に現れる。
    //
    // 【この導出が狭まっていないかは 2 つの検査が別の手がかりで照合する】
    //   - ソリューションへの登録漏れ … EveryProjectUnderSourceRoots_IsRegisteredInTheSolution
    //     (ファイルシステムを手がかりにする。登録されていないプロジェクトは CI が触らないが、
    //      Web から ProjectReference すれば出荷はされるので、黙って視界の外に置けない)
    //   - 分類の取り違え … ProjectClassification_AgreesWithTheDirectoryLayout
    //     (置き場所の慣習を手がかりにする。IsTestProject を手がかりにすると、導出と照合が
    //      同じ判定になり「取りこぼしゼロ＝緑」で無力化される)
    private static IReadOnlyList<string> FindProductionProjects()
    {
        // ソリューションに登録されたプロジェクトから、テストプロジェクトを除く
        var projects = SolutionLayout.ProjectFiles
            .Where(path => !IsTestProject(path))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // 本番プロジェクトが 1 つも無いのは異常で、放置すると全検査が空振りする(fail-closed)
        Assert.True(projects.Count > 0,
            $"{SolutionLayout.FileName} に、テストプロジェクトでないプロジェクトが 1 つもありません。"
            + "この状態では、この検査はすべて空振りします。");
        // 見つかった一覧を返す
        return projects;
    }

    // 自分たちが書いたプロジェクトを置く 2 つの階層(src / tests)を列挙する
    private static IEnumerable<string> ProjectFilesUnderSourceRoots() =>
        new[] { RepositoryPaths.SrcRoot, RepositoryPaths.TestsRoot }
            // 階層が無い構成も考えられるので、実在するものだけを歩く
            .Where(Directory.Exists)
            // 各階層の配下から csproj を集める
            .SelectMany(rootDirectory =>
                Directory.EnumerateFiles(rootDirectory, ProjectFileSearchPattern, SearchOption.AllDirectories))
            // ビルド生成物配下は対象外
            .Where(path => !RepositoryPaths.IsBuildArtifact(path));

    // その csproj が IsTestProject を「無条件に」true として宣言しているかを返す。
    //
    // 【なぜ Descendants でファイル全体を探さないか】そちらは条件付きの宣言も拾ってしまう。
    // 例えば <PropertyGroup Condition="'$(Configuration)'=='Test'"><IsTestProject>true</IsTestProject>
    // と書くと、Release ビルドでは MSBuild が一度も評価しないのに本番プロジェクトが
    // 対象から外れる(この guard が守るべき本命の直接参照が、丸ごと検査されなくなる向き)。
    // 条件を評価する気はないので、条件が付いていたら「宣言していない」側へ倒す。
    // 倒す向きの代償は「条件付きで宣言した本物のテストプロジェクトが本番として現れる」ことだが、
    // それは EveryProductionProject_IsListedInTheTable が両方の直し方を案内して止まる側の外れ方
    private static bool IsTestProject(string projectPath) => DeclaresIsTestProject(LoadProject(projectPath));

    /// <summary>
    /// 読み込んだ csproj が <c>IsTestProject</c> を「無条件に」true と宣言しているかを返す。
    /// <para><b>internal なのは、この判定を合成入力で固定するため。</b> 実在する 2 つの csproj は
    /// どちらもルート直下・条件なしで宣言しているので、条件を見る部分を落としても実データでは
    /// 結果が変わらず全件緑になる（この repo が別の判定について繰り返し記録している形）。
    /// 挙動は <see cref="DeclaresIsTestProject_OnlyAcceptsUnconditionalDeclarations"/> が固定する。</para>
    /// </summary>
    internal static bool DeclaresIsTestProject(XDocument project) =>
        // ルート直下の PropertyGroup のうち、条件が付いていないものだけを見る
        project.Root?.Elements()
            .Where(group => group.Name.LocalName == PropertyGroupElement && !HasCondition(group))
            // その中の IsTestProject 要素(こちらにも条件が付いていないもの)を取り出す
            .SelectMany(group => group.Elements()
                .Where(e => e.Name.LocalName == IsTestProjectProperty && !HasCondition(e)))
            // 書かれた値を文書順に並べる
            .Select(e => e.Value.Trim())
            // 【Any ではなく最後の宣言を採る】MSBuild のプロパティは後勝ちなので、
            // true のあとに false を書いた csproj は本番プロジェクトとして出荷される。
            // Any で見ると「どこかに true がある」で真になり、その本番プロジェクトが
            // 検査対象から静かに外れる(fail-open。テンプレートから作って旗を上書きする形で起こる)
            .LastOrDefault() is { } declared
        // MSBuild の真偽値は大文字小文字を区別しない
        && string.Equals(declared, MsBuildTrue, StringComparison.OrdinalIgnoreCase);

    // その要素に Condition 属性が付いているかを返す(名前空間が付いていても局所名で見れば外れない)
    private static bool HasCondition(XElement element) =>
        element.Attributes().Any(a => a.Name.LocalName == ConditionAttribute);

    // csproj を XML として読む。読めないときは、どのファイルかを名指しして落とす。
    // 素の XmlException は行と位置しか持たずファイル名を含まないため、そのまま投げると
    // (しかも Lazy の中で投げるため)4 つの検査すべてが原因の分からない赤になる
    private static XDocument LoadProject(string projectPath)
    {
        try
        {
            // 通常はここで読み終わる
            return XDocument.Load(projectPath);
        }
        catch (System.Xml.XmlException exception)
        {
            // どの csproj が壊れているのかを添えて落とす(fail-closed)
            Assert.Fail($"{KeyOf(projectPath)} を XML として読めませんでした"
                + $"(この検査は csproj の構造を読むので、壊れていると本番かテストかを判定できません): "
                + exception.Message);
            // Assert.Fail は必ず例外を投げるので到達しない(コンパイラのための行)
            throw;
        }
    }
}
