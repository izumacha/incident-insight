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
    // (「走査で何を見つけるか」と「表のキーの組み立て」で別々に書くと、片方を変えた瞬間に
    //  キーが一致しなくなり、「表に無いプロジェクト」という実際の原因とは違う失敗文言になる)
    private const string ProjectFileSearchPattern = "*" + RepositoryPaths.ProjectFileExtension;

    // 走査で降りないディレクトリ（理由付き）。
    // 【なぜ要るか】ここはリポジトリ全体を再帰で歩く唯一の走査なので、自分たちが書いていない
    // csproj を拾いうる。拾うと「本番プロジェクトとして表へ登録するか、自分の持ち物でない
    // ファイルへ IsTestProject を書くか」という直しようの無い要求になる
    // (この repo が繰り返し避けている形)。wwwroot/lib を「中を見ない」と登録しているのと同じ扱い
    private static readonly IReadOnlyDictionary<string, string> DirectoriesNotScanned =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["node_modules"] = "npm の取得物。CompileTypeScript が npm ci で作るので存在しうるが、"
                + "中の csproj は自分たちの持ち物ではない。",
            [".git"] = "Git のメタデータ。作業ツリーのファイルではない。",
        };

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
            // パスの綴りも NuGet の ID も、引き方は大文字小文字を区別しない
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

    // 本番プロジェクト(テストプロジェクトでないもの)の csproj。走査は 1 回で済むので結果を保持する
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
    public void ProductionProjects_CoverEveryNonTestProjectInTheSolution()
    {
        // 照合の手がかりは「ソリューションに登録されたプロジェクト」= CI が restore する範囲そのもの。
        // 【なぜ導出と手がかりを分けるか】同じ手がかりで導出とガードを作ると、導出が狭まったときに
        // ガードも一緒に狭まって「取りこぼしゼロ＝緑」で無力化される(CLAUDE.md が
        // FieldLengthsTests.LengthGovernedTypes_CoverEveryOwnedDbSet について記録しているのと同じ理由)。
        // 導出はファイルシステム、こちらはソリューションを読む
        var listedInSolution = SolutionLayout.ProjectFiles
            .Where(path => !IsTestProject(path))
            .Select(KeyOf)
            .OrderBy(key => key, StringComparer.Ordinal)
            .ToList();

        // 手がかりが 1 件も取れない状態では照合が空振りするので落とす(fail-closed)
        Assert.True(listedInSolution.Count > 0,
            $"{SolutionLayout.FileName} からテストプロジェクトでないプロジェクトを 1 つも読み取れませんでした。"
            + "この状態では走査の網羅を照合できません。");

        // 走査で見つけた本番プロジェクト(導出側)
        var discovered = ProductionProjects.Value.Select(KeyOf).ToHashSet(StringComparer.Ordinal);
        // ソリューションにあるのに走査で見つかっていないものを集める
        var missed = listedInSolution.Where(key => !discovered.Contains(key)).ToList();

        // 走査の起点や除外が狭まると、そのプロジェクトだけが黙って全検査から外れる
        Assert.True(missed.Count == 0,
            $"{SolutionLayout.FileName} に登録されている本番プロジェクトが、走査で見つかっていません:\n"
            + string.Join("\n", missed.Select(key => $"  {key}"))
            + $"\n\n{nameof(FindProductionProjects)} の走査の起点・除外("
            + $"{nameof(DirectoriesNotScanned)})が狭まると、そのプロジェクトは"
            + "この guard のすべての検査から黙って外れます(違反ゼロ＝緑になります)。");
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
    //
    // 【残っている境界】見えるのは csproj に無条件で書かれた IsTestProject だけで、
    // Directory.Build.props へ括り出した宣言や SDK が暗黙に設定する分は見えない
    // (どう切っているかと、なぜその向きへ倒すかは IsTestProject の説明が正本)。
    // 見えない場合そのプロジェクトは本番として現れるので、
    // EveryProductionProject_IsListedInTheTable の失敗文言が「表へ登録する」と
    // 「csproj に IsTestProject を宣言する」の両方を案内する(誤って本番の表へ登録すると、
    // まさにこの検査が防ぎたいテスト専用の依存を承認してしまうため)
    private static IReadOnlyList<string> FindProductionProjects()
    {
        // リポジトリ配下の csproj をすべて集め、ビルド生成物配下は除く
        var projects = Directory.EnumerateFiles(RepositoryPaths.Root, ProjectFileSearchPattern, SearchOption.AllDirectories)
            .Where(path => !RepositoryPaths.IsBuildArtifact(path))
            // 自分たちの持ち物でない木(取得物・VCS のメタデータ)は見ない
            .Where(path => !IsInsideUnscannedDirectory(path))
            // テストプロジェクトは本番出力に入らないので対象外
            .Where(path => !IsTestProject(path))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        // 本番プロジェクトが 1 つも見つからないのは異常で、放置すると全検査が空振りする(fail-closed)
        Assert.True(projects.Count > 0,
            "本番プロジェクト(テストプロジェクトでない csproj)がリポジトリ配下に 1 つも"
            + "見つかりませんでした。走査の起点か csproj の置き場所がずれている可能性があります"
            + $"(この状態では、この検査はすべて空振りします)。探した場所: {RepositoryPaths.Root}");
        // 見つかった一覧を返す
        return projects;
    }

    // そのパスが「走査で降りない」と決めたディレクトリの中にあるかを返す
    private static bool IsInsideUnscannedDirectory(string path) =>
        // リポジトリルートからの相対パスを区切りで分解し、除外対象の名前が含まれるかを見る
        Path.GetRelativePath(RepositoryPaths.Root, path)
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(DirectoriesNotScanned.ContainsKey);

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
