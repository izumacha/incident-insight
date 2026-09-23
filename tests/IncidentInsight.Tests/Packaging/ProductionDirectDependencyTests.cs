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
    // 【プロジェクトのパスをリテラルで書かない】リポジトリ構成の目印を書いてよいのは RepositoryPaths だけで、
    // RepositoryPathsUsageTests がそれを検査している。目印は共有ヘルパーの定数から組み立てる
    private static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, string>>
        IntendedProductionDependencies =
            // パスの綴りも NuGet の ID も、引き方は大文字小文字を区別しない
            new Dictionary<string, IReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase)
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
            };

    // 本番プロジェクト(テストプロジェクトでないもの)の csproj。走査は 1 回で済むので結果を保持する
    private static readonly Lazy<IReadOnlyList<string>> ProductionProjects = new(FindProductionProjects);

    // Web プロジェクトの csproj を指す表のキー。リポジトリ構成の目印は共有ヘルパーから読む
    private static string WebProjectKey =>
        KeyOf(Path.Combine(RepositoryPaths.WebProject, RepositoryPaths.WebProjectDirectoryName + ".csproj"));

    [Fact]
    public void EveryProductionProject_IsListedInTheTable()
    {
        // 表に無い本番プロジェクトを集める
        var unlisted = ProductionProjects.Value
            .Select(KeyOf)
            .Where(key => !IntendedProductionDependencies.ContainsKey(key))
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
            // そのプロジェクトの表(未登録なら空として扱い、専任の検査に報告を任せる)
            var intended = IntendedFor(project);
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
        foreach (var (projectKey, intended) in IntendedProductionDependencies)
        {
            // 対応する csproj を探す(見つからないなら表ごと古くなっている)
            var project = ProductionProjects.Value
                .FirstOrDefault(path => string.Equals(KeyOf(path), projectKey, StringComparison.OrdinalIgnoreCase));
            // プロジェクトそのものが無ければ、その行すべてを古い行として報告する
            if (project is null)
            {
                stale.AddRange(intended.Keys.Select(id => $"{projectKey}: {id} (プロジェクトが見つかりません)"));
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
    public void EveryIntendedDependency_HasAReason()
    {
        // 理由が空・空白だけの行を集める
        var withoutReason = IntendedProductionDependencies
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

    // 表のうち、そのプロジェクト向けの行を返す(未登録なら空)
    private static IReadOnlyDictionary<string, string> IntendedFor(string projectPath) =>
        IntendedProductionDependencies.TryGetValue(KeyOf(projectPath), out var intended)
            ? intended
            // 未登録は EveryProductionProject_IsListedInTheTable が専任で報告する
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    // csproj のパスを表のキー(リポジトリルートからの相対パス。区切りは '/')へ直す。
    // 区切りを正規化するのは、実行環境によって '\' と '/' が混ざるとキーが一致しなくなるため
    private static string KeyOf(string projectPath) =>
        Path.GetRelativePath(RepositoryPaths.Root, projectPath).Replace('\\', '/');

    // そのプロジェクトのロックファイルから、直接参照のパッケージ ID を読み出す。
    //
    // 【0 件を異常として落とさない】PackageReference を 1 つも持たない本番プロジェクト
    // (ProjectReference と POCO だけのクラスライブラリ等)は正当な状態で、そこで落とすと
    // 「表へ登録しても直らない赤」になる。ロックファイルそのものが読めない場合は
    // ProjectLockFile.ReadEntries が fail-closed で落とすので、空振りの検出はそちらが受け持つ
    private static IReadOnlyList<string> DirectPackagesOf(string projectPath) =>
        ProjectLockFile.ReadEntries(ProjectLockFile.PathFor(Path.GetDirectoryName(projectPath)!))
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
    // 【残っている境界】見えるのは csproj に直接書かれた IsTestProject だけで、
    // Directory.Build.props へ括り出した宣言や SDK が暗黙に設定する分は見えない。
    // その場合そのプロジェクトは本番として現れるので、
    // EveryProductionProject_IsListedInTheTable の失敗文言が「表へ登録する」と
    // 「csproj に IsTestProject を宣言する」の両方を案内する(誤って本番の表へ登録すると、
    // まさにこの検査が防ぎたいテスト専用の依存を承認してしまうため)
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
            "本番プロジェクト(テストプロジェクトでない csproj)がリポジトリ配下に 1 つも"
            + "見つかりませんでした。走査の起点か csproj の置き場所がずれている可能性があります"
            + $"(この状態では、この検査はすべて空振りします)。探した場所: {RepositoryPaths.Root}");
        // 見つかった一覧を返す
        return projects;
    }

    // その csproj が IsTestProject を true として宣言しているかを返す
    private static bool IsTestProject(string projectPath) =>
        // csproj を XML として読み、プロパティ要素を局所名で探す
        // (SDK 形式に既定の名前空間は無いが、局所名で見れば付いていても外れない)
        XDocument.Load(projectPath).Descendants()
            .Where(e => e.Name.LocalName == IsTestProjectProperty)
            // MSBuild の真偽値は大文字小文字を区別しない
            .Any(e => string.Equals(e.Value.Trim(), "true", StringComparison.OrdinalIgnoreCase));
}
