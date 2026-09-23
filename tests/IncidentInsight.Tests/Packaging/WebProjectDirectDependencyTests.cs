// packages.lock.json を JSON として読むために取り込む
using System.Text.Json;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Packaging;

// Guard-rail test: 本番の Web プロジェクトが直接参照する NuGet パッケージを、理由付きの表と突き合わせる。
//
// 【発端】Dependabot の nuget updater は、ロックファイルを持つプロジェクトでは推移依存を更新するために
// その依存を「直接参照へ昇格させる」。実際 PR #267 は、テストプロジェクトが「本番アセンブリには入らない」と
// 明記している解析用の依存 Microsoft.CodeAnalysis.CSharp を、src/IncidentInsight.Web の直接参照として
// 足していた(Web 側のロックファイルでは Microsoft.EntityFrameworkCore.Design 経由の推移依存だったため、
// 更新対象として掴まれた)。つまりこの形は「テスト専用のはずの依存が本番プロジェクトへ入る」経路になる。
//
// 【なぜ既存の検出網では足りないか】あの PR が赤くなったのは偶然にすぎない。
// Microsoft.EntityFrameworkCore.Design が Microsoft.CodeAnalysis.Common を完全一致 (= 4.8.0) でピンして
// いたため NU1107 の版衝突になり、Web プロジェクト単体を locked-mode で復元する Docker ジョブが落ちた。
// 完全一致のピンを持たない推移依存が同じ形で昇格した場合、復元は成功するので
// ビルドも全テストも Docker イメージも緑のまま、本番イメージに解析器やコンパイラが同梱される
// (サイズと供給網の面が黙って広がる。§9「新規依存は最小限に絞って出所・メンテ状況を確認する」)。
// しかも実測では、あの PR で build-and-test は 0 Warning / 0 Error で緑だった
// (solution 単位の locked-mode restore はロックファイルと一致していれば版衝突を報告しない)。
// 赤くなったのは Docker ジョブ 1 本だけで、診断も Docker のレイヤ内の NU1107 だった。
// だから「昇格そのもの」を、版衝突が起きるかどうかとは無関係に、速くて読みやすい形で落とす。
//
// 【なぜ csproj ではなく packages.lock.json を読むのか】ロックファイルは「実際に直接参照として解決された
// もの」の唯一の記録で、csproj の記述ゆれ(属性の並び・条件付き ItemGroup・将来の Directory.Build.props)に
// 左右されない。ロックファイルだけを書き換える差分も同じ土俵で捕まる。CI と Dockerfile の
// locked-mode restore が、この記録と csproj の一致そのものを強制している。
//
// 【表は人が判断するエスケープハッチ】「その依存を本番へ入れてよいか」は機械では決められないので、
// 判断の記録として理由を必須にしてある(AuditedEntityModel.LengthGovernanceExclusions と同じ扱い)。
// エントリが増える差分は、出所・メンテ状況・本番に入れる必要があることをレビューで必ず確認する。
public class WebProjectDirectDependencyTests
{
    // 各プロジェクトの隣に置かれるロックファイルの名前
    private const string LockFileName = "packages.lock.json";

    // ロックファイルで、ターゲットフレームワークごとの解決結果をまとめているキー名
    private const string DependenciesKey = "dependencies";

    // ロックファイルで、直接参照か推移依存かを表すキー名
    private const string TypeKey = "type";

    // 上記 type が「csproj に直接書かれた参照」を表すときの値
    private const string DirectPackageKind = "Direct";

    // 本番の Web プロジェクトが直接参照してよいパッケージと、その理由。
    //
    // 【理由を必須にする意味】理由が空の行を許すと「とりあえず検出網を黙らせる」使い方ができてしまう
    // (この repo が [NotPhi] で同じ口を塞いだのと同じ形)。下の
    // EveryIntendedDependency_HasAReason が空・空白の理由を落とす。
    //
    // 【版はここで管理しない】メジャー版の揃えは EfCorePackageAlignmentTests、床値と保留は
    // dependabot.yml と同テストが受け持つ。ここが見るのは「本番へ入れる顔ぶれ」だけ。
    private static readonly IReadOnlyDictionary<string, string> IntendedWebProjectDependencies =
        // NuGet のパッケージ ID は大文字小文字を区別しないため、引き方も区別しない
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Microsoft.AspNetCore.Identity.EntityFrameworkCore"] =
                "ASP.NET Core Identity を EF Core で永続化する(ApplicationUser と 3 ロールの基盤)。",
            ["Microsoft.Data.SqlClient"] =
                "SQL Server 配備向け ADO.NET ドライバ。セキュリティ更新の床値として直接参照でピンしている"
                + "(理由は csproj のコメントと CLAUDE.md §3 が正本)。",
            ["Microsoft.EntityFrameworkCore.Design"] =
                "EF Core マイグレーションの追加に必要。PrivateAssets=all のビルド時専用依存で、"
                + "実行時アセンブリには流れない。",
            ["Microsoft.EntityFrameworkCore.Sqlite"] =
                "既定の DB プロバイダ(単一ファイルの SQLite 配備)。",
            ["Microsoft.EntityFrameworkCore.SqlServer"] =
                "オンプレ病院向けの DB プロバイダ(既存 SQL Server 配備)。",
            ["Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore"] =
                "/health が DB 接続まで確認するためのヘルスチェック。",
            ["Npgsql.EntityFrameworkCore.PostgreSQL"] =
                "Linux / マネージド配備向けの DB プロバイダ(PostgreSQL)。",
        };

    // 本番の Web プロジェクトのロックファイルから読み出した直接参照。走査は 1 回で済むので結果を保持する
    private static readonly Lazy<IReadOnlyList<string>> WebProjectDirectPackages =
        new(ReadWebProjectDirectPackages);

    [Fact]
    public void WebProject_DeclaresOnlyIntendedDirectDependencies()
    {
        // 表に載っていない直接参照を集める(Dependabot の昇格や、手で足した依存がここに出る)
        var unlisted = WebProjectDirectPackages.Value
            .Where(id => !IntendedWebProjectDependencies.ContainsKey(id))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        // 1 件でもあれば、直し方(本番に入れるのか、入れないのか)を名指しして落とす
        Assert.True(unlisted.Count == 0,
            $"本番の Web プロジェクトが、{nameof(IntendedWebProjectDependencies)} に無いパッケージを"
            + "直接参照しています:\n"
            + string.Join("\n", unlisted.Select(id => $"  {id}"))
            + "\n\nDependabot はロックファイルを持つプロジェクトの推移依存を更新するとき、その依存を"
            + "直接参照へ昇格させます(PR #267 がその実例で、テスト専用の解析パッケージが"
            + "本番プロジェクトへ入っていました)。心当たりがその PR なら、Web 側の追加は取り消し、"
            + "宣言を持つプロジェクト(多くはテストプロジェクト)だけを上げてください。"
            + $"\n本当に本番へ入れる依存なら、{nameof(IntendedWebProjectDependencies)} へ理由を添えて"
            + "登録してください(出所とメンテ状況の確認はレビューで行います。§9)。");
    }

    [Fact]
    public void EveryIntendedDependency_IsStillADirectReference()
    {
        // ロックファイルに直接参照として残っていない表の行を集める
        var stale = IntendedWebProjectDependencies.Keys
            .Where(id => !WebProjectDirectPackages.Value.Contains(id, StringComparer.OrdinalIgnoreCase))
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        // 古い行を残すと「今は無いパッケージの事前承認」になり、後から黙って昇格できてしまう
        Assert.True(stale.Count == 0,
            $"{nameof(IntendedWebProjectDependencies)} に、Web プロジェクトの {LockFileName} で"
            + $"{DirectPackageKind} として解決されていない行があります:\n"
            + string.Join("\n", stale.Select(id => $"  {id}"))
            + "\n\n参照を外したのなら、この表の行も同じ変更セットで消してください。残しておくと"
            + "「今は存在しないパッケージへの事前承認」になり、後で同じ ID が直接参照へ昇格しても"
            + "この検査は何も言いません(fail-open)。");
    }

    [Fact]
    public void EveryIntendedDependency_HasAReason()
    {
        // 理由が空・空白だけの行を集める
        var withoutReason = IntendedWebProjectDependencies
            .Where(entry => string.IsNullOrWhiteSpace(entry.Value))
            .Select(entry => entry.Key)
            // 失敗メッセージの再現性のため並びを固定する
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToList();

        // 理由を空にできると、この表が「検出網を黙らせるだけの口」になる
        Assert.True(withoutReason.Count == 0,
            $"{nameof(IntendedWebProjectDependencies)} の理由が空(または空白だけ)です:\n"
            + string.Join("\n", withoutReason.Select(id => $"  {id}"))
            + "\n\nこの表はレビューで読むための記録なので、なぜ本番へ入れるのかを書いてください。");
    }

    // 本番の Web プロジェクトのロックファイルから、直接参照のパッケージ ID を読み出す。
    //
    // 【なぜ EfCorePackageAlignmentTests の走査を使わないか】あちらが答えるのは
    // 「ソリューション全体で、各パッケージがどの版に解決されたか」で、対象も全プロジェクトに及ぶ。
    // ここで要るのは「Web プロジェクト 1 つの直接参照の顔ぶれ」だけなので、目的も戻り値も違う。
    // 同じ JSON の歩き方が 3 箇所目に現れたら Helpers/ へ切り出すこと(§6 の「2〜3 箇所目で共通化」)。
    private static IReadOnlyList<string> ReadWebProjectDirectPackages()
    {
        // Web プロジェクトの隣にあるロックファイルを指す
        var lockFile = Path.Combine(RepositoryPaths.WebProject, LockFileName);

        // 見つからないまま先へ進むと検査が空振りするので、探した場所を示して落とす(fail-closed)
        Assert.True(File.Exists(lockFile),
            $"Web プロジェクトの {LockFileName} が見つかりません"
            + "(移動・リネーム、または RestorePackagesWithLockFile が外れた可能性があります)。"
            + $"探した場所: {lockFile}");

        // 失敗メッセージ用に、リポジトリルートからの相対パスにしておく
        var relativePath = Path.GetRelativePath(RepositoryPaths.Root, lockFile);
        // ロックファイルを JSON として解析する
        using var document = JsonDocument.Parse(File.ReadAllText(lockFile));

        // 解決結果はターゲットフレームワークごとに入れ子になっている。
        // 書式が変わって読めないときは、素の例外ではなくどのファイルが読めなかったかを示して落とす
        Assert.True(document.RootElement.TryGetProperty(DependenciesKey, out var dependencies),
            $"{relativePath} に {DependenciesKey} がありません。{LockFileName} の書式が変わった可能性があります"
            + "(読み取れないと、この検査は静かに空振りします)。");

        // 直接参照として現れたパッケージ ID を溜める入れ物
        var direct = new List<string>();
        // ターゲットフレームワークごとに解決結果を見る(将来 multi-target になっても取りこぼさない)
        foreach (var framework in dependencies.EnumerateObject())
        {
            // そのフレームワーク配下のパッケージを 1 件ずつ取り出す
            foreach (var entry in framework.Value.EnumerateObject())
            {
                // type を読む(無い項目は判定できないので直接参照とはみなさない)
                if (!entry.Value.TryGetProperty(TypeKey, out var type)) continue;
                // 直接参照でなければ対象外(推移依存はこの不変条件の対象ではない)
                if (!string.Equals(type.GetString(), DirectPackageKind, StringComparison.OrdinalIgnoreCase)) continue;
                // まだ拾っていなければ記録する(multi-target で同じ ID が複数回現れるため)
                if (!direct.Contains(entry.Name, StringComparer.OrdinalIgnoreCase)) direct.Add(entry.Name);
            }
        }

        // 直接参照が 1 件も読めないのは異常(書式変更など)で、放置すると「違反ゼロ＝緑」になる
        Assert.True(direct.Count > 0,
            $"{relativePath} から {DirectPackageKind} のパッケージを 1 件も読み取れませんでした。"
            + "この状態では上の検査がすべて空振りします。");

        // 読み取った一覧を返す
        return direct;
    }
}
