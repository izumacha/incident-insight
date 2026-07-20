using System.Text.RegularExpressions;

namespace IncidentInsight.Tests.Views;

// Guard-rail tests: Admin/RiskManager 限定のコントローラ(AnalyticsController /
// IncidentsController.Delete)へ誘導する View 側のリンク・ボタンが、対応するロール
// チェックで囲まれていることを検査する。
//
// 過去の回帰: AnalyticsController は [Authorize(Policy = Policies.CanViewAnalytics)]
// (Admin/RiskManager 限定)、IncidentsController.Delete は
// [Authorize(Policy = Policies.CanDeleteIncident)](同じく Admin/RiskManager 限定)だが、
// これらへ遷移する UI(ナビの「分析・集計」リンク、ダッシュボードの「分析ページで確認」
// リンク、インシデント編集画面の「削除」ボタン)がロールで隠されておらず、
// 自部署のインシデントを閲覧・編集できる Staff にも無条件で表示されていた。
// Staff がクリックすると常に 403(AccessDenied へリダイレクト)になる、押しても
// 絶対に成功しない UI/コントローラ不整合。
//
// コントローラ単体テストでは View 側の表示条件の欠落を検出できないため、
// ConcurrencyTokenFormTests と同様に View ソースを直接走査して固定する。
public class RoleGatedNavigationTests
{
    // 「Admin または RiskManager のみ」を表す @if 条件(このリポジトリで統一して使う文言)
    private const string FullAccessRoleCondition =
        "User.IsInRole(AppRoles.Admin) || User.IsInRole(AppRoles.RiskManager)";

    // @if (条件) { 本体 } ブロックを(改行を跨いで)非貪欲に抜き出す正規表現。
    // 本体側は最初に現れる「改行 + インデント空白 + 単独の "}"」で閉じると仮定する
    // (このリポジトリの @if ブロックは C# のネストしたラムダ式等を含まないため、
    //  ConcurrencyTokenFormTests の <form>...</form> 抽出と同じ考え方で成立する。
    //  閉じ括弧の前にインデント用の空白/タブが入る点を見落とすとマッチしないため、
    //  "\r?\n\}" ではなく "\r?\n[ \t]*\}" にしている)。
    private static readonly Regex FullAccessIfBlockRegex = new(
        $@"@if\s*\(\s*{Regex.Escape(FullAccessRoleCondition)}\s*\)\s*\{{(?<body>.*?)\r?\n[ \t]*\}}",
        RegexOptions.Singleline);

    [Fact]
    public void Layout_AnalyticsNavLink_IsGuardedByFullAccessRole()
    {
        // AnalyticsController(CanViewAnalytics = Admin/RiskManager 限定)へのナビリンクが
        // ロールガード内にあることを確認する
        var source = ReadView("Shared", "_Layout.cshtml");
        AssertMarkerIsInsideFullAccessGuard(
            source, "asp-controller=\"Analytics\" asp-action=\"Index\"",
            "Views/Shared/_Layout.cshtml の「分析・集計」ナビリンク");
    }

    [Fact]
    public void DashboardFailedMeasuresAlert_AnalyticsLink_IsGuardedByFullAccessRole()
    {
        // ダッシュボードの「再発が確認された対策」アラート内の分析ページリンクが
        // ロールガード内にあることを確認する
        var source = ReadView("Home", "Index.cshtml");
        AssertMarkerIsInsideFullAccessGuard(
            source, "asp-controller=\"Analytics\" asp-action=\"Index\" class=\"alert-link",
            "Views/Home/Index.cshtml の「分析ページで確認」リンク");
    }

    [Fact]
    public void IncidentEdit_DeleteButton_IsGuardedByFullAccessRole()
    {
        // IncidentsController.Delete(CanDeleteIncident = Admin/RiskManager 限定)への
        // 削除フォームがロールガード内にあることを確認する
        var source = ReadView("Incidents", "Edit.cshtml");
        AssertMarkerIsInsideFullAccessGuard(
            source, "asp-action=\"Delete\" asp-route-id=\"@Model.Id\"",
            "Views/Incidents/Edit.cshtml の削除ボタン");
    }

    // 指定マーカー文字列が、FullAccessRoleCondition の @if ブロック内に含まれているかを検証する
    private static void AssertMarkerIsInsideFullAccessGuard(string source, string marker, string description)
    {
        // マーカー自体がファイル内に存在すること(リファクタでマークアップ自体が消えていないか)
        Assert.True(source.Contains(marker, StringComparison.Ordinal),
            $"{description} が見つかりません(マーカー文字列 '{marker}' が変更された可能性があります)。");

        // FullAccessRoleCondition の @if ブロックのいずれかがマーカーを含むことを確認する
        var guarded = FullAccessIfBlockRegex.Matches(source)
            .Cast<Match>()
            .Any(m => m.Groups["body"].Value.Contains(marker, StringComparison.Ordinal));

        Assert.True(guarded,
            $"{description} が「{FullAccessRoleCondition}」の @if ブロックで囲まれていません。" +
            "対応するコントローラアクションが Admin/RiskManager 限定の場合、UI 側もロールで隠さないと" +
            "Staff がクリックしても常に 403 になる導線が残ります。");
    }

    // Views/{controller}/{file} を読み込むヘルパー
    private static string ReadView(string controllerFolder, string fileName)
    {
        var path = Path.Combine(FindViewsDirectory(), controllerFolder, fileName);
        return File.ReadAllText(path);
    }

    // テスト実行ディレクトリから上へ辿り src/IncidentInsight.Web/Views を見つける
    // (ConcurrencyTokenFormTests と同じ探索ロジック)
    private static string FindViewsDirectory()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ルートに達するまで親を遡る
        while (dir != null)
        {
            // リポジトリルートの目印(ソリューションファイル)を探す
            var candidate = Path.Combine(dir.FullName, "src", "IncidentInsight.Web", "Views");
            // Views ディレクトリが見つかればそれを返す
            if (Directory.Exists(candidate)) return candidate;
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException("src/IncidentInsight.Web/Views がテスト実行位置から見つかりません。");
    }
}
