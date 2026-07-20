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
    // 「Admin または RiskManager のみ」を表す @if 条件(このリポジトリで統一して使う文言。
    // DepartmentScope.HasFullAccess() 拡張メソッドに一元化された判定を View 側から呼ぶ)
    private const string FullAccessRoleCondition = "User.HasFullAccess()";

    // @if (条件) { 本体 } ブロックを(改行を跨いで)非貪欲に抜き出す正規表現。
    // 本体側は最初に現れる「改行 + インデント空白 + 単独の "}"」で閉じると仮定する
    // (このリポジトリの @if ブロックは C# のネストしたラムダ式等を含まないため、
    //  ConcurrencyTokenFormTests の <form>...</form> 抽出と同じ考え方で成立する。
    //  閉じ括弧の前にインデント用の空白/タブが入る点を見落とすとマッチしないため、
    //  "\r?\n\}" ではなく "\r?\n[ \t]*\}" にしている)。
    private static readonly Regex FullAccessIfBlockRegex = new(
        $@"@if\s*\(\s*{Regex.Escape(FullAccessRoleCondition)}\s*\)\s*\{{(?<body>.*?)\r?\n[ \t]*\}}",
        RegexOptions.Singleline);

    // AnalyticsController(CanViewAnalytics = Admin/RiskManager 限定)へのリンクを検出するパターン
    private static readonly Regex AnalyticsLinkRegex =
        new(@"asp-controller=""Analytics""\s+asp-action=""Index""", RegexOptions.None);

    // Delete アクションへのフォームを検出するパターン。IncidentsController.Delete /
    // PreventiveMeasuresController.Delete はいずれも [Authorize(Policy = Policies.CanDeleteIncident)]
    // (Admin/RiskManager 限定)のため、asp-action="Delete" は常にこのポリシー配下にある前提で検査する
    private static readonly Regex DeleteActionRegex =
        new(@"asp-action=""Delete""", RegexOptions.None);

    [Fact]
    public void AnyAnalyticsLink_AcrossAllViews_IsGuardedByFullAccessRole()
    {
        // 特定ファイルだけでなく Views 配下のすべての .cshtml を走査する。
        // 個別ファイルだけを検査すると、将来別の View に新しい Analytics リンクが
        // 追加されたときにガード漏れを検知できない(3 箇所固定チェックの弱点を解消する)。
        AssertEveryMatchIsGuardedAcrossAllViews(
            AnalyticsLinkRegex,
            "AnalyticsController(CanViewAnalytics = Admin/RiskManager 限定)へのリンク");
    }

    [Fact]
    public void AnyDeleteForm_AcrossAllViews_IsGuardedByFullAccessRole()
    {
        // 同上。IncidentsController.Delete / PreventiveMeasuresController.Delete のいずれかへの
        // 新しい削除フォームが将来追加されても、ガード漏れがあれば検知できるようにする
        AssertEveryMatchIsGuardedAcrossAllViews(
            DeleteActionRegex,
            "Delete アクション(CanDeleteIncident = Admin/RiskManager 限定)への削除フォーム");
    }

    [Fact]
    public void IncidentEdit_DeleteButton_IsGuardedByFullAccessRole()
    {
        // 過去に実際に欠落していた具体箇所(インシデント編集画面の削除ボタン)を
        // 個別に固定する回帰テスト(ConcurrencyTokenFormTests の
        // DashboardOverdueAlert_CompleteForm_SendsConcurrencyToken と同じ位置づけ)
        var source = ReadView("Incidents", "Edit.cshtml");
        var match = DeleteActionRegex.Match(source);
        Assert.True(match.Success, "Views/Incidents/Edit.cshtml の削除ボタンが見つかりません。");
        Assert.True(IsGuardedByFullAccessRole(source, match.Index),
            "Views/Incidents/Edit.cshtml の削除ボタンが「User.HasFullAccess()」の @if ブロックで" +
            "囲まれていません。");
    }

    // 指定した正規表現にマッチする箇所すべてが、Views 配下のどのファイルにあっても
    // FullAccessRoleCondition の @if ブロック内にあることを検証する
    private static void AssertEveryMatchIsGuardedAcrossAllViews(Regex targetPattern, string description)
    {
        // 検出した違反(ファイル名とマッチ箇所)を集める
        var violations = new List<string>();
        // マッチが 1 件も見つからなければ検査パターン自体が壊れている可能性があるので記録する
        var totalMatches = 0;

        // Views 配下のすべての .cshtml を走査する
        foreach (var file in Directory.EnumerateFiles(FindViewsDirectory(), "*.cshtml", SearchOption.AllDirectories))
        {
            // ビューのソースを読み込む
            var source = File.ReadAllText(file);
            // このファイル内の対象パターンをすべて列挙する
            foreach (Match m in targetPattern.Matches(source))
            {
                totalMatches++;
                // マッチ位置がロールガード内かどうかを確認する
                if (!IsGuardedByFullAccessRole(source, m.Index))
                {
                    violations.Add($"{Path.GetFileName(file)}: 位置 {m.Index} 付近 ('{m.Value}')");
                }
            }
        }

        // 検査対象が 1 件も見つからないのは想定外(検出パターンの劣化を示す可能性がある)
        Assert.True(totalMatches > 0,
            $"{description} が Views 配下のどこにも見つかりませんでした。検出パターンが変更された可能性があります。");
        // 違反ゼロであること(あればどのファイル・位置かをメッセージで示す)
        Assert.True(violations.Count == 0,
            $"{description} で「{FullAccessRoleCondition}」の @if ブロックに囲まれていない箇所があります:\n" +
            string.Join("\n", violations));
    }

    // 指定インデックス位置が、ソース内のいずれかの FullAccessRoleCondition ガードブロックの
    // 本体(body)範囲内に収まっているかを判定する
    private static bool IsGuardedByFullAccessRole(string source, int targetIndex)
        => FullAccessIfBlockRegex.Matches(source)
            .Cast<Match>()
            .Any(m => targetIndex >= m.Groups["body"].Index
                      && targetIndex < m.Groups["body"].Index + m.Groups["body"].Length);

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
