using System.Text.RegularExpressions;

namespace IncidentInsight.Tests.Views;

// Guard-rail tests: 楽観ロックトークンを引数で受け取る POST アクション
// (Complete / CompleteMeasure / RateMeasure / UpdateStatus) へ送信する Razor フォームが、
// concurrencyToken の hidden field を必ず持つことを検査する。
// 送信漏れがあるとコントローラ側で Guid.Empty が OriginalValue にピンされ、
// 楽観ロック検査が 100% 失敗して機能が完全に壊れる(ダッシュボードの「完了報告」で実際に発生した回帰)。
// コントローラ単体テストでは View の欠落を検出できないため、View ソースを直接走査して防ぐ。
public class ConcurrencyTokenFormTests
{
    // トークンの round-trip が必須な POST アクション名の一覧(コントローラの Guid concurrencyToken 引数と対応)
    private static readonly string[] TokenRequiredActions =
    {
        "Complete",        // PreventiveMeasuresController.Complete
        "CompleteMeasure", // IncidentMeasuresController.CompleteMeasure
        "RateMeasure",     // IncidentMeasuresController.RateMeasure
        "UpdateStatus",    // PreventiveMeasuresController.UpdateStatus
    };

    // <form ...> ... </form> のブロック全体を(改行を跨いで)抜き出す正規表現
    private static readonly Regex FormBlockRegex =
        new(@"<form\b(?<attrs>[^>]*)>(?<body>.*?)</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

    [Fact]
    public void Forms_PostingToTokenPinningActions_IncludeConcurrencyTokenHiddenField()
    {
        // リポジトリ内の Views ディレクトリを特定する
        var viewsDir = FindViewsDirectory();
        // 検出した違反(ファイル名と該当フォームの冒頭)を集める
        var violations = new List<string>();

        // すべての Razor ビューを走査する
        foreach (var file in Directory.EnumerateFiles(viewsDir, "*.cshtml", SearchOption.AllDirectories))
        {
            // ビューのソースを読み込む
            var source = File.ReadAllText(file);
            // ファイル内の <form> ブロックを列挙する
            foreach (Match form in FormBlockRegex.Matches(source))
            {
                // 開きタグの属性部分(asp-action / action がここに現れる)
                var attrs = form.Groups["attrs"].Value;
                // トークン必須アクションへ POST するフォームだけを対象にする
                if (!TargetsTokenRequiredAction(attrs)) continue;
                // フォーム内に concurrencyToken の入力欄があるか検査する
                if (form.Value.Contains("name=\"concurrencyToken\"", StringComparison.Ordinal)) continue;
                // 欠落を違反として記録する(ファイルとフォーム冒頭 80 文字で位置を特定できるようにする)
                var head = Regex.Replace(form.Value, @"\s+", " ");
                violations.Add($"{Path.GetFileName(file)}: {head[..Math.Min(80, head.Length)]}");
            }
        }

        // 違反ゼロであること(あればどのフォームかをメッセージで示す)
        Assert.True(violations.Count == 0,
            "concurrencyToken hidden field が欠落したフォームがあります:\n" + string.Join("\n", violations));
    }

    [Fact]
    public void DashboardOverdueAlert_CompleteForm_SendsConcurrencyToken()
    {
        // ダッシュボードの期限超過アラート内「完了報告」フォーム(過去に欠落した箇所)を個別に固定する
        var indexView = Path.Combine(FindViewsDirectory(), "Home", "Index.cshtml");
        // ビューのソースを読み込む
        var source = File.ReadAllText(indexView);
        // Complete へ POST するフォームブロックを取り出す
        var completeForm = FormBlockRegex.Matches(source)
            .Cast<Match>()
            .FirstOrDefault(m => m.Groups["attrs"].Value.Contains("asp-action=\"Complete\"", StringComparison.Ordinal));
        // フォーム自体が存在すること
        Assert.NotNull(completeForm);
        // 実トークン(@m.ConcurrencyToken)を hidden field で送信していること
        Assert.Contains("name=\"concurrencyToken\" value=\"@m.ConcurrencyToken\"", completeForm!.Value);
    }

    // 開きタグの属性がトークン必須アクション宛てかどうかを判定する
    private static bool TargetsTokenRequiredAction(string attrs)
    {
        // asp-action="X" 形式(Tag Helper)と action="/…/X/…" 形式(素の HTML + JS 差し替え)の両方を見る
        return TokenRequiredActions.Any(action =>
            attrs.Contains($"asp-action=\"{action}\"", StringComparison.Ordinal) ||
            Regex.IsMatch(attrs, $@"\baction=""[^""]*/{action}(/|"")"));
    }

    // テスト実行ディレクトリから上へ辿り src/IncidentInsight.Web/Views を見つける
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
