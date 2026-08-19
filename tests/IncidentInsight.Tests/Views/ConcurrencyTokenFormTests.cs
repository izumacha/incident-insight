using System.Text.RegularExpressions;

// リポジトリ内のパスを解決する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

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
        "Complete",             // PreventiveMeasuresController.Complete
        "CompleteMeasure",      // IncidentMeasuresController.CompleteMeasure
        "RateMeasure",          // IncidentMeasuresController.RateMeasure
        "UpdateStatus",         // PreventiveMeasuresController.UpdateStatus
        "Delete",               // IncidentsController.Delete / PreventiveMeasuresController.Delete
        "DeleteCauseAnalysis",  // CauseAnalysesController.DeleteCauseAnalysis
    };

    // 素の hidden input が出力する name 属性のリテラル(コントローラ引数 concurrencyToken と対応)
    private const string TokenFieldNameLiteral = "name=\"concurrencyToken\"";

    // CSRF + 楽観ロックトークンをセット出力する共通部品(Views/Shared/_ConcurrencyTokenFields.cshtml)の参照
    private const string TokenPartialReference = "<partial name=\"_ConcurrencyTokenFields\"";

    // <form ...> ... </form> のブロック全体を(改行を跨いで)抜き出す正規表現
    private static readonly Regex FormBlockRegex =
        new(@"<form\b(?<attrs>[^>]*)>(?<body>.*?)</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase);

    [Fact]
    public void Forms_PostingToTokenPinningActions_IncludeConcurrencyTokenHiddenField()
    {
        // 検出した違反(ファイル名と該当フォームの冒頭)を集める
        var violations = new List<string>();
        // 検査したトークン必須フォームの数。0 件のまま終わると「違反なし」と区別が付かず、
        // 検出パターンが壊れただけなのに緑になってしまうため数えておく
        // (ChartAccessibilityTests / RoleGatedNavigationTests と同じ空振り対策)
        var inspectedTargetForms = 0;

        // すべての Razor ビューを走査する
        foreach (var file in RepositoryPaths.EnumerateViewFiles())
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
                // 対象フォームを 1 件検査したものとして数える
                inspectedTargetForms++;
                // フォーム内に concurrencyToken の入力欄があるか検査する(素の name 記法と asp-for 記法の両対応)
                if (HasConcurrencyTokenField(form.Value)) continue;
                // 欠落を違反として記録する(ファイルとフォーム冒頭 80 文字で位置を特定できるようにする)
                var head = Regex.Replace(form.Value, @"\s+", " ");
                violations.Add($"{Path.GetFileName(file)}: {head[..Math.Min(80, head.Length)]}");
            }
        }

        // 検査対象が 1 件も見つからないのは想定外(フォームの書き方が変わって FormBlockRegex が
        // 合わなくなった、アクション名を改名して TokenRequiredActions と食い違った、等を示す)
        Assert.True(inspectedTargetForms > 0,
            "トークン必須アクションへ POST するフォームが Views 配下に 1 つも見つかりませんでした。"
            + "検出パターンまたは対象アクション名が変更された可能性があります。");

        // 違反ゼロであること(あればどのフォームかをメッセージで示す)
        Assert.True(violations.Count == 0,
            "concurrencyToken hidden field が欠落したフォームがあります:\n" + string.Join("\n", violations));
    }

    [Fact]
    public void DashboardOverdueAlert_CompleteForm_SendsConcurrencyToken()
    {
        // ダッシュボードの期限超過アラート内「完了報告」フォーム(過去に欠落した箇所)を個別に固定する
        var indexView = Path.Combine(RepositoryPaths.Views, "Home", "Index.cshtml");
        // ビューのソースを読み込む
        var source = File.ReadAllText(indexView);
        // Complete へ POST するフォームブロックを取り出す
        var completeForm = FormBlockRegex.Matches(source)
            .Cast<Match>()
            .FirstOrDefault(m => m.Groups["attrs"].Value.Contains("asp-action=\"Complete\"", StringComparison.Ordinal));
        // フォーム自体が存在すること
        Assert.NotNull(completeForm);
        // 共通部品(_ConcurrencyTokenFields)経由で実トークン(モデルの ConcurrencyToken)を送信していること
        // (ループ変数名のリファクタで壊れないよう、部品参照とモデル束縛の対応だけを正規表現で固定する)
        Assert.Matches(@"<partial\s+name=""_ConcurrencyTokenFields""\s+model=""\w+\.ConcurrencyToken""", completeForm!.Value);
    }

    // 開きタグの属性がトークン必須アクション宛てかどうかを判定する
    private static bool TargetsTokenRequiredAction(string attrs)
    {
        // asp-action="X"(Tag Helper) / action="/…/X/…"(素の HTML + JS 差し替え) /
        // action="@Url.Action("X", …)"(Razor ヘルパー) の 3 形式を見る。
        // いずれにも当たらない書き方(単引用符・formaction 等)は検査対象外になるため、
        // トークン必須アクションへの新しいフォームは上記いずれかの形式で書くこと。
        return TokenRequiredActions.Any(action =>
            attrs.Contains($"asp-action=\"{action}\"", StringComparison.Ordinal) ||
            Regex.IsMatch(attrs, $@"\baction=""[^""]*/{action}(/|"")") ||
            attrs.Contains($"Url.Action(\"{action}\"", StringComparison.Ordinal));
    }

    // フォーム本体が concurrencyToken の入力欄を持つかを判定する
    private static bool HasConcurrencyTokenField(string formBlock)
    {
        // 次の 3 記法を受け付ける:
        // (1) 共通部品 <partial name="_ConcurrencyTokenFields" model="…" />(推奨。CSRF とセットで出力)
        // (2) 素の name 記法(name="concurrencyToken"。大文字始まりの name="ConcurrencyToken" も
        //     モデルバインドは大文字小文字非依存なので許容)
        // (3) Tag Helper の asp-for 記法(asp-for="ConcurrencyToken"。実行時に name="ConcurrencyToken" を出力)
        return formBlock.Contains(TokenPartialReference, StringComparison.Ordinal) ||
               formBlock.Contains(TokenFieldNameLiteral, StringComparison.OrdinalIgnoreCase) ||
               formBlock.Contains("asp-for=\"ConcurrencyToken\"", StringComparison.Ordinal);
    }
}
