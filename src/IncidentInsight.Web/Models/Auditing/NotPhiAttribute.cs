// この型の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Auditing;

/// <summary>
/// 監査対象エンティティの文字列カラムのうち、<see cref="SensitiveAttribute"/> を付けずに
/// <c>AuditLog.ChangesJson</c> へ平文で残してよいものに付ける「明示的な除外」印。
///
/// なぜ「付けない」ではなく「付けないと宣言する」必要があるか:
///   <see cref="AuditSaveChangesInterceptor"/> の <c>SerializeChanges</c> は、
///   <see cref="SensitiveAttribute"/> が無いプロパティの値を**そのまま** ChangesJson へ書く。
///   つまり PHI(患者の個人情報)を含む列を新設して annotate を忘れると、ビルドもテストも緑のまま
///   平文の PHI が監査テーブルへ流れ込む。しかも <c>AuditLog</c> は追記専用(インターセプタが唯一の
///   書き込み源で、UPDATE/DELETE 経路を持たない)ため、後から気付いても書かれた行は消せない。
///   「無印」が「安全だと判断した」と「判断し忘れた」の両方を意味してしまうのが問題の核で、
///   両者を区別できる限り、付け忘れは検出できない。
///
/// そこで <c>AuditedEntityPhiClassificationTests</c> が「監査対象エンティティの永続化される
/// string 列は、<see cref="SensitiveAttribute"/> か本属性のどちらかを必ず持つ」ことを機械的に
/// 固定する。分類し忘れた列はどちらも持たないので、テストが落ちて気付ける
/// (helpdesk-hub の失敗イベント分類表が Set ではなく網羅的な Record である理由と同じ発想:
///  「綴り間違い」ではなく「分類し忘れ」を捕まえたいので、無印を許さない形にする)。
///
/// 例: [NotPhi("部署名は Incident.Departments の固定候補から選ぶ閉じた語彙で、自由記述ではない")]
/// </summary>
// Property にだけ付けられる。重複指定は禁止(理由が 2 つ並ぶと、どちらが現行の判断か読めなくなる)
[AttributeUsage(AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
public sealed class NotPhiAttribute : Attribute
{
    // なぜ平文で残してよいと判断したのかの理由(監査・レビュー時に読む唯一の根拠)
    public string Reason { get; }

    // 理由を必須の引数にしているのは、引数なしで付けられると「とりあえず黙らせる」使い方ができてしまい、
    // 検出網が「分類したかどうか」しか見なくなるため。判断の中身をコードに残させる
    public NotPhiAttribute(string reason)
    {
        // 空文字や空白だけの理由は「理由を書いた」ことにならないので、その場で弾く(fail-closed)
        if (string.IsNullOrWhiteSpace(reason))
        {
            // 付け方の誤りは実行時ではなく開発時に気付くべきなので例外で知らせる
            throw new ArgumentException("PHI 除外の理由は必須です(なぜ平文で残してよいのかを書く)。", nameof(reason));
        }

        // 検証を通った理由を保持する
        this.Reason = reason;
    }
}
