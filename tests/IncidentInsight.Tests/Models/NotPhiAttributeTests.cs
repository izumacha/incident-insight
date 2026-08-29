// [NotPhi] 属性の定義を使うために取り込む
using IncidentInsight.Web.Models.Auditing;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// [NotPhi] 属性そのものの契約テスト。
//
// この属性の値打ちは「なぜ平文で監査ログに残してよいと判断したのか」がコードに残ることにあり、
// 理由を空にできると「とりあえず検出網を黙らせる」使い方が通ってしまう。そうなると
// AuditedEntityPhiClassificationTests は「分類したかどうか」しか見なくなり、判断の中身を
// 伴わない除外を素通りさせる — 検出網が形だけ残って実質死ぬ。
// ここで境界値(null / 空文字 / 空白のみ)を潰しておく。
public class NotPhiAttributeTests
{
    [Fact]
    public void Constructor_KeepsReason_WhenGivenNonEmptyText()
    {
        // 通常の使い方: 理由を渡して属性を作る
        var attribute = new NotPhiAttribute("固定候補から選ぶ閉じた語彙のため");

        // 渡した理由がそのまま読み出せることを確認する(レビュー時に読む唯一の根拠)
        Assert.Equal("固定候補から選ぶ閉じた語彙のため", attribute.Reason);
    }

    [Theory]
    // 理由なしとみなす入力を並べる(null / 空文字 / 半角空白 / 全角空白 / タブ)
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("　")]
    [InlineData("\t")]
    public void Constructor_Throws_WhenReasonIsMissingOrBlank(string? reason)
    {
        // 理由が実質空なら例外になることを確認する(付け方の誤りを開発時に気付かせる)
        var ex = Assert.Throws<ArgumentException>(() => new NotPhiAttribute(reason!));

        // どの引数が悪いのかが呼び出し側に伝わることを確認する
        Assert.Equal("reason", ex.ParamName);
    }
}
