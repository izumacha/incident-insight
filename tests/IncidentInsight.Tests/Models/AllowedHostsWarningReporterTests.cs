// 文書（docs/security.md）を読むために使う
using IncidentInsight.Tests.Helpers;
// 突き合わせる定数の置き場所
using IncidentInsight.Web.Models.Validation;
// テストフレームワーク
using Xunit;

// このテストが属する名前空間(判定側の検査と同じ場所)
namespace IncidentInsight.Tests.Models;

/// <summary>
/// 運用手順が引用している診断の綴りが、実装と食い違っていないことを固定する。
/// </summary>
/// <remarks>
/// <b>なぜ要るのか。</b> <c>docs/security.md</c> は運用者へ
/// 「この文字列が出ていないことを確認せよ」と案内している。文言を <c>Program.cs</c> の
/// literal のままにしておくと、言い回しを変えた瞬間に<b>手順の grep が永久に空振りする</b> ——
/// 診断が静かに失敗している配備が「きれい」と読め、この節が防ごうとしている
/// <b>誤った安心</b>そのものになる（レビュー指摘）。
/// 兄弟の <c>StaticAssetCacheControl_MatchesTheDocumentedDirective</c> と同じ形で、
/// <b>文書と定数のどちらか一方だけを動かす差分</b>が必ず落ちるようにしてある。
/// </remarks>
public class AllowedHostsWarningReporterTests
{
    [Theory]
    // 検査そのものが失敗したときの記録
    [InlineData(nameof(AllowedHostsWarningReporter.CheckFailedMessagePrefix))]
    // 再読み込みの購読を張れなかったときの記録
    [InlineData(nameof(AllowedHostsWarningReporter.SubscribeFailedMessagePrefix))]
    public void DiagnosticMarkers_AppearInTheOperatorRunbook(string constantName)
    {
        // 名前から定数の値を取り出す(テストへ綴りを書き写さないため)
        var marker = (string)typeof(AllowedHostsWarningReporter)
            .GetField(constantName)!
            .GetRawConstantValue()!;

        // 運用者向けドキュメントを読む
        var securityDoc = File.ReadAllText(
            Path.Combine(RepositoryPaths.Root, "docs", "security.md"));

        // 手順がその綴りを引用していること
        Assert.Contains(marker, securityDoc, StringComparison.Ordinal);
    }
}
