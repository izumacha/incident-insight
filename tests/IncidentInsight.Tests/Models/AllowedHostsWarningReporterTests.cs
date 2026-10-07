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
    // <b>定数をそのまま渡す（レビュー指摘）。</b> 以前は定数の<b>名前</b>を渡して
    // リフレクションで値を引いていたが、`const string` は InlineData にそのまま書けるので
    // 「綴りを書き写さない」目的は同じく満たせる。しかもリフレクション版にだけある壊れ方があり、
    // `const` を `static readonly` へ直すだけで GetRawConstantValue が投げ、
    // <b>drift ではなくリフレクションの失敗</b>として赤くなる
    [Theory]
    // 1 本目（全許可）の警告。
    // <b>運用手順の主役はこの 2 本（レビュー指摘）。</b> docs/security.md が
    // 「配備後にこのログが出ていないことを確認してください」と案内しているのは
    // 全許可と一致しえない項目の警告で、以前はその 2 本だけが突き合わせの外にいた ——
    // 診断の失敗（下の 2 本）より先に空振りしてはいけない綴りなのに、
    // <b>文面を推敲すると手順の grep だけが黙って永久に外れる</b>状態だった
    [InlineData(AllowedHostsWarningReporter.PermissiveWarningMarker)]
    // 2 本目（一致しえない項目）の警告
    [InlineData(AllowedHostsWarningReporter.NeverMatchingEntriesWarningMarker)]
    // 検査そのものが失敗したときの記録
    [InlineData(AllowedHostsWarningReporter.CheckFailedMessagePrefix)]
    // 再読み込みの購読を張れなかったときの記録
    [InlineData(AllowedHostsWarningReporter.SubscribeFailedMessagePrefix)]
    public void DiagnosticMarkers_AppearInTheOperatorRunbook(string marker)
    {
        // 運用者向けドキュメントを読む。
        // <b>読み口も共有する（レビュー指摘）。</b> パスだけを共有して
        // 読み方を各自で書くと、改行の正規化を足した側だけが直り、
        // もう片方は<b>Windows のチェックアウトでだけ壊れる</b>状態が黙って残る
        var securityDoc = MarkdownSource.Read(RepositoryPaths.SecurityDoc);

        // 手順がその綴りを引用していること
        Assert.Contains(marker, securityDoc, StringComparison.Ordinal);
    }
}
