// 日本語ラベルの一元解決(EnumLabels)を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;
// 監査対象エンティティ名の唯一の真実の源(AuditSaveChangesInterceptor)を参照するために取り込む
using IncidentInsight.Web.Data;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 監査ログ画面のエンティティ名ラベルが、監査対象すべてを網羅していることを固定するテスト。
//
// なぜ必要か: AuditLogsController.AllowedEntityNames は AuditSaveChangesInterceptor.AuditedEntities
// から導出されるので、監査対象を足せばフィルタの許可リストもドロップダウンも自動で追随する。
// ところが**そのすぐ隣で使われる日本語ラベルの変換表 EnumLabels.AuditEntityJa は手書きの写し**で、
// JapaneseAuditEntity は辞書に無いキーを渡されると「元の値をそのまま返す」フォールバックを持つ。
//
// つまり監査対象を 1 つ足すと、ラベルだけが取り残されて CLR の型名("CauseCategory" 等)が
// 日本語 UI の 3 箇所(ドロップダウン / AuditLogs/Index の各行 / AuditLogs/Details)に
// 英語のまま出る。フォールバックがあるおかげで例外にもならず、ビルドも全テストも緑のまま通る。
//
// これは導出元をそろえた PR がまさに塞ごうとしている「写しが取り残される」形そのものなので、
// 「ラベル表は監査対象を全網羅する」ことを機械的に固定する。
// (フォールバック自体は残す — 監査ログは過去の行を保持し続けるため、監査対象から外した
//  エンティティの古い行を表示するときに例外で画面を落とすより、元の値を出す方が安全)
public class AuditEntityLabelCoverageTests
{
    [Fact]
    public void EveryAuditedEntity_HasJapaneseLabel()
    {
        // ラベルが引けなかった(= フォールバックで元の値がそのまま返ってきた)監査対象を集める
        var missing = AuditSaveChangesInterceptor.AuditedEntities
            // 変換結果が入力と同一なら、辞書に無くてフォールバックしたということ
            .Where(name => EnumLabels.JapaneseAuditEntity(name) == name)
            // 失敗メッセージの並びを実行ごとに揺らさないため序数順に整える
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 網羅漏れが 1 件も無いことを確認する(失敗時はどの監査対象かと対処法を示す)
        Assert.True(missing.Count == 0,
            $"監査対象エンティティの日本語ラベルが EnumLabels.AuditEntityJa にありません: " +
            $"{string.Join(", ", missing)}。" +
            "JapaneseAuditEntity は辞書に無いキーを元の値のまま返すため、これを放置すると " +
            "監査ログ画面(フィルタのドロップダウン / 一覧の各行 / 詳細)に CLR の型名が " +
            "英語のまま表示されます。EnumLabels.AuditEntityJa に日本語ラベルを追加してください。");
    }

    [Fact]
    public void AuditedEntities_IsNotEmpty()
    {
        // 監査対象が 0 件だと上の検査が「漏れゼロ」で緑になり、検出網が黙って死ぬ(fail-closed)
        Assert.NotEmpty(AuditSaveChangesInterceptor.AuditedEntities);
    }
}
