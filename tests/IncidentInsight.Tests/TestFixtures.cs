// テスト全体で共通して使う定数・フィクスチャをまとめる
namespace IncidentInsight.Tests;

// 固定時計(FixedClock)を組み立てるために取り込む
using IncidentInsight.Tests.Helpers;
// IClock 抽象を型として使うために取り込む
using IncidentInsight.Web.Services;

/// <summary>
/// テスト全体で共有する固定値。
/// 各テストクラスで独立定義すると値が乖離するリスクがあるため、ここを唯一の真実の源とする。
/// </summary>
internal static class TestFixtures
{
    // テスト全体で「今日」として使う固定日付（決定論的テストのため DateTime.Today を使わない）。
    // 参照しているテストクラスをここに書き並べない — 参照が増えるたびにこの一覧だけが古くなる
    // （実際、以前の一覧は AnalyticsControllerTests が参照し始めた時点で不足していた）。
    //
    // 【この日付を動かすときの不変条件: 実時刻より過去に保つ】
    // 一部のテストクラスは、この日付を種データに使いながらコントローラへ実時計（SystemClock）を
    // 注入している。IncidentsController の Create/Edit は「発生日時に未来の日時は指定できません。」
    // を検証するため、この定数を実時刻より先の日付へ動かすと、それらの検査が一斉に
    // RedirectToActionResult ではなく ViewResult を受け取って落ちる（原因が定数側にあることは
    // 失敗メッセージからは分からない）。動かす必要が出たときは、同じ変更セットで該当クラスへ
    // 下の <see cref="Clock"/> を注入し、実時計への依存ごと外すこと。
    public static readonly DateTime Today = new DateTime(2026, 6, 11);

    // 上の固定日付を「今」として返す共有の時刻源。
    // コントローラへの注入とテストデータの生成で同じインスタンスを使うことで、
    // 「本体は IClock（JST）・データは OS のローカル時刻」という時刻源の割れを防ぐ（CLAUDE.md §3）。
    // FixedClock は不変（読み取り専用フィールドだけを持つ）なので、テスト間で共有しても
    // 干渉しない。各所で new FixedClock(TestFixtures.Today) と書き写すと、
    // 「正本の時計の作り方」を変えたときに書き写した側が取り残される（§6 DRY）。
    public static readonly IClock Clock = new FixedClock(Today);
}
