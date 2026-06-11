// テスト全体で共通して使う定数・フィクスチャをまとめる
namespace IncidentInsight.Tests;

/// <summary>
/// テスト全体で共有する固定値。
/// 各テストクラスで独立定義すると値が乖離するリスクがあるため、ここを唯一の真実の源とする。
/// </summary>
internal static class TestFixtures
{
    // テスト全体で「今日」として使う固定日付（決定論的テストのため DateTime.Today を使わない）
    // PreventiveMeasureTests / IncidentTests / IncidentsControllerTests が参照する
    public static readonly DateTime Today = new DateTime(2026, 6, 11);
}
