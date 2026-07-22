// アプリ本体の IClock 抽象を実装するために取り込む
using IncidentInsight.Web.Services;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// コンストラクタで渡した時刻を固定で返すテスト用の <see cref="IClock"/> 実装。
/// SystemClock(実時刻)では「未来の日時かどうか」のような境界判定テストが
/// 実行時刻に依存して不安定になるため、時刻を固定して決定論的に検証する。
/// </summary>
internal sealed class FixedClock : IClock
{
    // テストで「現在時刻」として扱う固定の日時
    private readonly DateTime _now;

    // 固定したい日時を受け取って保持するコンストラクタ
    public FixedClock(DateTime now) => _now = now;

    // 常に固定した日時を「現在時刻」として返す
    public DateTime Now => _now;

    // 固定した日時の 0 時 0 分を「今日」として返す
    public DateTime Today => _now.Date;

    // テストではタイムゾーンの区別が不要なため、固定した日時をそのまま UTC としても返す
    public DateTime UtcNow => _now;
}
