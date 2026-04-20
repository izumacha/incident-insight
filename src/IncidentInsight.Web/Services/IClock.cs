// このサービス群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Services;

/// <summary>
/// 時刻源の抽象化。アプリケーション内で <see cref="DateTime.Now"/> /
/// <see cref="DateTime.Today"/> / <see cref="DateTime.UtcNow"/> を直接呼ばず、
/// この抽象を経由することで (a) テスト時に時刻を固定でき、(b) 運用タイムゾーン
/// ポリシーを一点で差し替え可能にする。
///
/// <para>
/// 運用ポリシー: <b>IncidentInsight は運用タイムゾーン (JST) のローカル時刻で
/// すべてのビジネスタイムスタンプを格納する</b>。これは既存の DB スキーマおよび
/// ビューの前提と一致する。将来 UTC へ移行する場合は
/// <see cref="SystemClock"/> の実装と表示側のフォーマッタを併せて差し替える。
/// </para>
/// <para>
/// Issue #31 参照: 以前は監査ログだけ UTC・他はローカルで 9h のオフセットが
/// 発生していたが、このインタフェースに集約することで解消している。
/// </para>
/// </summary>
public interface IClock
{
    /// <summary>運用タイムゾーン(JST)の現在時刻。</summary>
    // 運用タイムゾーン(JST)の「今この瞬間」を返すプロパティ
    DateTime Now { get; }

    /// <summary>運用タイムゾーン(JST)の今日の日付(0:00:00)。</summary>
    // 運用タイムゾーン(JST)の「今日の 0 時 0 分」を返すプロパティ
    DateTime Today { get; }

    /// <summary>UTC 現在時刻(外部連携・一部メタ情報用)。</summary>
    // 世界協定時刻(UTC)の現在時刻。外部連携用などで使う
    DateTime UtcNow { get; }
}

/// <summary>
/// 既定の実装。サーバの OS ロケールが JST に設定されている前提で
/// <see cref="DateTime.Now"/> / <see cref="DateTime.Today"/> を返す。
/// </summary>
// 実運用向けの既定実装。OS の時刻をそのまま使う
public sealed class SystemClock : IClock
{
    // OS のローカル時刻(運用では JST 設定)を返す
    public DateTime Now => DateTime.Now;
    // OS のローカル日付(0:00:00)を返す
    public DateTime Today => DateTime.Today;
    // OS の UTC 時刻を返す
    public DateTime UtcNow => DateTime.UtcNow;
}
