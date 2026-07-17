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
/// 既定の実装。OS のタイムゾーン設定に依存せず、UTC から JST へ明示変換して返す。
/// 以前は <see cref="DateTime.Now"/> をそのまま返しており「OS が JST 設定である」ことが
/// 暗黙の前提だったが、Linux コンテナ / クラウド(既定 UTC)へ配備すると全タイムスタンプが
/// 9 時間ずれる(Issue #31 と同種のバグ)ため、TimeZoneInfo で常に JST へ変換する。
/// </summary>
// 実運用向けの既定実装。UTC を基準に JST へ変換して返す
public sealed class SystemClock : IClock
{
    // JST のタイムゾーン情報(プロセス起動時に一度だけ解決してキャッシュ)
    private static readonly TimeZoneInfo JstZone = ResolveJstZone();

    // JST のタイムゾーンを OS 非依存に解決する。
    // IANA ID("Asia/Tokyo")は Linux / macOS / ICU 有効な Windows で使え、
    // 見つからない環境(ICU 無効の Windows 等)では Windows ID("Tokyo Standard Time")へ
    // フォールバックする(§10 プラットフォーム差を 1 か所に閉じ込める)。
    private static TimeZoneInfo ResolveJstZone()
    {
        try
        {
            // まず IANA 形式のタイムゾーン ID で検索する
            return TimeZoneInfo.FindSystemTimeZoneById("Asia/Tokyo");
        }
        catch (TimeZoneNotFoundException)
        {
            // IANA ID が無い環境では Windows 形式の ID で再検索する
            return TimeZoneInfo.FindSystemTimeZoneById("Tokyo Standard Time");
        }
    }

    // UTC の現在時刻を JST へ変換して返す(OS のタイムゾーン設定に依存しない)
    public DateTime Now => TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, JstZone);
    // JST の今日の日付(0:00:00)を返す
    public DateTime Today => Now.Date;
    // OS の UTC 時刻を返す
    public DateTime UtcNow => DateTime.UtcNow;
}
