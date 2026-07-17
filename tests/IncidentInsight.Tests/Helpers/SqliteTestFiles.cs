// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// SQLite ファイル DB を使うテストの共通後始末ヘルパー。
/// SQLite は本体ファイルのほかに WAL / SHM / journal の補助ファイルを作りうるため、
/// 後始末は必ずこのヘルパー経由で一括削除する(各テストにループを書き写すと、
/// 削除対象の差異(例: -journal の消し忘れ)が生まれ CI に一時ファイルが残る)。
/// </summary>
public static class SqliteTestFiles
{
    /// <summary>指定した SQLite DB ファイルと補助ファイルをまとめて削除する。</summary>
    public static void Cleanup(string dbPath)
    {
        // 本体 + SQLite が作りうる補助ファイルを列挙して削除する
        foreach (var path in new[] { dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal" })
        {
            // 存在するファイルだけ削除する
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
