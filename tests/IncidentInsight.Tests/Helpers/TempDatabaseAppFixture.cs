// WebApplicationFactory(実 HTTP パイプラインでの統合テスト)を使う
using Microsoft.AspNetCore.Mvc.Testing;
// テスト用の環境名指定に使う
using Microsoft.AspNetCore.Hosting;
// テスト用の設定上書きに使う
using Microsoft.Extensions.Configuration;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// テスト専用の一時 DB を指してアプリを<b>1 度だけ</b>起動し、使い終わったファイルを消すフィクスチャ。
/// </summary>
/// <remarks>
/// <para><b>なぜテストクラスのコンストラクタで組み立ててはいけないのか。</b>
/// xUnit はテストメソッドごとにテストクラスを作り直すので、コンストラクタで
/// <c>WithWebHostBuilder</c> を呼ぶと<b>派生ファクトリがテストの数だけ生まれる</b> ——
/// <c>IClassFixture</c> でファクトリ自体を共有していても、アプリの起動・マイグレーション・
/// シードがテストごとに走り、そのたびに別名の一時 DB ができる。
/// 生成した <c>.db</c>(および SQLite が並べて作る補助ファイル)は誰も消さないので、
/// CI ランナーや開発機に上限なく溜まる(§8「リソースを確実に解放する」)。</para>
///
/// <para><b>だから組み立てをここへ 1 か所に寄せる。</b> 統合テストが 2 つ以上あると
/// 同じ仕掛けを書き写すことになり、片方だけ後始末が直る(＝もう片方は漏れ続ける)ので、
/// 設定の違いだけを派生クラスから渡す形にする(CLAUDE.md §6 DRY)。
/// 削除は <see cref="SqliteTestFiles"/> 経由で行う ——消す対象(WAL / SHM / journal)の
/// 一覧をここに書き写すと、対象が増えたときに片方だけ古くなる。</para>
/// </remarks>
public abstract class TempDatabaseAppFixture : IDisposable
{
    // 生成した一時 DB のパス(後始末で消す対象を推測しないよう、作った値をそのまま持つ)
    private readonly string _databasePath;

    // アプリ全体を起動する素のファクトリ(Dispose の対象として保持する)
    private readonly WebApplicationFactory<Program> _baseFactory = new();

    /// <summary>
    /// 一時 DB を指す設定でアプリを起動する。
    /// </summary>
    /// <param name="databaseFileNamePrefix">一時 DB のファイル名の接頭辞(どのテストの物か分かる値)。</param>
    /// <param name="settings">そのテストに固有の設定上書き(接続文字列はここで指定しない)。</param>
    protected TempDatabaseAppFixture(
        string databaseFileNamePrefix,
        IReadOnlyDictionary<string, string?> settings)
    {
        // 他のテストと衝突しない一時 DB のパスを決める(リポジトリ内に DB を作らない)
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"{databaseFileNamePrefix}-{Guid.NewGuid():N}.db");

        // 実運用設定を汚さないよう、テスト専用の設定でアプリを起動する
        Factory = _baseFactory.WithWebHostBuilder(builder =>
        {
            // シード・パスワードポリシーが緩い Development 環境として起動する
            builder.UseEnvironment("Development");
            // 設定値をテスト用に上書きする
            builder.ConfigureAppConfiguration((_, config) =>
            {
                // 派生クラスが渡した設定を土台にする
                var values = new Dictionary<string, string?>(settings)
                {
                    // 接続文字列だけはこのクラスが決める(派生側が一時 DB の場所を書き写さないため)
                    ["ConnectionStrings:DefaultConnection"] = $"Data Source={_databasePath}",
                };
                // メモリ上の設定ソースを最後に追加して既存設定を上書きする
                config.AddInMemoryCollection(values);
            });
        });
    }

    /// <summary>テストが共有する、起動済みのアプリのファクトリ。</summary>
    public WebApplicationFactory<Program> Factory { get; }

    /// <summary>アプリを停止し、生成した一時 DB のファイルを消す。</summary>
    public void Dispose()
    {
        // 先に派生ファクトリを止めて、SQLite のファイルハンドルを解放させる
        Factory.Dispose();
        // 派生元のファクトリも明示的に止める
        _baseFactory.Dispose();
        // 本体と補助ファイルをまとめて消す(対象の一覧は共通ヘルパーが持つ)
        SqliteTestFiles.Cleanup(_databasePath);
        // 派生クラスがファイナライザを持たないことを明示する(CA1816)
        GC.SuppressFinalize(this);
    }
}
