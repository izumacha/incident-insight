// WebApplicationFactory(実 HTTP パイプラインでの統合テスト)を使う
using Microsoft.AspNetCore.Mvc.Testing;
// テスト用の環境名指定に使う
using Microsoft.AspNetCore.Hosting;
// テスト用の設定上書きに使う
using Microsoft.Extensions.Configuration;
// 起動時のログを受け取るためのプロバイダ登録に使う
using Microsoft.Extensions.Logging;

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
    /// <param name="environmentName">
    /// 起動する環境名。既定は <c>Development</c>(シード・パスワードポリシーが緩い)。
    /// <b>起動時の警告を見たいテストだけが <c>Staging</c> を渡す</b> ——
    /// <c>Program.cs</c> の警告は <c>if (!IsDevelopment())</c> の中にあるため、
    /// 既定のままではその配線が 1 行も走らない(実測で、警告のブロックを丸ごと消しても
    /// 全件緑のまま通った)。<c>Production</c> ではなく <c>Staging</c> を使うのは、
    /// <c>Audit:HashSalt</c> の必須チェックが <c>IsProduction()</c> 限定で、
    /// 秘密鍵を持ち込まずに同じ分岐を通せるため。
    /// </param>
    /// <param name="configureLogging">
    /// ログの出力先を足したいテスト向けの差し込み口(既定は何もしない)。
    /// <b>起動時の警告はアプリの組み立て中に出る</b>ので、後から
    /// <c>Factory.Services</c> を覗いても間に合わない ——受け取るには
    /// 起動前にプロバイダを登録しておく必要がある。
    /// </param>
    protected TempDatabaseAppFixture(
        string databaseFileNamePrefix,
        IReadOnlyDictionary<string, string?> settings,
        string environmentName = "Development",
        Action<ILoggingBuilder>? configureLogging = null)
    {
        // 他のテストと衝突しない一時 DB のパスを決める(リポジトリ内に DB を作らない)
        _databasePath = Path.Combine(
            Path.GetTempPath(),
            $"{databaseFileNamePrefix}-{Guid.NewGuid():N}.db");

        // 実運用設定を汚さないよう、テスト専用の設定でアプリを起動する
        Factory = _baseFactory.WithWebHostBuilder(builder =>
        {
            // 指定された環境として起動する(既定はシード・パスワードポリシーが緩い Development)
            builder.UseEnvironment(environmentName);
            // ログの出力先を足したいテストがあれば、起動前に登録しておく
            if (configureLogging is not null)
            {
                // 渡された設定をそのままロギングの組み立てへ流す
                builder.ConfigureLogging(configureLogging);
            }
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

    /// <summary>
    /// リダイレクトを追わない素の HTTP クライアントを作る。
    /// </summary>
    /// <remarks>
    /// 自動追跡を切るのは、302 を追った先の応答ヘッダを見てしまうと
    /// 「どの応答を検証しているか」が分からなくなるため。
    /// <b>ここに置くのは、同じ組み立てが 3 箇所目になったから</b>(§6「2〜3 箇所目で共通化」)。
    /// クライアントの既定(ヘッダー・タイムアウト等)を足すときに、一部の呼び出し側にだけ
    /// 適用される状態を作らない。
    /// </remarks>
    /// <returns>組み立てた HttpClient。</returns>
    public HttpClient CreateNonRedirectingClient() =>
        // 共有しているファクトリから、302 等を自動で追跡しないクライアントを作る
        Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            // 302 等を自動で追跡しない
            AllowAutoRedirect = false,
        });

    /// <summary>アプリを停止し、生成した一時 DB のファイルを消す。</summary>
    /// <remarks>
    /// <b>後始末は必ず finally で行う。</b> 素直に 4 手順を並べると、ホストの停止が
    /// 例外を投げた時点(ホステッドサービスや DbContext の破棄が失敗する・SQLite の
    /// ファイルがまだ開いている等)で残りが実行されず、<b>このクラスが存在する理由である
    /// 一時ファイルの削除がまるごと飛ぶ</b>。停止で落ちたときこそファイルが残るので、
    /// 順序ではなく到達を保証する。
    /// </remarks>
    public void Dispose()
    {
        // 後始末に必ず到達させる(停止が失敗しても削除は行う)
        try
        {
            // 先に派生ファクトリを止めて、SQLite のファイルハンドルを解放させる。
            // ここが投げても、派生元の停止と削除は下の finally で必ず行われる
            try
            {
                // 派生ファクトリ(テスト用設定を適用したほう)を止める
                Factory.Dispose();
            }
            finally
            {
                // 派生元のファクトリも明示的に止める
                _baseFactory.Dispose();
            }
        }
        finally
        {
            // 本体と補助ファイルをまとめて消す(対象の一覧は共通ヘルパーが持つ)。
            //
            // <b>ここで投げさせない。</b> SQLite は接続をプールするので、停止直後は
            // まだファイルが開いていることがあり、プラットフォームによっては削除が
            // IOException になる。この finally は「必ず後始末へ到達する」ために置いたのに、
            // その 1 手順が投げると (a) 本来の停止時の例外を置き換えて原因が読めなくなり、
            // (b) GC.SuppressFinalize にも到達しない。消せなかったファイルは
            // プロセス終了後に OS の一時領域の掃除へ委ねる ——後始末の失敗で
            // 検証結果を赤くすると、本物の不具合と見分けが付かなくなる
            // <b>先に接続プールを解放する</b>。Microsoft.Data.Sqlite は接続をプールするので、
            // ホストを止めただけではファイルハンドルが残る。Linux は開いたままでも
            // unlink できてしまうため CI では気付けないが、Windows では削除が
            // IOException になり、下の catch が黙って飲み込む ——
            // つまり「このクラスが防ぐはずの溜まり続ける状態」が、
            // 検査がすべて緑のまま特定の環境でだけ起き続ける。
            //
            // <b>削除とは別の try に分ける。</b> 以前は同じ try に並べていたため、
            // プールの解放が IOException / UnauthorizedAccessException 以外
            // (プールの状態が壊れているときの InvalidOperationException 等)を投げると
            // <b>削除そのものが走らなかった</b> ——このクラスが存在する理由(一時ファイルを
            // 溜めない)が、いちばん解放に失敗している場面で黙って失われる。
            // 同じ理由で catch は種類を絞らない: ここで拾い損ねた例外は
            // 下の後始末ごと飛ばしてしまい、Factory.Dispose() の本当のエラーも置き換える
            try
            {
                // 接続プールを解放して、ファイルハンドルを手放す
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            }
            catch (Exception)
            {
                // 解放できなくても削除は試みる(掴まれたままなら下の catch が受ける)
            }

            // 本体と補助ファイルをまとめて消す
            try
            {
                // 生成した一時 DB と補助ファイルを消す
                SqliteTestFiles.Cleanup(_databasePath);
            }
            catch (IOException)
            {
                // 別プロセス・別ハンドルが掴んでいて消せなかった場合(握り潰す理由は上のとおり)
            }
            catch (UnauthorizedAccessException)
            {
                // 権限が無くて消せなかった場合も同じ扱いにする
            }

            // 派生クラスがファイナライザを持たないことを明示する(CA1816)
            GC.SuppressFinalize(this);
        }
    }
}
