// 起動時に出したログを溜めておくために使う
using System.Collections.Concurrent;
// 判定側の規則(警告の文面の正本)を参照するために使う
using IncidentInsight.Web.Models.Validation;
// テスト用のアプリ起動フィクスチャを使う
using IncidentInsight.Tests.Helpers;
// ログのプロバイダを自作して差し込むために使う
using Microsoft.Extensions.Logging;
// テストフレームワーク
using Xunit;

// このテストが属する名前空間(パイプライン周りの検査と同じ場所)
namespace IncidentInsight.Tests.Middleware;

/// <summary>
/// <c>AllowedHosts</c> の設定ミスに対して、<c>Program.cs</c> が<b>実際に警告を出す</b>ことを固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ判定側のテストだけでは足りないのか。</b>
/// <see cref="AllowedHostsPolicy"/> の単体テストが固定しているのは<b>判定</b>だけで、
/// その判定を<b>起動時に呼んでログへ出す配線</b>は 1 行も通らない ——
/// 警告は <c>if (!app.Environment.IsDevelopment())</c> の中にあり、
/// 統合テストのフィクスチャは既定で <c>Development</c> として起動するため。
/// 実測でも、<b>2 本目の警告のブロックを丸ごと削除しても全件緑のまま通り、
/// ログの引数を入れ替えても誰も気づかなかった</b>。
/// 判定を <c>AllowedHostsPolicy</c> へ寄せたのはこの穴を小さくするためだが、
/// 「呼んでいるか」「何を渡しているか」だけは残るので、ここで直接見る。</para>
///
/// <para><b><c>Staging</c> で起動する。</b> <c>!IsDevelopment()</c> を満たす環境のうち、
/// <c>Production</c> は <c>Audit:HashSalt</c> が空だと起動に失敗する（仕様）。
/// <c>Staging</c> ならその必須チェック（<c>IsProduction()</c> 限定）を通らずに
/// まったく同じ警告の分岐へ入れるので、秘密鍵をテストへ持ち込まずに済む。</para>
/// </remarks>
public class AllowedHostsStartupWarningTests
{
    // 1 本目（全許可）の警告を見分ける目印。文面そのものではなく、
    // 一意に決まる書き出しだけを見る（文言の推敲で赤くしないため）
    private const string PermissiveWarningMarker = "AllowedHosts is permissive";

    // 2 本目（一致しえない項目）の警告を見分ける目印（同上）
    private const string DeadEntryWarningMarker = "AllowedHosts contains";

    [Fact]
    public void RealHostnamesOnly_WarnAboutNothing()
    {
        // 実ホスト名だけを並べた、正しい設定
        using var fixture = new WarningCapturingFixture("incident.example.test;www.example.test");

        // 1 本目も 2 本目も出ないこと（正しい設定で鳴ると、運用者は警告を見なくなる）
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));
    }

    [Fact]
    public void WildcardEntry_WarnsWithTheWildcardCause()
    {
        // 実ホスト名の隣にワイルドカードを置いた形（「追加」しようとすると自然に書く）
        using var fixture = new WarningCapturingFixture("*;incident.example.test");

        // 1 本目が出ること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>原因の説明が、その設定に合ったものであること。</b> ここを見ないと、
        // 対応表を作った意味が無い（どの原因でも同じ 1 文を出す退行が素通りする）
        Assert.Contains(
            AllowedHostsPolicy.PermissiveCauseMessage(AllowedHostsPolicy.PermissiveReason.WildcardEntry),
            warning);

        // 設定値そのものが載ること（運用者が「自分の設定だ」と気づけるように）
        Assert.Contains("*;incident.example.test", warning);

        // 一致しえない項目は無いので、2 本目は出ないこと
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));
    }

    [Fact]
    public void EmptyList_WarnsWithTheEmptyListCause()
    {
        // テンプレート展開で両方が未定義だと、区切りだけが残る
        using var fixture = new WarningCapturingFixture(";");

        // 1 本目が出ること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>ワイルドカードの話をしないこと。</b> この値には 3 綴りが 1 つも無いので、
        // 「'*' を消せ」と案内すると存在しないものを探させることになる
        Assert.Contains(
            AllowedHostsPolicy.PermissiveCauseMessage(AllowedHostsPolicy.PermissiveReason.NoEntriesLeft),
            warning);
    }

    [Fact]
    public void WhitespaceAfterASeparator_WarnsOnlyAboutTheDeadEntry()
    {
        // 一覧を書くときに自然に入る形（区切りのうしろの空白）
        const string allowedHosts = "incident.example.test; www.example.test";

        // その設定で起動する
        using var fixture = new WarningCapturingFixture(allowedHosts);

        // <b>1 本目は出ないこと。</b> 絞り込み自体は効いているので、
        // 「警告が出ていないことの確認」という運用手順がそのまま誤った安心になる
        // ——2 本目を足した理由そのものなので、ここを固定しておく
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 2 本目が出ること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));

        // 件数が載ること（値が長いときでも件数だけは読める、という意図を固定する）
        Assert.Contains("1 entry/entries", warning);

        // <b>死んでいる項目が "[ ]" で囲まれて名指しされること。</b>
        // 空白は目で見えないので、囲まないと「なぜ一致しないのか」が伝わらない
        Assert.Contains("[ www.example.test]", warning);

        // その設定に合った直し方（この形は消しても全許可にならないので Safe）
        Assert.Contains(
            AllowedHostsPolicy.DeadEntryFixAdvice(
                AllowedHostsPolicy.DeadEntryDeletionOutcome.Safe),
            warning);
    }

    [Fact]
    public void DeadEntryNextToAWildcard_TellsOperatorsNotToJustDeleteIt()
    {
        // ASPNETCORE_URLS を写して書くと自然に生まれる形＋末尾に空白
        const string allowedHosts = "incident.example.test;0.0.0.0; ";

        // その設定で起動する
        using var fixture = new WarningCapturingFixture(allowedHosts);

        // 2 本とも出ること（原因も対処も違うので、まとめずに別々に出す）
        Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));

        // <b>本命。</b> 消すと残りがワイルドカードだけになるので、
        // 「消してよい」と案内してはいけない（400 は止まるが issue #64 へ移るだけ）
        Assert.Contains(
            AllowedHostsPolicy.DeadEntryFixAdvice(
                AllowedHostsPolicy.DeadEntryDeletionOutcome.WouldAllowEveryHost),
            warning);
    }

    // <b>ポート付きの項目でも 2 本目の警告が出ること（issue #256）。</b>
    // 以前は「一致しえない」の定義が前後の空白だけだったため、ポートを書いた項目は
    // <b>毎リクエスト 400 になるのに警告が 1 本も出なかった</b> ——
    // docs/security.md が案内する「警告が出ていないことの確認」がそのまま誤った安心になる。
    [Fact]
    public void PortInAnEntry_WarnsWithThePortCause()
    {
        // ASPNETCORE_URLS からホスト名を写すと自然に生まれる形
        const string allowedHosts = "incident.example.test;www.example.test:8080";

        // その設定で起動する
        using var fixture = new WarningCapturingFixture(allowedHosts);

        // <b>1 本目は出ないこと。</b> 絞り込み自体は効いているので、
        // この警告だけを見ていると設定ミスに気づけない（2 本目を足した理由そのもの）
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 2 本目が出ること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));

        // ポートの付いた項目が "[ ]" で囲まれて名指しされること
        Assert.Contains("[www.example.test:8080]", warning);

        // <b>本命。</b> その項目に<b>ポートの理由</b>が添えられていること ——
        // 以前は文面が「前後の空白が残っている」と決め打ちだったので、
        // ここを見ないと事実と違う理由を添えたまま緑になる
        Assert.Contains(
            AllowedHostsPolicy.DeadEntryCauseMessage(
                AllowedHostsPolicy.DeadEntryReason.PortSuffix),
            warning);

        // 空白の理由のほうは、この設定には当てはまらないので出ないこと
        Assert.DoesNotContain(
            AllowedHostsPolicy.DeadEntryCauseMessage(
                AllowedHostsPolicy.DeadEntryReason.SurroundingWhitespace),
            warning);
    }

    // <b>警告がログの 1 レコードに収まること。</b> 設定値をそのまま埋め込むと、
    // 行区切りを含む値で<b>1 本の警告がログ上は複数のレコードに見える</b> ——
    // docs/security.md が案内する「この警告が出ていないことを確認する」という運用手順が
    // 偽の継続行で破れ、ログの収集・解析が<b>まさにその設定ミスのときに</b>壊れる（issue #258）。
    //
    // <b>可視化の単体テストだけでは足りない。</b> あちらは
    // AllowedHostsPolicy.DescribeValueForLog を直接呼ぶので、Program.cs が
    // その呼び出しをやめて生の値へ戻しても 1 件も落ちない
    // （警告は if (!IsDevelopment()) の中にあり、この配線はここでしか走らない）。
    //
    // <b>ケースを CR / LF だけに絞ると、issue #258 が塞いだはずの穴が半分残る。</b>
    // ログの読み手が行を割る文字は CR / LF だけではなく、可視化の条件を char.IsControl に
    // していると U+2028 / U+2029 だけが生のまま載っていた（issue #263）。同じ役割の U+0085 は
    // char.IsControl が true なので通っており、<b>1 ケースではこの非対称に気づけない</b>。
    [Theory]
    // CR / LF —— テンプレート展開やコピー & ペーストで自然に生まれる形。
    // 制御文字は正規化に失敗するので、1 本目（全許可）の警告が出る経路に入る
    [InlineData("incident.example.test;0.0\r\n.0.0")]
    // NEL（U+0085）—— char.IsControl が true の行区切り。下の 2 つとの対照として置く。
    // <b>ワイルドカードを先に置いて 1 本目の警告を確実に出す</b> ——この経路が
    // 「正規化に失敗するか」に依存していると、可視化とは関係のない理由でケースが死ぬ
    [InlineData("*;a\u0085b")]
    // <b>本命。</b> U+2028 / U+2029 は char.IsControl が false なので、
    // 条件を「制御文字か」にしていると生のままログへ載る（issue #263）
    [InlineData("*;a\u2028b")]
    [InlineData("*;a\u2029b")]
    public void LineSeparatorsInTheValue_DoNotSplitTheWarningAcrossLogRecords(string allowedHosts)
    {
        // その設定で起動する
        using var fixture = new WarningCapturingFixture(allowedHosts);

        // 1 本目が出ること（出ていないと、以降の検査が「無いものを見て緑」になる）
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>本命。</b> 警告の文面に行区切りが 1 つも残っていないこと＝レコードが分断されない
        Assert.DoesNotContain(warning, ch => LogRecordSplittingCharacters.Contains(ch));

        // 値そのものは（可視化された形で）載ること ——運用者が自分の設定だと気づけるように。
        // 期待値は判定側の関数から取る（文面の綴りをテストへ書き写さないため）
        Assert.Contains(AllowedHostsPolicy.DescribeValueForLog(allowedHosts), warning);
    }

    // ログの読み手が「ここで行が変わった」と解釈しうる文字。
    //
    // <b>可視化の条件（AllowedHostsPolicy 側）を呼ばずに、手で並べてある。</b>
    // あちらを呼ぶと「可視化される文字は可視化されている」という<b>自分自身との照合</b>に
    // なり、条件から U+2028 を落とす変異を 1 件も検出しなくなる。出典は
    // CSharpCommentScanner.SplitLines の docstring が挙げている区切り
    // （解析器や JSON / JS ベースのログビューアが行を分ける文字）。
    private static readonly char[] LogRecordSplittingCharacters =
        ['\r', '\n', '\u0085', '\u2028', '\u2029'];

    // <b>設定値と同じ理由で、環境名も生のままでは載せない（レビュー指摘）。</b>
    // ASPNETCORE_ENVIRONMENT は AllowedHosts とまったく同じ「運用者が設定する外部の文字列」で、
    // 同じテンプレート展開やコピー & ペーストで改行が紛れうる。片方だけ可視化しても、
    // もう片方が 1 本の警告を複数レコードへ割る（issue #258 が塞いだはずの穴が残る）。
    [Fact]
    public void ControlCharactersInTheEnvironmentName_DoNotSplitTheWarningAcrossLogRecords()
    {
        // 改行を含む環境名で、1 本目の警告が出る設定（未設定＝全許可）のまま起動する
        const string environmentName = "Staging\r\nINJECTED";

        // その環境名で起動する
        using var fixture = new WarningCapturingFixture("*", environmentName);

        // 1 本目が出ること（出ていないと、以降の検査が「無いものを見て緑」になる）
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>本命。</b> 警告の文面に改行が 1 つも残っていないこと
        Assert.DoesNotContain('\r', warning);
        Assert.DoesNotContain('\n', warning);

        // 環境名は（可視化された形で）載ること ——どの環境の話かが読めなくならないように
        Assert.Contains(AllowedHostsPolicy.DescribeValueForLog(environmentName), warning);
    }

    /// <summary>
    /// <c>Staging</c> としてアプリを起動し、起動中に出た警告を溜めておくフィクスチャ。
    /// </summary>
    /// <remarks>
    /// <b>プロバイダは起動前に登録する。</b> 起動時のログはアプリの組み立て中に出るので、
    /// 起動後に <c>Factory.Services</c> を覗いても間に合わない。
    /// </remarks>
    private sealed class WarningCapturingFixture : TempDatabaseAppFixture
    {
        // このインスタンスが起動したときに溜まった分だけを見せる
        private readonly string[] _warnings;

        /// <summary>指定した許可リストで <c>Staging</c> として起動する。</summary>
        /// <param name="allowedHosts">検証したい <c>AllowedHosts</c> の値。</param>
        public WarningCapturingFixture(string allowedHosts, string environmentName = "Staging")
            // <b>溜め込み先はインスタンスごとに作り、ここから配る。</b>
            // 基底のコンストラクタ引数はインスタンスのフィールドを参照できないので、
            // 以前は static なキューを共有していた ——ところがホストは Dispose() まで
            // 生きたまま同じキューへ書き続けるので、<b>停止時に出た Warning
            // （EF Core / Identity / ホステッドサービス）が次のフィクスチャの
            // 読み出しに混ざる</b>。いまは各アサーションが目印で絞っているので無害だが、
            // Assert.Empty(...) のような検査を足した瞬間に<b>非決定的に落ち、
            // しかも無関係なテストを名指しする</b>。private なコンストラクタへ
            // 1 度渡せば、共有そのものが無くなる
            : this(allowedHosts, environmentName, new ConcurrentQueue<string>())
        {
        }

        /// <summary>溜め込み先を受け取って起動する（共有しないための経路）。</summary>
        /// <param name="allowedHosts">検証したい <c>AllowedHosts</c> の値。</param>
        /// <param name="environmentName">起動する環境名（既定は <c>Staging</c>）。</param>
        /// <param name="captured">このインスタンス専用の溜め込み先。</param>
        private WarningCapturingFixture(
            string allowedHosts, string environmentName, ConcurrentQueue<string> captured)
            : base(
                "ii-hostwarn",
                new Dictionary<string, string?> { ["AllowedHosts"] = allowedHosts },
                // 警告の分岐（!IsDevelopment()）へ入るために既定は Staging。
                // 環境名そのものを検証したいときだけ、呼び出し側が差し替える
                environmentName,
                // 起動前に、溜め込むだけのプロバイダを登録する
                logging => logging.AddProvider(new CapturingLoggerProvider(captured)))
        {
            // <b>アプリの起動をここで強制する。</b> WebApplicationFactory は遅延生成で、
            // Services / CreateClient に触れるまでパイプラインを組み立てない ——
            // 触れずに溜め込み先を読むと、まだ何も出ていないので必ず空になる（実測）
            _ = Factory.Services;

            // 起動が済んだ時点で溜まっている分を切り出して持つ
            // （読み出しは 1 度きりにして、あとから増えた分に依存しない）
            _warnings = [.. captured];
        }

        /// <summary>起動中に出た警告（新しい順ではなく、出た順）。</summary>
        public IReadOnlyList<string> Warnings => _warnings;
    }

    /// <summary>
    /// <c>Warning</c> 以上のメッセージを、整形済みの 1 本の文字列として溜めるプロバイダ。
    /// </summary>
    /// <param name="sink">溜め込み先。</param>
    private sealed class CapturingLoggerProvider(ConcurrentQueue<string> sink) : ILoggerProvider
    {
        /// <summary>カテゴリごとのロガーを作る（どのカテゴリでも同じ溜め込み先を使う）。</summary>
        /// <param name="categoryName">ログのカテゴリ名（ここでは使わない）。</param>
        /// <returns>溜め込むだけのロガー。</returns>
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(sink);

        /// <summary>解放するものは無い。</summary>
        public void Dispose()
        {
            // 溜め込み先は呼び出し側が持っているので、ここでは何もしない
        }
    }

    /// <summary>
    /// <c>Warning</c> 以上を整形して溜めるだけのロガー。
    /// </summary>
    /// <param name="sink">溜め込み先。</param>
    private sealed class CapturingLogger(ConcurrentQueue<string> sink) : ILogger
    {
        /// <summary>スコープは使わない。</summary>
        /// <typeparam name="TState">スコープの状態の型。</typeparam>
        /// <param name="state">スコープの状態（使わない）。</param>
        /// <returns>何もしない使い捨ての破棄可能オブジェクト。</returns>
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        /// <summary>Warning 以上だけを受け取る。</summary>
        /// <param name="logLevel">そのログの深刻度。</param>
        /// <returns>受け取るなら <c>true</c>。</returns>
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        /// <summary>1 件のログを整形して溜める。</summary>
        /// <typeparam name="TState">ログの状態の型。</typeparam>
        /// <param name="logLevel">そのログの深刻度。</param>
        /// <param name="eventId">イベント ID（使わない）。</param>
        /// <param name="state">ログの状態。</param>
        /// <param name="exception">例外（使わない）。</param>
        /// <param name="formatter">状態と例外を 1 本の文字列にする関数。</param>
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            // Warning 未満は見ない（起動時の情報ログで埋もれさせない）
            if (!IsEnabled(logLevel)) return;

            // <b>プレースホルダを埋めた最終的な文面を溜める。</b> 構造化ログの
            // 引数を個別に見ると、テンプレートと引数の並びが入れ替わった退行
            // （運用者が読む文面が壊れる形）を拾えない
            sink.Enqueue(formatter(state, exception));
        }
    }
}
