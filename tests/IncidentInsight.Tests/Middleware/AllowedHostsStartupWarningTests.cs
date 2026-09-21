// 起動時に出したログを溜めておくために使う
using System.Collections.Concurrent;
// 判定側の規則(警告の文面の正本)を参照するために使う
using IncidentInsight.Web.Models.Validation;
// テスト用のアプリ起動フィクスチャを使う
using IncidentInsight.Tests.Helpers;
// ログのプロバイダを自作して差し込むために使う
using Microsoft.Extensions.Logging;
// 稼働中に差し替えられる設定ソースを自作するために使う
using Microsoft.Extensions.Configuration;
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

    // 検査そのものが失敗したときに残る記録の目印（起動時・再読み込みで共通。同上）
    private const string CheckFailureMarker = "Failed to check AllowedHosts";

    // 出力先を落とすテスト用プロバイダが投げる例外の文面。
    // <b>定数にしてあるのは、最後の手段が「元の失敗」まで運んでいるかを見るため</b> ——
    // テストと実装の 2 か所へ綴りを書き写すと、片方だけ直したときに照合が空振りする
    private const string FailingSinkExceptionMessage = "The log sink is unavailable (test double).";

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
    // <b>ケースを CR / LF だけに絞ると、値の側と同じ非対称がここに残る（レビュー指摘）。</b>
    // 実測でも、環境名の可視化だけを issue #263 以前の規則（制御文字だけを見る形）へ戻すと
    // 1160 件すべて緑のまま通った ——"Staging\r\nINJECTED" はどちらの規則でも同じ綴りへ
    // 可視化されるので、CR / LF の 1 ケースでは新旧の規則を区別できない。
    [Theory]
    // CR / LF —— テンプレート展開やコピー & ペーストで自然に生まれる形
    [InlineData("Staging\r\nINJECTED")]
    // NEL（U+0085）—— char.IsControl が true の行区切り。下の 2 つとの対照として置く
    [InlineData("Staging\u0085INJECTED")]
    // <b>本命。</b> U+2028 / U+2029 は char.IsControl が false なので、
    // 可視化の条件を「制御文字か」に戻すと生のままログへ載る（issue #263）
    [InlineData("Staging\u2028INJECTED")]
    [InlineData("Staging\u2029INJECTED")]
    public void LineSeparatorsInTheEnvironmentName_DoNotSplitTheWarningAcrossLogRecords(
        string environmentName)
    {
        // その環境名で、1 本目の警告が出る設定（全許可）のまま起動する
        using var fixture = new WarningCapturingFixture("*", environmentName);

        // 1 本目が出ること（出ていないと、以降の検査が「無いものを見て緑」になる）
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>本命。</b> 警告の文面に行区切りが 1 つも残っていないこと。
        // 一覧は値の側の検査と共有する（同じ「行を割る文字」を 2 か所へ書き写さない）
        Assert.DoesNotContain(warning, ch => LogRecordSplittingCharacters.Contains(ch));

        // 環境名は（可視化された形で）載ること ——どの環境の話かが読めなくならないように
        Assert.Contains(AllowedHostsPolicy.DescribeValueForLog(environmentName), warning);
    }

    // <b>稼働中に設定を緩めたら、警告を出し直すこと（issue #264）。</b>
    //
    // appsettings.json は既定で reloadOnChange: true で、HostFilteringOptions は
    // ConfigurationChangeTokenSource 経由で再束縛される ——つまり運用中に
    // AllowedHosts を "*" や "…;0.0.0.0" へ書き換えると、<b>ミドルウェアは即座に
    // 全ホスト許可へ切り替わる</b>。起動時に 1 度しか評価していないと、そのとき
    // 新しい警告は 1 本も出ないので、docs/security.md が案内する
    // 「配備後は 2 本とも出ていないことを確認する」手順が<b>そのまま誤った安心</b>になる。
    // "*;incident.example.com" を取りこぼしていた頃と同じ形の穴が、時間軸の方向に残っていた。
    //
    // <b>Staging で実際に起動して見る。</b> 警告は if (!IsDevelopment()) の中にあり、
    // フィクスチャの既定（Development）では配線が 1 行も走らないので、
    // 単体テストだけだと OnChange の購読を消しても全件緑のまま通る。
    [Fact]
    public void LooseningTheValueAtRuntime_EmitsThePermissiveWarningAgain()
    {
        // 正しく絞られた値で起動する（起動時には 1 本も出ない状態から始める）
        using var fixture = new WarningCapturingFixture("incident.example.test");

        // 起動直後は 1 本目が出ていないこと
        // （出ていると、以降の「増えたか」の検査が起動時の 1 本を見て緑になる）
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // <b>稼働中に全許可へ緩める。</b> ASPNETCORE_URLS を写すと自然に生まれる綴り
        fixture.ReloadAllowedHosts("incident.example.test;0.0.0.0");

        // <b>本命。</b> 再読み込みの後に 1 本目が出ていること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 緩めた<b>後</b>の値が載っていること ——起動時の値のまま出すと、
        // 運用者は「どの設定について言われているのか」を取り違える
        Assert.Contains(
            AllowedHostsPolicy.DescribeValueForLog("incident.example.test;0.0.0.0"),
            warning);
    }

    // 2 本目（一致しえない項目）も同じ引き金で出し直すこと。
    //
    // <b>片方だけを配線した状態にしない。</b> どちらの穴も運用者からは
    // 「警告が出ていない」という同じ見た目になるので、1 本目だけ追随させると
    // 「並べたのに一致しない」形が再読み込み後は黙ったままになる。
    [Fact]
    public void AddingANeverMatchingEntryAtRuntime_EmitsTheDeadEntryWarningAgain()
    {
        // 一致しえない項目が 1 つも無い値で起動する
        using var fixture = new WarningCapturingFixture("incident.example.test");

        // 起動直後は 2 本目が出ていないこと
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));

        // <b>稼働中に、区切りのうしろへ空白の入った一覧へ書き換える。</b>
        // 一覧を書くときに自然に入る形で、実測では 2 件目だけが静かに 400 になる
        fixture.ReloadAllowedHosts("incident.example.test; www.example.test");

        // <b>本命。</b> 再読み込みの後に 2 本目が出ていること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(DeadEntryWarningMarker));

        // 一致しえない項目が "[ ]" で囲まれて名指しされていること
        Assert.Contains("[ www.example.test]", warning);
    }

    // <b>再読み込みの検査が失敗しても、例外を呼び出し元へ通さないこと（レビュー指摘）。</b>
    //
    // 変更トークンの発火は CancellationTokenSource.Cancel() 経由で、集めた例外を
    // 呼び出し元へ投げ直す。本番でのその呼び出し元は設定ファイルの監視スレッドなので、
    // ここから例外が出ると<b>設定ファイルに触れただけでプロセスが落ちる</b>。
    // 加えて、同じトークンに連なる他の購読（HostFilteringOptions 自身の再束縛を含む）も
    // そこで打ち切られる。診断のための警告がアプリを止めるのは本末転倒で、
    // CLAUDE.md §9 の「例外時はクラッシュではなく機能を縮退して継続する」に反する。
    //
    // <b>この検査が無いと、握りの配線を消しても全件緑のまま通る</b>（実測）——
    // どのケースもコールバックを失敗させていなかったため。
    //
    // <b>失敗する場所を 2 通り見る。</b> 警告そのものの書き込みが落ちる場合と、
    // <b>それを記録しようとした LogError まで落ちる</b>場合（ログの出力先ごと
    // 落ちている状況）で、後者は最後の手段（別の出力先へ吐いて必ず戻る）を通る。
    [Theory]
    // 1 本目の警告の書き込みだけが落ちる
    [InlineData(false)]
    // 警告も、その失敗を記録する LogError も落ちる（出力先ごと落ちている状況）
    [InlineData(true)]
    public void AFailingLogSink_DoesNotPropagateOutOfTheReloadCallback(bool failEveryWrite)
    {
        // 絞られた値で起動し、起動時には何も書き込ませない
        // （起動時に落とすとアプリの組み立て自体が失敗し、見たい経路へ到達しない）
        using var fixture = new WarningCapturingFixture(
            "incident.example.test",
            failLoggingWhen: message =>
                // 出力先ごと落ちている状況では、起動後のどの書き込みも失敗させる。
                // そうでなければ、1 本目の警告だけを失敗させる
                failEveryWrite
                    ? message.Contains(PermissiveWarningMarker) || message.Contains(CheckFailureMarker)
                    : message.Contains(PermissiveWarningMarker));

        // <b>本命。</b> 稼働中に全許可へ緩める ——このとき 1 本目の警告の書き込みが失敗する。
        // 例外がここまで戻ってくると（＝本番ならプロセスが落ちる形）、この行で落ちる
        var reload = Record.Exception(() => fixture.ReloadAllowedHosts("*"));

        // コールバックの外へ例外が出ていないこと
        Assert.Null(reload);

        // <b>握り潰してはいない</b>こと ——出力先が生きているほうのケースでは、
        // 失敗の事実が文脈付きで記録されている（§6「エラーを握り潰さない」）。
        // 出力先ごと落ちているケースでは記録も残せないので、そこは求めない
        if (!failEveryWrite)
        {
            // 再検査に失敗したことが記録されていること
            Assert.Contains(fixture.Warnings, w => w.Contains(CheckFailureMarker));
        }
    }

    // <b>起動時の検査が失敗しても、起動そのものは止めないこと（レビュー指摘）。</b>
    //
    // 呼び出し口は起動時と再読み込みの 2 つあり、以前は再読み込み側にだけ
    // 例外の手当てがあった。ログの出力先が落ちている状態（読み取り専用や満杯の
    // ボリュームを指したファイル出力、起動時にまだ届かないネットワーク出力）では、
    // <b>診断のための警告を書けないというだけでアプリが起動できなくなる</b> ——
    // CLAUDE.md §9 の「例外時はクラッシュではなく機能を縮退して継続する」に反する。
    //
    // <b>この非対称は検出網が無いと見えない。</b> 既存の検査はどれも再読み込み側でしか
    // 出力先を落としていなかった（起動時に落とすとフィクスチャの構築自体が失敗する）。
    [Fact]
    public void AFailingLogSinkAtStartup_DoesNotPreventTheAppFromStarting()
    {
        // 全許可のまま起動する ——起動時に 1 本目の警告を書こうとして失敗する状況
        var startup = Record.Exception(() => new WarningCapturingFixture(
            "*",
            failLoggingWhen: message =>
                // 1 本目の警告の書き込みだけを落とす（その失敗の記録は残せる状態にする）
                message.Contains(PermissiveWarningMarker)));

        // <b>本命。</b> 起動が例外で止まっていないこと
        Assert.Null(startup);
    }

    // <b>起動時の失敗も、握り潰さず記録すること。</b>
    // 上の検査は「起動できること」しか見ないので、例外を黙って捨てる実装でも通る。
    [Fact]
    public void AFailingLogSinkAtStartup_StillRecordsTheFailure()
    {
        // 上と同じ状況で起動し、溜まった記録を読む
        using var fixture = new WarningCapturingFixture(
            "*",
            failLoggingWhen: message => message.Contains(PermissiveWarningMarker));

        // 検査に失敗したことが、文脈付きで残っていること
        Assert.Contains(fixture.Warnings, w => w.Contains(CheckFailureMarker));
    }

    // <b>出力先ごと落ちていても、失敗の事実は別の出力先へ必ず残すこと（レビュー指摘）。</b>
    //
    // 上の Theory は「例外が外へ出ないこと」しか見ていないので、最後の手段を
    // 空の catch へ潰しても両ケースとも通ってしまう（実測）——そのとき
    // AllowedHosts が黙って緩み、しかも再検査が失敗した事実がどこにも残らない。
    // 運用者は docs/security.md の「2 本とも出ていないことの確認」をきれいなログで
    // 通してしまう。CLAUDE.md §6 の「空の catch を作らない」に当たる形でもある。
    [Fact]
    public void WhenEvenTheErrorLogFails_TheFailureStillReachesStandardError()
    {
        // 絞られた値で起動し、起動後の書き込みはすべて落ちるようにする
        using var fixture = new WarningCapturingFixture(
            "incident.example.test",
            failLoggingWhen: message =>
                // 警告も、その失敗を記録する LogError も落とす（出力先ごと落ちている状況）
                message.Contains(PermissiveWarningMarker) || message.Contains(CheckFailureMarker));

        // 標準エラーを横取りして、最後の手段が何を書くかを読めるようにする
        var originalError = Console.Error;
        // 横取り用の受け皿
        var captured = new StringWriter();

        // 横取りは必ず元へ戻す（他のテストの出力先を巻き込まない）
        try
        {
            // 標準エラーを受け皿へ差し替える
            Console.SetError(captured);
            // 稼働中に全許可へ緩める ——警告もその失敗の記録も書き込みに失敗する
            fixture.ReloadAllowedHosts("*");
        }
        finally
        {
            // 元の標準エラーへ戻す
            Console.SetError(originalError);
        }

        // 受け皿に書かれた内容を読む
        var fallback = captured.ToString();

        // <b>本命 1。</b> 「再検査が失敗した」事実そのものが残っていること
        Assert.Contains(CheckFailureMarker, fallback);

        // <b>本命 2。</b> 元の失敗（なぜ再検査が失敗したか）も一緒に残っていること ——
        // 出力先が落ちた理由だけを書くと、肝心の事実がどこにも残らない
        Assert.Contains(FailingSinkExceptionMessage, fallback);
    }

    // <b>評価済みとして覚えるのは、出し終えた後であること（レビュー指摘）。</b>
    //
    // 先に覚えると、出力の途中で例外が出た値がそのまま「評価済み」として残り、
    // <b>同じ値での再読み込みでは重複抑止に当たって黙る</b> ——その値に対する警告が
    // プロセスの生涯にわたって失われる。後で覚えれば、失敗した値は次の再読み込みで
    // もう一度評価され、最悪でも同じ警告が 2 度出るだけで済む（過剰に出す＝安全側）。
    //
    // <b>並び順を入れ替える変異は、この検査が無いと全件緑のまま通る</b>（実測）。
    [Fact]
    public void AWarningLostToAFailingSink_IsRetriedOnTheNextReload()
    {
        // 1 本目の警告の書き込みを「最初の 1 回だけ」失敗させるための数え手
        var permissiveWrites = 0;

        // 絞られた値で起動する（起動時には 1 本目が出ないので、数え手は動かない）
        using var fixture = new WarningCapturingFixture(
            "incident.example.test",
            failLoggingWhen: message =>
                // 1 本目の警告の、最初の書き込みだけを落とす
                message.Contains(PermissiveWarningMarker) && Interlocked.Increment(ref permissiveWrites) == 1);

        // 1 回目: 全許可へ緩める ——警告の書き込みが失敗するので、何も残らない
        fixture.ReloadAllowedHosts("*");

        // この時点では 1 本目が残っていないこと（前提の確認。残っていると次の検査が意味を失う）
        Assert.DoesNotContain(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 2 回目: <b>同じ値のまま</b>もう一度再読み込みを起こす。
        // 失敗した値を「評価済み」にしていなければ、ここで評価し直される
        fixture.ReloadAllowedHosts("*");

        // <b>本命。</b> 失われたはずの警告が、次の再読み込みで出ていること
        Assert.Contains(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));
    }

    // <b>未設定のまま起動したら 1 本目を出すこと（レビュー指摘）。</b>
    //
    // Reporter は「前回と同じ値なら黙る」ので、<b>初回だけは必ず評価する</b>という旗を
    // 持っている。その旗を落とすと、未設定（値が null）のときだけ
    // 「前回の値（既定の null）と同じ」に当たって<b>1 本も出なくなる</b> ——
    // そのとき HostFiltering は ["*"] へ落ちて全許可（issue #64）なので、
    // いちばん警告が要る場合だけ黙ることになる。
    //
    // <b>以前はこの不変条件に検出網が無かった。</b> 既存のケースはどれも文字列を渡して
    // いたため、旗を外す変異が 1157 件すべて緑のまま通った（実測）。
    [Fact]
    public void UnsetValue_StillEmitsThePermissiveWarning()
    {
        // AllowedHosts が解決できない（未設定の）状態で起動する
        using var fixture = new WarningCapturingFixture(null);

        // 1 本目が出ていること
        var warning = Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 「未設定」として名乗られていること ——空文字を設定した場合と区別が付くように
        // （期待値は判定側の定数から取る。文面の綴りをテストへ書き写さないため）
        Assert.Contains(AllowedHostsPolicy.UnsetValueForLog, warning);
    }

    // <b>同じ値のまま再読み込みが起きても、警告を増やさないこと。</b>
    //
    // 再読み込みの通知は AllowedHosts が変わっていなくても届く（設定ファイルの
    // どこを直しても鳴り、ファイル監視は 1 度の書き込みで複数回鳴ることがある）。
    // 毎回出すと<b>本当に緩めた瞬間の 1 本</b>が同じ文面の山に埋もれ、
    // 「いつ緩んだか」を追えなくなる。
    [Fact]
    public void ReloadingWithoutChangingTheValue_DoesNotRepeatTheWarning()
    {
        // 全許可のまま起動する（起動時に 1 本目が出る状態）
        using var fixture = new WarningCapturingFixture("*");

        // 起動時に 1 本出ていること（ここが 0 本だと、以降の検査が何も見ていない）
        Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));

        // 値を変えずに再読み込みだけを起こす
        fixture.ReloadAllowedHosts("*");

        // <b>本命。</b> 1 本のままで、同じ警告が積み増されていないこと
        Assert.Single(fixture.Warnings, w => w.Contains(PermissiveWarningMarker));
    }

    /// <summary>
    /// <c>Staging</c> としてアプリを起動し、出た警告を溜めておくフィクスチャ。
    /// </summary>
    /// <remarks>
    /// <para><b>プロバイダは起動前に登録する。</b> 起動時のログはアプリの組み立て中に出るので、
    /// 起動後に <c>Factory.Services</c> を覗いても間に合わない。</para>
    ///
    /// <para><b>起動時だけを見るテストと、再読み込みまで見るテストで 1 つにしてある。</b>
    /// 以前は 2 クラスに分かれていたが、非自明な仕掛け（溜め込み先をインスタンスごとに
    /// 持たせる private コンストラクタ・<c>Staging</c> での起動・プロバイダの登録・
    /// 遅延生成を打ち切る <c>_ = Factory.Services;</c>）を<b>そっくり書き写していた</b> ——
    /// どれかを直す人は 2 か所を直す必要があり、説明のコメントが付いていない側の写しを
    /// 触った人は「なぜこの形なのか」を知りようがない（§6 DRY。
    /// <see cref="TempDatabaseAppFixture"/> の docstring 自体が、同じ重複を一度やった記録）。</para>
    /// </remarks>
    private sealed class WarningCapturingFixture : TempDatabaseAppFixture
    {
        // 稼働中に値を差し替え、再読み込みを起こすための設定ソース
        private readonly ReloadableSettingsSource _settings;

        // 起動後も増え続ける溜め込み先
        private readonly ConcurrentQueue<string> _captured;

        /// <summary>指定した許可リストで起動する。</summary>
        /// <param name="allowedHosts">
        /// 起動時の <c>AllowedHosts</c> の値。<b><c>null</c> は「未設定」</b>を表す ——
        /// リポジトリの <c>appsettings.json</c> は既定の <c>"*"</c> を持つので、
        /// キーごと省くだけでは未設定を再現できない（そちらが読まれる）。
        /// 値を <c>null</c> にした項目を最後に積むことで、設定の解決結果を未設定にする。
        /// </param>
        /// <param name="environmentName">
        /// 起動する環境名（既定は <c>Staging</c>）。警告の分岐（<c>!IsDevelopment()</c>）へ
        /// 入るために既定は <c>Staging</c> で、環境名そのものを検証したいときだけ差し替える。
        /// </param>
        /// <param name="failLoggingWhen">
        /// ログの出力先が落ちている状況を作るための判定（既定は何も落とさない）。
        /// <b>本番の経路を再現するために要る</b> ——再読み込みのコールバックから例外が出ると、
        /// 変更トークンの発火（<c>CancellationTokenSource.Cancel()</c>）が呼び出し元へ
        /// 投げ直すので、<b>設定ファイルに触れただけでプロセスが落ちる</b>。
        /// </param>
        public WarningCapturingFixture(
            string? allowedHosts,
            string environmentName = "Staging",
            Func<string, bool>? failLoggingWhen = null)
            // <b>溜め込み先と設定ソースはインスタンスごとに作り、ここから配る。</b>
            // 基底のコンストラクタ引数はインスタンスのフィールドを参照できないので、
            // 以前は static なキューを共有していた ——ところがホストは Dispose() まで
            // 生きたまま同じキューへ書き続けるので、<b>停止時に出た Warning
            // （EF Core / Identity / ホステッドサービス）が次のフィクスチャの
            // 読み出しに混ざる</b>。いまは各アサーションが目印で絞っているので無害だが、
            // Assert.Empty(...) のような検査を足した瞬間に<b>非決定的に落ち、
            // しかも無関係なテストを名指しする</b>。private なコンストラクタへ
            // 1 度渡せば、共有そのものが無くなる
            : this(
                new ReloadableSettingsSource(allowedHosts),
                new ConcurrentQueue<string>(),
                environmentName,
                failLoggingWhen)
        {
        }

        /// <summary>設定ソースと溜め込み先を受け取って起動する（共有しないための経路）。</summary>
        /// <param name="settings">稼働中に差し替えられる設定ソース。</param>
        /// <param name="captured">このインスタンス専用の溜め込み先。</param>
        /// <param name="environmentName">起動する環境名。</param>
        /// <param name="failLoggingWhen">ログの出力先を落とす判定（<c>null</c> なら落とさない）。</param>
        private WarningCapturingFixture(
            ReloadableSettingsSource settings,
            ConcurrentQueue<string> captured,
            string environmentName,
            Func<string, bool>? failLoggingWhen)
            : base(
                "ii-hostwarn",
                // 起動時の値は差し替え可能なソース側が持つので、ここでは何も固定しない
                new Dictionary<string, string?>(),
                environmentName,
                // 起動前に、溜め込むだけのプロバイダを登録する
                logging => logging.AddProvider(new CapturingLoggerProvider(captured, failLoggingWhen)),
                // 差し替え用のソースを基底の設定より後ろへ積む
                config => config.Add(settings))
        {
            // 受け取ったものを、差し替えと読み出しのために持っておく
            _settings = settings;
            // 溜め込み先はそのまま持つ（起動後に増えた分も見たいので切り出さない）
            _captured = captured;

            // <b>アプリの起動をここで強制する。</b> WebApplicationFactory は遅延生成で、
            // Services / CreateClient に触れるまでパイプラインを組み立てない ——
            // 触れずに溜め込み先を読むと、まだ何も出ていないので必ず空になる（実測）
            _ = Factory.Services;
        }

        /// <summary>起動時と、その後の再読み込みで出た警告（出た順）。</summary>
        public IReadOnlyList<string> Warnings => [.. _captured];

        /// <summary>
        /// 稼働中の設定を差し替え、設定の再読み込みを起こす。
        /// </summary>
        /// <remarks>
        /// <b>ファイルを書き換えて監視の発火を待つ形にはしない。</b> それだと
        /// 監視の遅延ぶんだけ待つことになり、待ち時間の長短で結果が変わる
        /// （CI で時々落ちる検査は、いずれ無効化される）。設定プロバイダに
        /// 直接「変わった」と言わせれば、<b>呼び出しから戻った時点で購読側は走り終えている</b>。
        /// </remarks>
        /// <param name="allowedHosts">差し替え後の <c>AllowedHosts</c> の値。</param>
        public void ReloadAllowedHosts(string? allowedHosts) => _settings.Replace(allowedHosts);
    }

    /// <summary>
    /// <c>AllowedHosts</c> だけを持ち、稼働中に差し替えられる設定ソース。
    /// </summary>
    /// <param name="initialValue">起動時の値（<c>null</c> は「キーはあるが値が無い」＝未設定を表す）。</param>
    private sealed class ReloadableSettingsSource(string? initialValue) : IConfigurationSource
    {
        // 実体のプロバイダ（差し替えと通知はこちらが行う）
        private readonly ReloadableProvider _provider = new(initialValue);

        /// <summary>設定の組み立て時に、同じプロバイダを返す（差し替え先を 1 つに保つ）。</summary>
        /// <param name="builder">組み立て中の設定ビルダー（ここでは使わない）。</param>
        /// <returns>このソースのプロバイダ。</returns>
        public IConfigurationProvider Build(IConfigurationBuilder builder) => _provider;

        /// <summary>値を差し替え、設定の再読み込みを通知する。</summary>
        /// <param name="allowedHosts">差し替え後の値。</param>
        public void Replace(string? allowedHosts) => _provider.Replace(allowedHosts);

        /// <summary>1 つのキーだけを持ち、差し替えのたびに再読み込みを通知するプロバイダ。</summary>
        /// <param name="initialValue">起動時の値（<c>null</c> なら未設定）。</param>
        private sealed class ReloadableProvider(string? initialValue) : ConfigurationProvider
        {
            /// <summary>設定の読み込み（起動時の値を 1 つ置くだけ）。</summary>
            public override void Load() =>
                // 起動時はこの 1 キーだけを持つ
                Data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["AllowedHosts"] = initialValue,
                };

            /// <summary>値を差し替え、購読側へ「変わった」と伝える。</summary>
            /// <param name="allowedHosts">差し替え後の値（<c>null</c> なら未設定）。</param>
            public void Replace(string? allowedHosts)
            {
                // 保持している値を書き換える
                Data["AllowedHosts"] = allowedHosts;
                // 変更トークンを発火させる（HostFilteringOptions の再束縛はこれが引き金）
                OnReload();
            }
        }
    }

    /// <summary>
    /// <c>Warning</c> 以上のメッセージを、整形済みの 1 本の文字列として溜めるプロバイダ。
    /// </summary>
    /// <param name="sink">溜め込み先。</param>
    /// <param name="failWhen">
    /// 出力先が落ちている状況を作るための判定（<c>null</c> なら落とさない）。
    /// 整形済みの本文を受け取り、<c>true</c> を返したものは書き込みの代わりに例外を投げる。
    /// </param>
    private sealed class CapturingLoggerProvider(
        ConcurrentQueue<string> sink, Func<string, bool>? failWhen = null) : ILoggerProvider
    {
        /// <summary>カテゴリごとのロガーを作る（どのカテゴリでも同じ溜め込み先を使う）。</summary>
        /// <param name="categoryName">ログのカテゴリ名（ここでは使わない）。</param>
        /// <returns>溜め込むだけのロガー。</returns>
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(sink, failWhen);

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
    private sealed class CapturingLogger(ConcurrentQueue<string> sink, Func<string, bool>? failWhen) : ILogger
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

            // <b>プレースホルダを埋めた最終的な文面を作る。</b> 構造化ログの
            // 引数を個別に見ると、テンプレートと引数の並びが入れ替わった退行
            // （運用者が読む文面が壊れる形）を拾えない
            var message = formatter(state, exception);

            // 出力先が落ちている状況を作るテストのために、指定された本文だけ書き込みを失敗させる
            if (failWhen is not null && failWhen(message))
            {
                // 実際の出力先が落ちたときと同じく、書き込みの呼び出しから例外を投げる
                throw new InvalidOperationException(FailingSinkExceptionMessage);
            }

            // 溜め込む
            sink.Enqueue(message);
        }
    }
}
