// テスト対象の LoginRateLimitOptions を使う
using IncidentInsight.Web.Models.RateLimiting;

// テストクラスの名前空間(既存の Models 配下テストと同じ場所)
namespace IncidentInsight.Tests.Models;

/// <summary>
/// ログイン試行レート制限設定の既定値を固定する回帰テスト。
/// 設定(RateLimit:Login)が未指定の環境でも、既定値によって制限が
/// 「有効な正の値」で必ず働くこと(fail-safe)を担保する。
/// </summary>
public class LoginRateLimitOptionsTests
{
    [Fact]
    public void Defaults_ArePositive_AndMatchNamedConstants()
    {
        // 設定未指定を想定して既定コンストラクタで生成する
        var options = new LoginRateLimitOptions();

        // 既定の許可回数が名前付き定数と一致することを確認する
        Assert.Equal(LoginRateLimitOptions.DefaultPermitLimit, options.PermitLimit);
        // 既定のウィンドウ長が名前付き定数と一致することを確認する
        Assert.Equal(LoginRateLimitOptions.DefaultWindowSeconds, options.WindowSeconds);
        // 既定値が正の値(= 制限が実際に機能する値)であることを確認する
        Assert.True(options.PermitLimit > 0);
        // ウィンドウ長も正の値であることを確認する
        Assert.True(options.WindowSeconds > 0);
    }

    [Fact]
    public void PolicyName_IsStable()
    {
        // ポリシー名は Program.cs の登録と [EnableRateLimiting] の両方から参照される
        // 唯一の定数。改名すると片側だけ変え忘れた場合に制限が無効化されるため、
        // 文字列そのものを回帰テストで固定する
        Assert.Equal("LoginRateLimit", LoginRateLimitOptions.PolicyName);
    }
}
