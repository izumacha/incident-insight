// テスト用のクレーム(ユーザー情報の属性)を組み立てるために使う
using System.Security.Claims;
// テスト共通ヘルパー(UserContextHelper / TestTempData)を使う
using IncidentInsight.Tests.Helpers;
// テスト対象の AccountController を使う
using IncidentInsight.Web.Controllers;
// ApplicationUser(ログインユーザーのモデル)を使う
using IncidentInsight.Web.Models;
// LoginViewModel(ログイン画面の入力モデル)を使う
using IncidentInsight.Web.Models.ViewModels;
// 認証まわりのスキーム型(IAuthenticationSchemeProvider)を参照するために使う
using Microsoft.AspNetCore.Authentication;
// DefaultHttpContext などの HTTP コンテキスト型を使う
using Microsoft.AspNetCore.Http;
// ASP.NET Core Identity の SignInManager / UserManager を使う
using Microsoft.AspNetCore.Identity;
// ViewResult / RedirectResult など MVC の戻り値型を使う
using Microsoft.AspNetCore.Mvc;
// IUrlHelper が使う UrlActionContext / UrlRouteContext を参照するために使う
using Microsoft.AspNetCore.Mvc.Routing;
// テストでは実際にログを出さないので「何もしないロガー」(NullLogger)を使う
using Microsoft.Extensions.Logging.Abstractions;
// IdentityOptions を IOptions でラップするために使う
using Microsoft.Extensions.Options;
// SignInResult は Identity 側と MVC 側で同名の型があるため Identity 側を別名で固定する
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

// テストクラスの名前空間(既存の *ControllerTests と同じ場所)
namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// AccountController のログインフローと、RedirectToLocal による
/// オープンリダイレクト(外部サイトへ勝手に転送される脆弱性)ガードの回帰テスト。
/// 本プロジェクトにはモックライブラリ(Moq 等)が無いため、依存を追加せず
/// SignInManager の仮想メソッドを上書きした自作フェイクで代替する。
/// 実際の Identity ストア(DB)を組み立てるロックアウトカウンタ等の統合的な挙動は
/// 配線が重いためここでは扱わず、コントローラの分岐ロジックのみを検証する。
/// </summary>
public class AccountControllerTests
{
    // --- テスト用フェイク ---

    /// <summary>
    /// IUserStore の最小フェイク。UserManager のコンストラクタが null を拒否するため
    /// 形だけ渡す(テスト中に呼ばれることはない)。
    /// </summary>
    private sealed class FakeUserStore : IUserStore<ApplicationUser>
    {
        // 破棄処理は何もしない(保持リソースが無いため)
        public void Dispose() { }
        // 以下はテストで呼ばれない想定なので、呼ばれたら明示的に失敗させる
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken ct) => throw new NotImplementedException();
        public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken ct) => throw new NotImplementedException();
        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken ct) => throw new NotImplementedException();
        public Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken ct) => throw new NotImplementedException();
        public Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken ct) => throw new NotImplementedException();
    }

    /// <summary>
    /// IUserClaimsPrincipalFactory の最小フェイク。SignInManager のコンストラクタが
    /// null を拒否するため形だけ渡す(テスト中に呼ばれることはない)。
    /// </summary>
    private sealed class FakeClaimsPrincipalFactory : IUserClaimsPrincipalFactory<ApplicationUser>
    {
        // 呼ばれない想定なので、呼ばれたら明示的に失敗させる
        public Task<ClaimsPrincipal> CreateAsync(ApplicationUser user) => throw new NotImplementedException();
    }

    /// <summary>
    /// SignInManager のフェイク。パスワード認証の結果を差し替え可能にし、
    /// 呼び出し内容(回数・サインアウト実行)を記録する。
    /// </summary>
    private sealed class FakeSignInManager : SignInManager<ApplicationUser>
    {
        // PasswordSignInAsync が返す結果(テストごとに設定する)
        public SignInResult ResultToReturn { get; set; } = SignInResult.Failed;
        // PasswordSignInAsync が呼ばれた回数(不要な認証呼び出しの検出用)
        public int PasswordSignInCallCount { get; private set; }
        // SignOutAsync が呼ばれたかどうか(ログアウト処理の実行確認用)
        public bool SignedOut { get; private set; }

        // コンストラクタ: 基底 SignInManager が null を許さない引数だけ最小フェイクで埋める
        public FakeSignInManager()
            : base(
                // UserManager: FakeUserStore 以外の依存はすべて null で足りる(基底で任意扱い)
                new UserManager<ApplicationUser>(new FakeUserStore(), null!, null!, null!, null!, null!, null!, null!, NullLogger<UserManager<ApplicationUser>>.Instance),
                // HTTP コンテキストアクセサ(実物の空実装で十分)
                new HttpContextAccessor(),
                // クレーム生成ファクトリ(形だけのフェイク)
                new FakeClaimsPrincipalFactory(),
                // IdentityOptions は既定値をそのまま使う(基底の Options プロパティと名前が衝突するため完全修飾)
                Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
                // ログは出さない(何もしないロガー)
                NullLogger<SignInManager<ApplicationUser>>.Instance,
                // 認証スキームプロバイダは基底で null 許容のため渡さない
                null!,
                // ユーザー確認(メール確認など)も基底で null 許容のため渡さない
                null!)
        {
        }

        // パスワード認証を実際には行わず、設定済みの結果を返す
        public override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            // 呼び出し回数を 1 増やして記録する
            PasswordSignInCallCount++;
            // テストで指定された認証結果をそのまま返す
            return Task.FromResult(ResultToReturn);
        }

        // クッキー削除などは行わず「サインアウトが要求された」ことだけ記録する
        public override Task SignOutAsync()
        {
            // サインアウト実行フラグを立てる
            SignedOut = true;
            // 非同期処理としては即完了を返す
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// IUrlHelper の最小フェイク。IsLocalUrl だけ本物と同等の判定
    /// (「/」始まりのサイト内パスのみローカル扱い、「//」「/\」「絶対URL」は外部扱い)を実装する。
    /// </summary>
    private sealed class FakeUrlHelper : IUrlHelper
    {
        // コントローラ側から参照される ActionContext(テストでは空で良い)
        public ActionContext ActionContext { get; } = new();

        // 本物の UrlHelper と同じ基準でローカル URL かどうかを判定する
        public bool IsLocalUrl(string? url)
        {
            // 空文字や null はローカル URL ではないので false
            if (string.IsNullOrEmpty(url)) return false;
            // 「/」1 文字だけならサイトのトップなのでローカル扱い
            if (url == "/") return true;
            // 「/」で始まり、2 文字目が「/」や「\」でなければサイト内パスとしてローカル扱い
            //  (「//evil.example」のようなプロトコル相対 URL を外部として弾くための条件)
            if (url[0] == '/' && url[1] != '/' && url[1] != '\\') return true;
            // 「~/」で始まる仮想パスもローカル扱い
            if (url.Length > 1 && url[0] == '~' && url[1] == '/') return true;
            // それ以外(http:// などの絶対 URL)は外部 URL として false
            return false;
        }

        // 以下はテストで使わないため、呼ばれたら明示的に失敗させる
        public string? Action(UrlActionContext actionContext) => throw new NotImplementedException();
        public string? Content(string? contentPath) => throw new NotImplementedException();
        public string? Link(string? routeName, object? values) => throw new NotImplementedException();
        public string? RouteUrl(UrlRouteContext routeContext) => throw new NotImplementedException();
    }

    // --- セットアップ ---

    // 各テストが共有するフェイク SignInManager(認証結果を差し替えて使う)
    private readonly FakeSignInManager _signInManager;
    // テスト対象のコントローラ
    private readonly AccountController _controller;

    // コンストラクタ: テストごとに新しいコントローラとフェイクを組み立てる
    public AccountControllerTests()
    {
        // フェイクの SignInManager を生成する
        _signInManager = new FakeSignInManager();
        // フェイクを注入してテスト対象コントローラを生成する
        _controller = new AccountController(_signInManager);
        // 未ログイン状態の HTTP コンテキストと TempData をコントローラに配線する
        _controller.ControllerContext = new ControllerContext
        {
            // DefaultHttpContext の User は「未認証」の空プリンシパルになる
            HttpContext = new DefaultHttpContext()
        };
        // TempData を使う場合に備えてテスト用の何もしない TempData を差し込む
        _controller.TempData = new TestTempData();
        // Url.IsLocalUrl の判定をテストで制御できるようフェイク IUrlHelper を差し込む
        _controller.Url = new FakeUrlHelper();
    }

    // 有効な入力値のログイン ViewModel を作るヘルパー
    private static LoginViewModel MakeVm() => new()
    {
        // テスト用のメールアドレス
        Email = "user@example.com",
        // テスト用のパスワード
        Password = "Password1!",
        // ログイン保持は使わない
        RememberMe = false
    };

    // --- Login POST: オープンリダイレクトガード(最重要) ---

    [Fact]
    public async Task Login_Post_ExternalReturnUrl_DoesNotRedirectThere_FallsBackToHome()
    {
        // 認証は成功する設定にする
        _signInManager.ResultToReturn = SignInResult.Success;

        // 外部の絶対 URL を returnUrl に指定してログインを実行する
        var result = await _controller.Login(MakeVm(), "https://evil.example/");

        // 外部 URL への生リダイレクト(RedirectResult)になっていないことを確認する
        Assert.IsNotType<RedirectResult>(result);
        // 代わりに安全なフォールバック(Home/Index へのリダイレクト)になることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        // 遷移先アクションが Index であることを確認する
        Assert.Equal("Index", redirect.ActionName);
        // 遷移先コントローラが Home であることを確認する
        Assert.Equal("Home", redirect.ControllerName);
    }

    [Fact]
    public async Task Login_Post_ProtocolRelativeReturnUrl_FallsBackToHome()
    {
        // 認証は成功する設定にする
        _signInManager.ResultToReturn = SignInResult.Success;

        // 「//evil.example」のようなプロトコル相対 URL(外部扱いすべき境界値)を指定する
        var result = await _controller.Login(MakeVm(), "//evil.example");

        // 生リダイレクトではなく Home/Index へのフォールバックになることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        // 遷移先アクションが Index であることを確認する
        Assert.Equal("Index", redirect.ActionName);
        // 遷移先コントローラが Home であることを確認する
        Assert.Equal("Home", redirect.ControllerName);
    }

    [Fact]
    public async Task Login_Post_LocalReturnUrl_RedirectsToIt()
    {
        // 認証は成功する設定にする
        _signInManager.ResultToReturn = SignInResult.Success;

        // サイト内パス(ローカル URL)を returnUrl に指定してログインを実行する
        var result = await _controller.Login(MakeVm(), "/Incidents/Details/1");

        // ローカル URL へのリダイレクトになることを確認する
        var redirect = Assert.IsType<RedirectResult>(result);
        // リダイレクト先が指定したサイト内パスそのものであることを確認する
        Assert.Equal("/Incidents/Details/1", redirect.Url);
    }

    [Fact]
    public async Task Login_Post_NullReturnUrl_RedirectsToHome()
    {
        // 認証は成功する設定にする
        _signInManager.ResultToReturn = SignInResult.Success;

        // returnUrl 未指定(null)でログインを実行する
        var result = await _controller.Login(MakeVm(), returnUrl: null);

        // 既定の遷移先である Home/Index へのリダイレクトになることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        // 遷移先アクションが Index であることを確認する
        Assert.Equal("Index", redirect.ActionName);
        // 遷移先コントローラが Home であることを確認する
        Assert.Equal("Home", redirect.ControllerName);
    }

    // --- Login POST: バリデーション・認証失敗 ---

    [Fact]
    public async Task Login_Post_InvalidModelState_RedisplaysView_WithoutSigningIn()
    {
        // 入力値のバリデーション NG 状態(例: メール未入力)を再現する
        _controller.ModelState.AddModelError(nameof(LoginViewModel.Email), "メールアドレスを入力してください");
        // 送信された入力値を用意する
        var vm = MakeVm();

        // バリデーション NG のままログインを実行する
        var result = await _controller.Login(vm, "/Incidents");

        // リダイレクトせずログイン画面が再表示されることを確認する
        var view = Assert.IsType<ViewResult>(result);
        // 入力値がそのまま画面に戻される(再入力の手間を省く)ことを確認する
        Assert.Same(vm, view.Model);
        // バリデーション NG 時はパスワード認証が一切呼ばれないことを確認する
        Assert.Equal(0, _signInManager.PasswordSignInCallCount);
    }

    [Fact]
    public async Task Login_Post_WrongCredentials_AddsModelError_AndRedisplaysView()
    {
        // 認証失敗(メール or パスワード不一致)の結果を返す設定にする
        _signInManager.ResultToReturn = SignInResult.Failed;
        // 送信された入力値を用意する
        var vm = MakeVm();

        // 誤った資格情報でログインを実行する
        var result = await _controller.Login(vm, "/Incidents");

        // リダイレクトせずログイン画面が再表示されることを確認する
        var view = Assert.IsType<ViewResult>(result);
        // 入力値が画面に戻されることを確認する
        Assert.Same(vm, view.Model);
        // 「正しくありません」系のモデルエラーが追加され ModelState が無効になることを確認する
        Assert.False(_controller.ModelState.IsValid);
        // パスワード認証が 1 回だけ呼ばれたことを確認する
        Assert.Equal(1, _signInManager.PasswordSignInCallCount);
    }

    [Fact]
    public async Task Login_Post_LockedOut_AddsModelError_AndRedisplaysView()
    {
        // 連続失敗によるロックアウトの結果を返す設定にする
        _signInManager.ResultToReturn = SignInResult.LockedOut;
        // 送信された入力値を用意する
        var vm = MakeVm();

        // ロックアウト状態でログインを実行する
        var result = await _controller.Login(vm, null);

        // リダイレクトせずログイン画面が再表示されることを確認する
        var view = Assert.IsType<ViewResult>(result);
        // 入力値が画面に戻されることを確認する
        Assert.Same(vm, view.Model);
        // ロックアウト案内のモデルエラーで ModelState が無効になることを確認する
        Assert.False(_controller.ModelState.IsValid);
    }

    // --- Login GET ---

    [Fact]
    public void Login_Get_Anonymous_ReturnsView_WithReturnUrlInViewData()
    {
        // 未ログイン状態でログイン画面を開く
        var result = _controller.Login("/Incidents");

        // ログイン画面のビューが返ることを確認する
        var view = Assert.IsType<ViewResult>(result);
        // 戻り先 URL が ViewData 経由で画面に渡ることを確認する
        Assert.Equal("/Incidents", _controller.ViewData["ReturnUrl"]);
    }

    [Fact]
    public void Login_Get_AlreadyAuthenticated_RedirectsToHome()
    {
        // ログイン済みユーザー(Admin)をコントローラに配線する
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());

        // ログイン済み状態でログイン画面を開く
        var result = _controller.Login(returnUrl: null);

        // 重複ログインを避けて Home/Index へリダイレクトされることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        // 遷移先アクションが Index であることを確認する
        Assert.Equal("Index", redirect.ActionName);
        // 遷移先コントローラが Home であることを確認する
        Assert.Equal("Home", redirect.ControllerName);
    }

    // --- Logout / AccessDenied ---

    [Fact]
    public async Task Logout_SignsOut_AndRedirectsToLogin()
    {
        // ログアウトを実行する
        var result = await _controller.Logout();

        // サインアウト処理(クッキー破棄相当)が実際に呼ばれたことを確認する
        Assert.True(_signInManager.SignedOut);
        // ログイン画面へのリダイレクトになることを確認する
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        // 遷移先アクションが Login であることを確認する
        Assert.Equal("Login", redirect.ActionName);
    }

    [Fact]
    public void AccessDenied_ReturnsView()
    {
        // アクセス拒否ページを開く
        var result = _controller.AccessDenied();

        // ビューがそのまま返ることを確認する
        Assert.IsType<ViewResult>(result);
    }
}
