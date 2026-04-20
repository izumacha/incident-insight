// 自プロジェクトのモデル(ApplicationUser)を使う
using IncidentInsight.Web.Models;
// ログイン画面の ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// 認可属性(AllowAnonymous)を使う
using Microsoft.AspNetCore.Authorization;
// Identity の SignInManager / UserManager を使う
using Microsoft.AspNetCore.Identity;
// MVC のコントローラ基底などを使う
using Microsoft.AspNetCore.Mvc;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// ログイン・ログアウト・アクセス拒否ページを司るコントローラ
public class AccountController : Controller
{
    // サインイン操作用のマネージャー(パスワード検証・クッキー発行など)
    private readonly SignInManager<ApplicationUser> _signInManager;
    // ユーザー情報操作用のマネージャー(参照だけで未使用だが DI 注入は残す)
    private readonly UserManager<ApplicationUser> _userManager;

    // コンストラクタ: DI で Identity の依存を受け取る
    public AccountController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
    }

    // GET /Account/Login
    // ログイン画面の表示(未ログイン時のみ)
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        // 既にログイン済みなら重複ログインを避けてトップへリダイレクト
        if (User.Identity?.IsAuthenticated == true)
            return RedirectToAction("Index", "Home");

        // ログイン成功後に戻したい URL を ViewData に積んで画面へ渡す
        ViewData["ReturnUrl"] = returnUrl;
        // ログイン画面のビューを返す
        return View();
    }

    // POST /Account/Login
    // フォーム送信を受け取ってサインインを実行する
    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel vm, string? returnUrl = null)
    {
        // エラー画面にも戻り先 URL を保持
        ViewData["ReturnUrl"] = returnUrl;
        // バリデーション NG なら入力値を残してログイン画面を再描画
        if (!ModelState.IsValid) return View(vm);

        // パスワード認証を実施。失敗時はロックアウトカウンタを進める
        var result = await _signInManager.PasswordSignInAsync(
            vm.Email, vm.Password, vm.RememberMe, lockoutOnFailure: true);

        // 成功したら事前に指定された戻り先 (なければホーム) へリダイレクト
        if (result.Succeeded)
            return RedirectToLocal(returnUrl);

        // 連続失敗でロックアウトされた場合の案内
        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, "アカウントがロックされています。しばらくしてから再試行してください。");
            return View(vm);
        }

        // 認証失敗(メール or パスワード不一致)
        ModelState.AddModelError(string.Empty, "メールアドレスまたはパスワードが正しくありません。");
        return View(vm);
    }

    // POST /Account/Logout
    // サインアウト後にログイン画面へ戻る
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        // クッキー削除などのサインアウト処理
        await _signInManager.SignOutAsync();
        // ログイン画面へリダイレクト
        return RedirectToAction("Login");
    }

    // GET /Account/AccessDenied
    // 権限不足時に表示されるページ(匿名アクセスも許可)
    [AllowAnonymous]
    public IActionResult AccessDenied() => View();

    // 外部サイトへのオープンリダイレクトを防ぎながら、ローカルURLにのみ戻すヘルパー
    private IActionResult RedirectToLocal(string? returnUrl)
    {
        // 内部 URL の場合だけそこへ戻す(外部 URL は無視)
        if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            return Redirect(returnUrl);
        // それ以外は安全側でトップページへ
        return RedirectToAction("Index", "Home");
    }
}
