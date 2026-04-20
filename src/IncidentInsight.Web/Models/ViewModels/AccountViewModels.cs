// 属性(Required / EmailAddress など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;

// この ViewModel 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// ログイン画面の入力を受け取るモデル
public class LoginViewModel
{
    // メールアドレス。必須入力かつ書式チェック
    [Required(ErrorMessage = "メールアドレスを入力してください")]
    [EmailAddress(ErrorMessage = "有効なメールアドレスを入力してください")]
    [Display(Name = "メールアドレス")]
    public string Email { get; set; } = "";

    // パスワード。必須入力で、入力欄は伏字表示(password type)になる
    [Required(ErrorMessage = "パスワードを入力してください")]
    [DataType(DataType.Password)]
    [Display(Name = "パスワード")]
    public string Password { get; set; } = "";

    // 「ログイン状態を保持する」チェックボックス(永続クッキーの有無)
    [Display(Name = "ログイン状態を保持する")]
    public bool RememberMe { get; set; }
}
