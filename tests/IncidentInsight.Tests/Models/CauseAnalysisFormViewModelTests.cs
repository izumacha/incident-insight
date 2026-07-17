// ViewModel(CauseAnalysisFormViewModel)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;
// [MaxLength] 等の DataAnnotations バリデーションを実行するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// CauseAnalysisFormViewModel.AdditionalNotes の文字数上限検証(EF Core は保存時に
// DataAnnotations を自動検証しないため、CauseAnalysesController.AddCauseAnalysis /
// EditCauseAnalysis の ModelState.IsValid チェックでここが唯一の防波堤になる。
// 他の自由記述欄(Why1-5/RootCauseSummary 等)と同じ500文字上限)。
public class CauseAnalysisFormViewModelTests
{
    // 必須項目を満たした状態で有効なフォームを作るヘルパー
    private static CauseAnalysisFormViewModel CreateValidForm() => new()
    {
        IncidentId = 1,
        CauseCategoryId = 1,
        Why1 = "なぜ1"
    };

    [Fact]
    public void AdditionalNotes_WithinLimit_PassesValidation()
    {
        // 500文字ちょうどの補足メモでフォームを作る
        var vm = CreateValidForm();
        vm.AdditionalNotes = new string('あ', 500);
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 上限ちょうどなのでバリデーションが通るはず
        Assert.True(isValid);
        // AdditionalNotes に関する検証エラーが含まれていないことを確認する
        Assert.DoesNotContain(results, r => r.MemberNames.Contains(nameof(CauseAnalysisFormViewModel.AdditionalNotes)));
    }

    [Fact]
    public void AdditionalNotes_ExceedsLimit_FailsValidation()
    {
        // 501文字(上限超過、フォーム改ざんや制限のないクライアントからの入力を想定)の補足メモ
        var vm = CreateValidForm();
        vm.AdditionalNotes = new string('あ', 501);
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 上限超過なのでバリデーションが失敗するはず
        Assert.False(isValid);
        // 失敗した項目名一覧を取り出す
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        // AdditionalNotes が失敗リストに含まれることを確認する
        Assert.Contains(nameof(CauseAnalysisFormViewModel.AdditionalNotes), failedFields);
    }

    [Fact]
    public void CauseCategoryId_Zero_FailsValidation()
    {
        // 原因分類が未選択(=0。select の未選択やフィールド未送信のバインド既定値)のフォーム。
        // 非 null の int に対する [Required] は常に成功してしまう(int は null になり得ない)ため、
        // [Range(1, ...)] が 0 を弾くことを固定する。ここで弾かないと FK=0 のまま INSERT され
        // 未捕捉の DbUpdateException(HTTP 500)になる(回帰防止)。
        var vm = CreateValidForm();
        vm.CauseCategoryId = 0;
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 未選択なのでバリデーションが失敗するはず
        Assert.False(isValid);
        // CauseCategoryId が失敗リストに含まれることを確認する
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        Assert.Contains(nameof(CauseAnalysisFormViewModel.CauseCategoryId), failedFields);
    }

    [Fact]
    public void CauseCategoryId_Positive_PassesValidation()
    {
        // 正の ID が選択されていれば CauseCategoryId の検証は通る
        // (実在チェックはコントローラ側の CauseCategoryExistsAsync が担当する)
        var vm = CreateValidForm();
        vm.CauseCategoryId = 1;
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションを実行する
        var isValid = Validator.TryValidateObject(vm, new ValidationContext(vm), results, true);

        // 検証が成功することを確認する
        Assert.True(isValid);
    }
}
