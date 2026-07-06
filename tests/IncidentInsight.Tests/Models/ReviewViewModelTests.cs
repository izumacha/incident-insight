// ViewModel(ReviewViewModel)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;
// [MaxLength] 等の DataAnnotations バリデーションを実行するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// ReviewViewModel.EffectivenessNote の文字数上限検証(EF Core は保存時に DataAnnotations を
// 自動検証しないため、PreventiveMeasuresController.Review の ModelState.IsValid チェックで
// ここが唯一の防波堤になる。他の自由記述欄(Description/AnalysisNote 等)と同じ500文字上限)。
public class ReviewViewModelTests
{
    // 必須項目を満たした状態で有効なフォームを作るヘルパー
    private static ReviewViewModel CreateValidForm() => new()
    {
        Id = 1,
        EffectivenessRating = 3,
        RecurrenceObserved = false
    };

    [Fact]
    public void EffectivenessNote_WithinLimit_PassesValidation()
    {
        // 500文字ちょうどのコメントでフォームを作る
        var vm = CreateValidForm();
        vm.EffectivenessNote = new string('あ', 500);
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 上限ちょうどなのでバリデーションが通るはず
        Assert.True(isValid);
        // EffectivenessNote に関する検証エラーが含まれていないことを確認する
        Assert.DoesNotContain(results, r => r.MemberNames.Contains(nameof(ReviewViewModel.EffectivenessNote)));
    }

    [Fact]
    public void EffectivenessNote_ExceedsLimit_FailsValidation()
    {
        // 501文字(上限超過、フォーム改ざんや制限のないクライアントからの入力を想定)のコメント
        var vm = CreateValidForm();
        vm.EffectivenessNote = new string('あ', 501);
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
        // EffectivenessNote が失敗リストに含まれることを確認する
        Assert.Contains(nameof(ReviewViewModel.EffectivenessNote), failedFields);
    }
}
