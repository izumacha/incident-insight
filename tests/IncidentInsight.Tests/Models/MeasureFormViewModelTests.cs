// ViewModel(MeasureFormViewModel)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;
// [Range] 等の DataAnnotations バリデーションを実行するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// MeasureFormViewModel.Priority の範囲検証(EF Core は保存時に DataAnnotations を自動検証しないため、
// AddMeasure / PreventiveMeasuresController.Create / Edit の入力段階でここが唯一の防波堤になる)
public class MeasureFormViewModelTests
{
    // Priority に必須項目を満たした状態で有効なフォームを作るヘルパー
    private static MeasureFormViewModel CreateValidForm(int priority) => new()
    {
        IncidentId = 1,
        Description = "対策内容",
        ResponsiblePerson = "担当者",
        ResponsibleDepartment = "内科病棟",
        DueDate = DateTime.Today.AddDays(30),
        Priority = priority
    };

    [Theory]
    // ドメインモデル PreventiveMeasure.Priority と同じ許容範囲(1=高〜3=低)を検証する
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void Priority_WithinRange_PassesValidation(int priority)
    {
        // 範囲内の優先度でフォームを作る
        var vm = CreateValidForm(priority);
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 範囲内なのでバリデーションが通るはず
        Assert.True(isValid);
        // Priority に関する検証エラーが含まれていないことを確認する
        Assert.DoesNotContain(results, r => r.MemberNames.Contains(nameof(MeasureFormViewModel.Priority)));
    }

    [Theory]
    // 範囲外(0 や 99 など)は不正値としてすり抜けを防ぐべき
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(99)]
    [InlineData(-1)]
    public void Priority_OutOfRange_FailsValidation(int priority)
    {
        // 範囲外の優先度でフォームを作る
        var vm = CreateValidForm(priority);
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 範囲外なのでバリデーションが失敗するはず
        Assert.False(isValid);
        // 失敗した項目名一覧を取り出す
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        // Priority が失敗リストに含まれることを確認する
        Assert.Contains(nameof(MeasureFormViewModel.Priority), failedFields);
    }
}
