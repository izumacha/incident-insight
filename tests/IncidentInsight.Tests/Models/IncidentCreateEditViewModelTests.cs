// ViewModel(IncidentCreateEditViewModel)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;
// IncidentTypeKind / IncidentSeverity enum を使うために取り込む
using IncidentInsight.Web.Models.Enums;
// [EnumDataType] 等の DataAnnotations バリデーションを実行するために取り込む
using System.ComponentModel.DataAnnotations;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// IncidentCreateEditViewModel.IncidentType / Severity の未定義値検証(EnumDataType)。
// ASP.NET のモデルバインドは未定義の整数(例: 99)もそのまま (IncidentTypeKind)99 として
// 束縛してしまうため、EnumDataType 属性がここで唯一の防波堤になる
// (UpdateStatus の Enum.IsDefined fail-closed 方針と同じ考え方)。
public class IncidentCreateEditViewModelTests
{
    // 必須項目を満たした状態で有効なフォームを作るヘルパー
    private static IncidentCreateEditViewModel CreateValidForm() => new()
    {
        OccurredAt = DateTime.Today,
        Department = "内科病棟",
        IncidentType = IncidentTypeKind.Medication,
        Severity = IncidentSeverity.Level2,
        Description = "テスト状況",
        ReporterName = "テスト太郎"
    };

    [Fact]
    public void IncidentType_Defined_PassesValidation()
    {
        // 定義済みのインシデント種別でフォームを作る
        var vm = CreateValidForm();
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 定義済み値なのでバリデーションが通るはず
        Assert.True(isValid);
        // IncidentType に関する検証エラーが含まれていないことを確認する
        Assert.DoesNotContain(results, r => r.MemberNames.Contains(nameof(IncidentCreateEditViewModel.IncidentType)));
    }

    [Fact]
    public void IncidentType_Undefined_FailsValidation()
    {
        // 未定義の整数値(フォーム改ざんを想定)をインシデント種別に割り当てる
        var vm = CreateValidForm();
        vm.IncidentType = (IncidentTypeKind)9999;
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 未定義値なのでバリデーションが失敗するはず
        Assert.False(isValid);
        // 失敗した項目名一覧を取り出す
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        // IncidentType が失敗リストに含まれることを確認する
        Assert.Contains(nameof(IncidentCreateEditViewModel.IncidentType), failedFields);
    }

    [Fact]
    public void Severity_Defined_PassesValidation()
    {
        // 定義済みの重症度でフォームを作る
        var vm = CreateValidForm();
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 定義済み値なのでバリデーションが通るはず
        Assert.True(isValid);
        // Severity に関する検証エラーが含まれていないことを確認する
        Assert.DoesNotContain(results, r => r.MemberNames.Contains(nameof(IncidentCreateEditViewModel.Severity)));
    }

    [Fact]
    public void Severity_Undefined_FailsValidation()
    {
        // 未定義の整数値(フォーム改ざんを想定)を重症度に割り当てる
        var vm = CreateValidForm();
        vm.Severity = (IncidentSeverity)9999;
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(vm);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(vm, ctx, results, true);

        // 未定義値なのでバリデーションが失敗するはず
        Assert.False(isValid);
        // 失敗した項目名一覧を取り出す
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        // Severity が失敗リストに含まれることを確認する
        Assert.Contains(nameof(IncidentCreateEditViewModel.Severity), failedFields);
    }
}
