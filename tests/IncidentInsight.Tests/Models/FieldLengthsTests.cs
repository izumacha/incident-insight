// エンティティ(Incident / CauseAnalysis / PreventiveMeasure / CauseCategory)を使うために取り込む
using IncidentInsight.Web.Models;
// 文字数上限の唯一の真実の源(FieldLengths)を検証対象として取り込む
using IncidentInsight.Web.Models.Validation;
// 入力用 ViewModel(IncidentCreateEditViewModel など)を使うために取り込む
using IncidentInsight.Web.Models.ViewModels;
// 監査対象エンティティをインターセプタの宣言から導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// [MaxLength] 属性を参照するために取り込む
using System.ComponentModel.DataAnnotations;
// リフレクション(型情報から属性を調べる仕組み)を使うために取り込む
using System.Reflection;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 文字数上限を一元管理する FieldLengths の不変条件テスト。
//
// 過去の回帰: 500 / 100 という上限がエンティティ・ViewModel・生文字列を検証するヘルパーの
// 3 層に裸の数値で散在していた。層ごとに別々の数値だったため、片方だけ変更すると
//   - ViewModel だけ緩める → 検証は通るのに保存時に列長超過(SQL Server / PostgreSQL では
//     未捕捉の DbUpdateException = HTTP 500)、
//   - エンティティだけ緩める → 新しい上限まで入力できない、
// という層またぎの不整合が起きうる(CLAUDE.md §6 定数の一元管理)。
// このテストは「業務データの [MaxLength] は必ず FieldLengths のいずれかの値である」ことを
// 機械的に固定し、裸の数値が再び紛れ込むのを CI で検知する。
public class FieldLengthsTests
{
    // 検査対象の型一覧(監査対象の集約 + 原因分類マスタ + 入力用 ViewModel)。
    // AuditLog は業務入力ではなく監査証跡スキーマ固有の列長(256/64/16)なので対象外。
    //
    // 監査対象の集約は名前を書き並べず AuditSaveChangesInterceptor.AuditedEntities から導出する。
    // 写しを持つと、監査対象を足したときに PHI 分類・長さ上限の検査だけが自動で追随し、
    // 「その [MaxLength] が FieldLengths の定数か」を見るこの検査だけが取り残される
    // ——新しい集約に裸の [MaxLength(200)] を書いても CI が緑のまま通る
    public static TheoryData<Type> LengthGovernedTypes
    {
        get
        {
            // 監査対象の集約(唯一の真実の源から導出)を土台にする
            var types = AuditedEntityModel.ResolveAuditedClrTypes().ToList();

            // 監査対象ではないが同じ上限規約に従う型を足す
            types.Add(typeof(CauseCategory));
            types.Add(typeof(IncidentCreateEditViewModel));
            types.Add(typeof(CauseAnalysisFormViewModel));
            types.Add(typeof(MeasureFormViewModel));
            types.Add(typeof(ReviewViewModel));

            // xUnit へ渡す形に詰め替える
            var data = new TheoryData<Type>();
            foreach (var type in types)
            {
                // 1 ケース分として追加する
                data.Add(type);
            }
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(LengthGovernedTypes))]
    public void EveryMaxLength_UsesAFieldLengthsConstant(Type type)
    {
        // FieldLengths が定める許容値の集合(ここに無い値は裸のマジックナンバーとみなす)
        var allowed = new[] { FieldLengths.FreeText, FieldLengths.ShortText };

        // 対象型の公開プロパティのうち [MaxLength] が付いているものを列挙する
        var offenders = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => new { Property = p, Attribute = p.GetCustomAttribute<MaxLengthAttribute>(inherit: false) })
            .Where(x => x.Attribute != null)
            // 許容値のいずれとも一致しない上限を違反として拾う
            .Where(x => !allowed.Contains(x.Attribute!.Length))
            .Select(x => $"{type.Name}.{x.Property.Name} = {x.Attribute!.Length}")
            .ToList();

        // 違反ゼロであること(あればどのプロパティが裸の数値かをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "[MaxLength] に FieldLengths 以外の裸の数値が使われています " +
            $"(FieldLengths.FreeText={FieldLengths.FreeText} / FieldLengths.ShortText={FieldLengths.ShortText}): "
            + string.Join(", ", offenders));
    }

    [Theory]
    [MemberData(nameof(LengthGovernedTypes))]
    public void ViewModelMaxLength_UsesJapaneseSharedErrorMessage(Type type)
    {
        // 入力用 ViewModel だけが画面へエラーメッセージを出す。エンティティ側の [MaxLength] は
        // EF Core の列長定義にしか使われず、メッセージが利用者に見えないため検査対象外にする
        if (!type.Name.EndsWith("ViewModel", StringComparison.Ordinal)) return;

        // [MaxLength] が付いた公開プロパティのうち、共通の日本語書式を使っていないものを拾う。
        // 既定のメッセージは英語("The field ... maximum length of '500'.")のため、
        // 指定漏れがあると日本語 UI に英文の検証エラーが混ざる(CLAUDE.md §1)
        var offenders = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => new { Property = p, Attribute = p.GetCustomAttribute<MaxLengthAttribute>(inherit: false) })
            .Where(x => x.Attribute != null)
            // ErrorMessage が共通書式と一致しないものを違反とする
            .Where(x => x.Attribute!.ErrorMessage != FieldLengths.MaxLengthMessage)
            .Select(x => $"{type.Name}.{x.Property.Name}")
            .ToList();

        // 違反ゼロであること
        Assert.True(offenders.Count == 0,
            "ViewModel の [MaxLength] に共通の日本語エラーメッセージ書式 " +
            "(FieldLengths.MaxLengthMessage) が指定されていません: " + string.Join(", ", offenders));
    }

    [Fact]
    public void MaxLengthMessage_FormatsDisplayNameAndLimit()
    {
        // 実際に MaxLengthAttribute が組み立てるメッセージを確認する。
        // {0} に表示名、{1} に上限文字数が入ることを固定し、書式を書き換えたときに
        // プレースホルダの取り違え(数字が表示されない等)を検知する
        var attribute = new MaxLengthAttribute(FieldLengths.FreeText)
        {
            ErrorMessage = FieldLengths.MaxLengthMessage
        };

        // 表示名「状況・経緯」に対するエラーメッセージを生成する
        var message = attribute.FormatErrorMessage("状況・経緯");

        // 項目名と上限文字数の両方が含まれた日本語メッセージになっていること
        Assert.Equal($"状況・経緯は{FieldLengths.FreeText}文字以内で入力してください。", message);
    }
}
