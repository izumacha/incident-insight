// エンティティ(Incident / CauseAnalysis / PreventiveMeasure)を使うために取り込む
using IncidentInsight.Web.Models;
// [Sensitive] 属性(PHI マスキング指示)の定義を使うために取り込む
using IncidentInsight.Web.Models.Auditing;
// 文字数上限の唯一の真実の源(FieldLengths)を期待値として使うために取り込む
using IncidentInsight.Web.Models.Validation;
// 監査対象エンティティをインターセプタの宣言から導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// [MaxLength] 等の DataAnnotations 属性を参照するために取り込む
using System.ComponentModel.DataAnnotations;
// リフレクション(型情報からプロパティや属性を調べる仕組み)を使うために取り込む
using System.Reflection;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 監査対象エンティティの自由記述カラムに対する長さ上限の不変条件テスト。
// EF Core は保存時に DataAnnotations を自動検証しないため、ViewModel 側の検証だけに頼ると
// 将来 ViewModel を経由しない書き込み経路(API 追加等)が生えた瞬間に無制限の自由記述
// (PHI 混入リスクのある列)がそのまま永続化されてしまう。
// この回帰テストは「[Sensitive] が付いた string プロパティには必ず [MaxLength] も付いている」
// という多層防御の不変条件を機械的に担保する(付け漏れを CI で検知する)。
public class FreeTextMaxLengthAttributeTests
{
    // 検査対象のエンティティ型一覧。型を書き並べず、監査インターセプタの宣言
    // (AuditSaveChangesInterceptor.AuditedEntities = 唯一の真実の源)から導出する。
    // ここで独自の一覧を持つと、監査対象を足したときに実装だけが増えて検査が追随せず、
    // 新しいエンティティの自由記述列が上限なしのまま素通りする
    public static TheoryData<Type> AuditedEntityTypes
    {
        get
        {
            // xUnit の [MemberData] へ渡す形に詰め替えるための入れ物
            var data = new TheoryData<Type>();
            // インターセプタの宣言から導出した CLR 型を 1 つずつ積む
            foreach (var entityType in AuditedEntityModel.ResolveAuditedClrTypes())
            {
                // 1 ケース分として追加する
                data.Add(entityType);
            }
            // 組み上がったケース一覧を返す
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void SensitiveStringProperties_MustHaveMaxLength(Type entityType)
    {
        // 対象エンティティの公開プロパティのうち、[Sensitive] 付きの string 型だけを抽出する
        var sensitiveStrings = entityType
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(string)
                        && p.GetCustomAttribute<SensitiveAttribute>(inherit: false) != null)
            .ToList();

        // 前提確認: 各エンティティに検査対象(自由記述/個人名カラム)が最低 1 つは存在するはず
        Assert.NotEmpty(sensitiveStrings);

        // [Sensitive] 付きなのに [MaxLength] が無いプロパティを探す(あれば付け漏れ)
        var missing = sensitiveStrings
            .Where(p => p.GetCustomAttribute<MaxLengthAttribute>(inherit: false) == null)
            .Select(p => $"{entityType.Name}.{p.Name}")
            .ToList();

        // 付け漏れが 1 件も無いことを確認する(失敗時はどのプロパティかをメッセージで示す)
        Assert.True(missing.Count == 0,
            $"[Sensitive] 付き string プロパティに [MaxLength] がありません: {string.Join(", ", missing)}");
    }

    [Theory]
    // 自由記述 3 プロパティが、入力経路(ViewModel)と同じ FieldLengths.FreeText 上限であることを個別確認する
    [InlineData(typeof(Incident), nameof(Incident.Description), FieldLengths.FreeText)]
    [InlineData(typeof(Incident), nameof(Incident.ImmediateActions), FieldLengths.FreeText)]
    [InlineData(typeof(CauseAnalysis), nameof(CauseAnalysis.AdditionalNotes), FieldLengths.FreeText)]
    public void FreeTextColumns_HaveExpectedMaxLength(Type entityType, string propertyName, int expected)
    {
        // 対象プロパティをリフレクションで取得する
        var property = entityType.GetProperty(propertyName);
        // プロパティ自体が存在することを確認する(改名時にテストが追従漏れしないように)
        Assert.NotNull(property);
        // [MaxLength] 属性を取り出す
        var attr = property!.GetCustomAttribute<MaxLengthAttribute>(inherit: false);
        // 属性が付いていることを確認する
        Assert.NotNull(attr);
        // 上限値が ViewModel 側の検証(FieldLengths.FreeText)と一致していることを確認する
        Assert.Equal(expected, attr!.Length);
    }
}
