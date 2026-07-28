// エンティティ(Incident / CauseAnalysis / PreventiveMeasure)を使うために取り込む
using IncidentInsight.Web.Models;
// [Sensitive] 属性(PHI マスキング指示)の定義を使うために取り込む
using IncidentInsight.Web.Models.Auditing;
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
    // 検査対象のエンティティ型一覧(監査インターセプタの対象と同じ 3 集約)
    public static TheoryData<Type> AuditedEntityTypes => new()
    {
        typeof(Incident),
        typeof(CauseAnalysis),
        typeof(PreventiveMeasure),
    };

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
    // 今回の修正で追加した 3 プロパティが、入力経路(ViewModel)と同じ 500 文字上限であることを個別確認する
    [InlineData(typeof(Incident), nameof(Incident.Description), 500)]
    [InlineData(typeof(Incident), nameof(Incident.ImmediateActions), 500)]
    [InlineData(typeof(CauseAnalysis), nameof(CauseAnalysis.AdditionalNotes), 500)]
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
        // 上限値が ViewModel 側の検証(500 文字)と一致していることを確認する
        Assert.Equal(expected, attr!.Length);
    }
}
