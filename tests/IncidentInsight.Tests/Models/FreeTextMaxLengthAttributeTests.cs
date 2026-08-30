// エンティティ(Incident / CauseAnalysis / PreventiveMeasure)を使うために取り込む
using IncidentInsight.Web.Models;
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

// 長さ上限の管理対象となる業務エンティティの string カラムに対する不変条件テスト。
// EF Core は保存時に DataAnnotations を自動検証しないため、ViewModel 側の検証だけに頼ると
// 将来 ViewModel を経由しない書き込み経路(API 追加等)が生えた瞬間に無制限の文字列が
// そのまま永続化されてしまう。しかも監査対象エンティティでは同じ値が AuditLog.ChangesJson へも
// 積まれるため、1 列ぶんの書き込みが行と監査ログの二重に効く(AuditLog は追記専用で消せない)。
//
// 検査範囲は監査対象ではなく**長さ上限の管理対象となる業務エンティティ**。監査対象に絞ると、
// 監査されないエンティティ(CauseCategory)の無制限な列を誰も見ないままになる
// ——実際 CauseCategory.Description が上限なしのまま残っていたのをこの拡張が検出した。
//
// 検査対象を「[Sensitive] 付きの列」ではなく**永続化される string 列すべて**にしているのが要点。
// 以前は [Sensitive] 付きだけを見ていたが、PHI 分類に [NotPhi] という 2 つ目の正当な選択肢が
// 増えた時点で、その形が検出網の穴になった —— 新しい string 列に [NotPhi("...")] だけ付けて
// [MaxLength] を書き忘れると、PHI 分類テストも本テストも緑のまま無制限の列が通ってしまう。
// しかも [NotPhi] 列は定義上マスクされないので、無制限の値が監査ログへ**平文で**積まれる。
// 「エスケープハッチを足したら、既存の検出網がその分だけ黙って狭くなる」という形の後退なので、
// 分類の種類に依存しない「列であること」を条件にして、将来の分類が増えても穴が空かないようにする。
//
// 列の一覧は CLR のリフレクションではなく EF Core のモデルから引く(PHI 分類テストと同じ源)。
// リフレクションだと計算プロパティ(SeverityLabel 等)を誤検出し、逆に shadow property を取りこぼす。
public class FreeTextMaxLengthAttributeTests
{
    // 検査対象のエンティティ型一覧。型を書き並べず、監査インターセプタの宣言
    // (AuditSaveChangesInterceptor.AuditedEntities = 唯一の真実の源)から導出する。
    // ここで独自の一覧を持つと、監査対象を足したときに実装だけが増えて検査が追随せず、
    // 新しいエンティティの自由記述列が上限なしのまま素通りする
    public static TheoryData<Type> LengthGovernedEntityTypes =>
        AuditedEntityModel.ToTheoryData(AuditedEntityModel.LengthGovernedEntityTypes());

    [Theory]
    [MemberData(nameof(LengthGovernedEntityTypes))]
    public void PersistedStringColumns_MustHaveMaxLength(Type entityType)
    {
        // 対象エンティティで実際に列になり、かつ属性を付けられる string 列を EF のモデルから取り出す
        // (列名と CLR プロパティの組)。shadow property は AuditedEntityPhiClassificationTests が
        // 専用の対処法で落とすので、ここでは対象から外れている
        var columns = AuditedEntityModel.ClrBackedStringColumns(entityType);

        // 前提確認: 各エンティティに検査対象の string 列が最低 1 つは存在するはず。
        // 0 件だと「全部上限付き」と誤って緑になり、検出網が黙って死ぬ(fail-closed にしておく)
        Assert.NotEmpty(columns);

        // 長さ上限が設定されていない列を探す(あれば付け漏れ)。
        // 判定は EF のモデルが持つ値なので、[MaxLength] 属性でも fluent の HasMaxLength() でも通る
        var missing = columns
            .Where(c => c.MaxLength == null)
            .Select(c => $"{entityType.Name}.{c.Name}")
            .ToList();

        // 付け漏れが 1 件も無いことを確認する(失敗時はどの列かをメッセージで示す)
        Assert.True(missing.Count == 0,
            $"永続化される string 列に長さ上限がありません: {string.Join(", ", missing)}。" +
            $"入力経路と同じ上限({nameof(FieldLengths)} の定数)を [MaxLength] か HasMaxLength() で明示してください " +
            "(EF Core は保存時に DataAnnotations を検証しないため、ViewModel を経由しない書き込み経路が " +
            "生えた瞬間に無制限の文字列がそのまま永続化され、同じ値が AuditLog.ChangesJson にも積まれます)。");
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
