// エンティティ(Incident / CauseAnalysis / PreventiveMeasure)を使うために取り込む
using IncidentInsight.Web.Models;
// 文字数上限の唯一の真実の源(FieldLengths)を期待値として使うために取り込む
using IncidentInsight.Web.Models.Validation;
// 監査対象エンティティをインターセプタの宣言から導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
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
    // 検査対象のエンティティ型一覧。型を書き並べず、長さ上限の管理対象を導出する
    // 共有ファクトリ(AuditedEntityModel.LengthGovernedTheoryData)から受け取る。
    //
    // **監査対象(AuditSaveChangesInterceptor.AuditedEntities)からは導出しない。**
    // 「どのエンティティを監査するか」と「どのエンティティの列長を管理するか」は別の関心事で、
    // 前者から後者を導くと、あるエンティティを監査対象から外した瞬間に無関係なはずの
    // 長さ検査までまとめて外れる(すべて fail-open。CLAUDE.md §3)。
    // ここで独自の一覧を持つのも同じ理由で避ける —— 管理対象が増えたときに
    // この検査だけが取り残され、新しいエンティティの自由記述列が上限なしのまま素通りする
    public static TheoryData<Type> LengthGovernedEntityTypes =>
        AuditedEntityModel.LengthGovernedTheoryData();

    [Theory]
    [MemberData(nameof(LengthGovernedEntityTypes))]
    public void PersistedStringColumns_MustHaveMaxLength(Type entityType)
    {
        // 対象エンティティで実際に列になる string 列を、列名と上限の組で EF のモデルから取り出す。
        //
        // shadow property(CLR プロパティを持たない列)も**含める**。以前は ClrBacked に絞り、
        // 「shadow は AuditedEntityPhiClassificationTests が専用の対処法で落とす」としていたが、
        // その検査の対象は監査対象 3 集約だけなので、監査対象でない CauseCategory へ
        // 上限なしの shadow string 列(Property<string>("...") )を足すと 4 つの検査すべてを
        // 素通りした(実測で全件緑)。上限の検査は属性を読まないので shadow 列も対象にできる。
        //
        // 基底クラス(Identity)が宣言した列は除く —— UserName / Email などの列長を決めているのは
        // ASP.NET Core Identity で、FieldLengths の定数を当てはめる対象ではない。
        // 一方 ApplicationUser.DisplayName / Department はこのリポジトリが足した業務列なので残る
        var columns = AuditedEntityModel.AppDeclaredStringColumnLengths(entityType);

        // 前提確認: このエンティティが自前の string プロパティを宣言しているなら、
        // 検査対象の列も最低 1 つは取れるはず。0 件なら「全部上限付き」と誤って緑になり、
        // このエンティティについて検出網が黙って死ぬ(fail-closed にしておく)。
        //
        // 「自前の string 列を持つなら」という条件を付けるのが要点。
        // 無条件に非空を要求すると、この repo が確立したパターン(Identity の型を継承して
        // 業務列を足す)に従って独自の string 列を持たない型を足したときに
        // 「自分たちには足せない列を足せ」という実行不能な指示になる。
        // 逆にスイート全体の合計で見ると granularity が失われ、あるエンティティの業務列が
        // 別アセンブリの基底へ移って 0 件になっても、他のエンティティの列数で合計が
        // 正のままになり**痕跡なく**そのエンティティだけ検査が空回りする(テスト件数も変わらない)。
        //
        // 数える対象は「マップ済み・主キー以外」に限る。単に「自前の string プロパティがあるか」で
        // 見ると、文字列を主キーにしたマスタ型や計算プロパティしか持たない型に対して
        // 「条件が実装とずれている」という誤った原因で落ちる(実測)
        var ownStringColumnCount = AuditedEntityModel.OwnDeclaredMappedStringPropertyCount(entityType);

        // 成り立つべき不変条件は「独立に数えた自前の string 列は、必ず検査対象に現れる」。
        //
        // 「0 件でないこと」だけを見ると**部分的な取りこぼしが素通りする**: たとえば
        // Incident の検査対象には値変換した enum 列(Severity / IncidentType)も含まれるため、
        // 絞り込みが狭まって自由記述 4 列が丸ごと落ちても columns.Count は 2 のままで、
        // 0 件ではないのでガードが発火しない。件数の比較にしておけば、その取りこぼしも捕まる
        // 突き合わせるのは**同じ種類の列どうし**。columns には値変換した enum 列や shadow 列も
        // 含まれるので、全体の件数で比べると「enum 列の数だけ string 列を落としても通る」
        // 隙間ができる —— 実測でも Incident(string 4 + enum 2)から自前の string 列を 2 つ
        // 落としつつ ReporterName の [MaxLength] を消すと 4 >= 4 が成立し、全件緑のまま
        // 個人名の列が無制限で出荷された(テスト件数すら変わらない)
        var clrStringColumnCount = columns.Count(c => c.IsClrString);

        // 独立に数えた自前の string 列は、必ず検査対象に現れるはず
        Assert.True(clrStringColumnCount >= ownStringColumnCount,
            $"{entityType.Name} は自前の string 列を {ownStringColumnCount} 件持つのに、検査対象の " +
            $"string 列が {clrStringColumnCount} 件しか取得できていません。" +
            "AppDeclaredStringColumnLengths の条件が実装とずれています" +
            "(このままだと落ちた列について上限の付け忘れが素通りします)。");

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

        // 長さ上限の属性は共有リーダーで解釈する。ここだけ [MaxLength] を直接読むと、
        // 綴りを [StringLength] へ変えたときにこのテストだけが「属性が無い」という
        // 原因の分からない失敗になる(CLAUDE.md「属性の解釈は 1 か所に集約する」)
        var limits = AuditedEntityModel.ReadLengthLimits(property!);

        // 上限が宣言されていることを確認する
        Assert.True(limits.Count > 0,
            $"{entityType.Name}.{propertyName} に長さ上限の属性が付いていません。");

        // 宣言された上限がすべて期待値と一致していることを確認する
        Assert.All(limits, limit => Assert.Equal(expected, limit.Length));
    }
}
