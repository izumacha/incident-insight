// PHI マスキング指示([Sensitive])と明示的除外([NotPhi])の定義を使うために取り込む
using IncidentInsight.Web.Models.Auditing;
// 監査対象エンティティ名の唯一の真実の源(AuditSaveChangesInterceptor)を参照するために取り込む
using IncidentInsight.Web.Data;
// 監査対象エンティティの導出と列の取り出しを行う共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// リフレクション(プロパティに付いた属性を調べる仕組み)を使うために取り込む
using System.Reflection;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 監査対象エンティティの文字列カラムに対する「PHI 分類の網羅性」テスト。
//
// なぜ必要か: AuditSaveChangesInterceptor.SerializeChanges は [Sensitive] が**無い**プロパティの
// 値をそのまま AuditLog.ChangesJson へ書く。つまり患者の自由記述や個人名を持つ列を新設して
// annotate を忘れると、コンパイルも既存テストも緑のまま平文の PHI が監査テーブルへ流れ込む。
// AuditLog は追記専用(インターセプタが唯一の書き込み源)なので、後から気付いても書かれた行は消せない。
//
// 既存の FreeTextMaxLengthAttributeTests が固定しているのは「[Sensitive] が付いていれば
// [MaxLength] もある」という**順方向**だけで、その逆(そもそも [Sensitive] を付け忘れた列)は
// どのテストも見ていなかった。このクラスがその逆方向を埋める。
//
// 判定は「無印を許さない」形にしている: 永続化される string 列は [Sensitive] か [NotPhi] の
// どちらかを必ず持たなければならない。無印が「安全だと判断した」と「判断し忘れた」の両方を
// 意味する限り付け忘れは検出できないため、判断したことを必ずコードに残させる
// (helpdesk-hub の AUTH_AUDIT_EVENT_IS_FAILURE が Set ではなく網羅的な Record である理由と同じ)。
public class AuditedEntityPhiClassificationTests
{
    // 検査対象のエンティティ型一覧。**ここに型を書き並べない**のが要点で、
    // AuditSaveChangesInterceptor.AuditedEntities(唯一の真実の源)から導出する。
    // テスト側が独自の一覧を持つと、監査対象を足したときに実装だけが増えて検査が追随せず、
    // 新しいエンティティの列が誰にも見られないまま平文で ChangesJson へ書かれる
    // ——「付け忘れを検出する」ためのこの検出網自身が、同じ形で穴を空けることになる
    public static TheoryData<Type> AuditedEntityTypes => AuditedEntityModel.AuditedEntityTheoryData();

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void PersistedStringColumns_MustBeClassifiedAsSensitiveOrExplicitlyNotPhi(Type entityType)
    {
        // このエンティティで実際に列になり、かつ属性を付けられる(CLR プロパティを持つ)string 列を取り出す。
        // shadow property を除くのは PersistedStringColumns_MustHaveBackingClrProperty が担当するため
        var columnNames = AuditedEntityModel.ClrBackedStringColumns(entityType)
            .Select(c => c.Name)
            .ToList();

        // 前提確認: 監査対象の各集約はいずれも文字列列を最低 1 つ持つはず。
        // 0 件だと「全部分類済み」と誤って緑になり、検出網が黙って死ぬ(fail-closed にしておく)
        Assert.NotEmpty(columnNames);

        // [Sensitive] も [NotPhi] も付いていない = 分類し忘れの列を集める
        var unclassified = columnNames
            .Where(name => !IsClassified(entityType, name))
            .ToList();

        // 分類漏れが 1 件も無いことを確認する(失敗時は列名と対処法をメッセージで示す)
        Assert.True(unclassified.Count == 0,
            $"監査対象エンティティの string 列が PHI 分類されていません: " +
            $"{string.Join(", ", unclassified.Select(n => $"{entityType.Name}.{n}"))}。" +
            "自由記述・個人名なら [Sensitive(Mask.Redact)] か [Sensitive(Mask.Hash)] を、" +
            "平文で監査ログに残してよいなら理由付きで [NotPhi(\"...\")] を付けてください " +
            "(無印のままだと AuditLog.ChangesJson へ平文で書かれます)。");
    }

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void SensitiveAndNotPhi_MustNotBeAppliedToTheSameColumn(Type entityType)
    {
        // このエンティティで実際に列になり、かつ属性を付けられる string 列を取り出す
        // (shadow property は属性を持ちえないので、そもそも矛盾のしようがない)
        var columnNames = AuditedEntityModel.ClrBackedStringColumns(entityType)
            .Select(c => c.Name)
            .ToList();

        // 両方付いている列を集める。両立は「マスクする」と「平文でよい」を同時に主張しており、
        // 実際にはインターセプタが [Sensitive] を優先してマスクするため [NotPhi] の理由文だけが
        // 残る — 読んだ人が「この列は平文で出る」と誤解する矛盾した状態になる
        var conflicting = columnNames
            .Where(name => FindAttribute<SensitiveAttribute>(entityType, name) != null
                        && FindAttribute<NotPhiAttribute>(entityType, name) != null)
            .ToList();

        // 矛盾した指定が 1 件も無いことを確認する
        Assert.True(conflicting.Count == 0,
            $"[Sensitive] と [NotPhi] が同じ列に付いています(どちらか一方にしてください): " +
            $"{string.Join(", ", conflicting.Select(n => $"{entityType.Name}.{n}"))}");
    }

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void PersistedStringColumns_MustHaveBackingClrProperty(Type entityType)
    {
        // 対応する CLR プロパティを持たない string 列(= shadow property)を集める
        var shadowColumns = AuditedEntityModel.ShadowStringColumnNames(entityType);

        // shadow property を禁じる理由は「属性を付けられないから」ではなく、
        // **インターセプタが原理的にマスクできないから**。LookupSensitiveMask は CLR プロパティに付いた
        // [Sensitive] を読むため、shadow property は必ず mask なし = 平文で ChangesJson へ書かれる。
        // つまり shadow string 列は「PHI が混じった瞬間に、追記専用テーブルへ平文で流れ込み、
        // 後から消せない」経路そのもので、[Sensitive] を付けて塞ぐことができない。
        //
        // この検査を分けているのは対処法が他の 2 つと違うため。分類漏れの答えは「属性を付ける」だが、
        // shadow property の答えは「CLR プロパティへ昇格させる(そのうえで分類する)」で、
        // 上の分類テストのメッセージ(「[Sensitive] か [NotPhi] を付けてください」)は実行不能な指示になる。
        // 実行不能な指示を出す検出網は、いずれ「直せないので検査を緩める」方向へ倒れる
        Assert.True(shadowColumns.Count == 0,
            $"監査対象エンティティに CLR プロパティを持たない string 列(shadow property)があります: " +
            $"{string.Join(", ", shadowColumns.Select(n => $"{entityType.Name}.{n}"))}。" +
            "shadow property には [Sensitive] を付けられないため、インターセプタは値を必ず平文で " +
            "AuditLog.ChangesJson へ書きます。通常の CLR プロパティへ昇格させたうえで " +
            "[Sensitive(...)] か [NotPhi(\"...\")] で分類してください。");
    }

    [Fact]
    public void AuditedEntityTypes_AreDerivedFromInterceptorDeclaration()
    {
        // 導出された CLR 型の名前を取り出す
        var derived = AuditedEntityModel.ResolveAuditedClrTypes()
            .Select(t => t.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // インターセプタが宣言している監査対象名を同じ順序に整える
        var declared = AuditSaveChangesInterceptor.AuditedEntities
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // 導出結果が宣言と 1 対 1 で対応していることを確認する。
        // ここがずれるのは「宣言にある名前が EF のモデルに無い」ときだけで、
        // その場合 ResolveAuditedClrTypes が先に落ちる。二重の確認に見えるが、
        // 将来 ResolveAuditedClrTypes に絞り込み(除外リスト等)が入ったときに、
        // 検査対象が黙って減ったことをここが捕まえる
        Assert.Equal(declared, derived);

        // 監査対象が 0 件だと上の 2 つの Theory が 1 ケースも実行されず、
        // 「失敗が無い＝緑」になってしまうので、最低 1 件あることを固定する(fail-closed)
        Assert.NotEmpty(derived);
    }

    // 指定した列が [Sensitive] か [NotPhi] のどちらかで分類済みかを返す
    private static bool IsClassified(Type entityType, string propertyName)
    {
        // マスク指定があれば分類済み
        if (FindAttribute<SensitiveAttribute>(entityType, propertyName) != null) return true;
        // 明示的な除外があれば分類済み
        if (FindAttribute<NotPhiAttribute>(entityType, propertyName) != null) return true;
        // どちらも無ければ分類し忘れ
        return false;
    }

    // 指定した CLR プロパティに付いた属性を取得する(無ければ null)。
    // インターセプタの LookupSensitiveMask と同じく inherit: true で基底クラスの指定も拾う
    private static T? FindAttribute<T>(Type entityType, string propertyName) where T : Attribute
    {
        // 対象のプロパティ情報を共有ヘルパー経由で取り出す(探索条件を検査ごとにばらけさせない)
        var property = AuditedEntityModel.FindClrProperty(entityType, propertyName);
        // CLR プロパティが無い列(shadow property)は属性を持ちえない
        // (この状態は PersistedStringColumns_MustHaveBackingClrProperty が専用のメッセージで落とす)
        if (property is null) return null;
        // 属性を取得して返す(継承元クラスに付けられた指定も対象にする)
        return property.GetCustomAttribute<T>(inherit: true);
    }
}
