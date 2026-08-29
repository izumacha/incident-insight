// エンティティ(Incident / CauseAnalysis / PreventiveMeasure)を使うために取り込む
using IncidentInsight.Web.Models;
// PHI マスキング指示([Sensitive])と明示的除外([NotPhi])の定義を使うために取り込む
using IncidentInsight.Web.Models.Auditing;
// ApplicationDbContext(EF Core のモデル定義)を使うために取り込む
using IncidentInsight.Web.Data;
// DbContextOptionsBuilder / UseInMemoryDatabase を使うために取り込む
using Microsoft.EntityFrameworkCore;
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
    // 検査対象のエンティティ型一覧(AuditSaveChangesInterceptor.AuditedEntities と同じ 3 集約)。
    // ここを CLR 型で持つのは、下で EF のモデルを引く際のキーに使うため
    public static TheoryData<Type> AuditedEntityTypes => new()
    {
        typeof(Incident),
        typeof(CauseAnalysis),
        typeof(PreventiveMeasure),
    };

    // 検査に使う EF Core のモデル(どの CLR プロパティが実際に列として永続化されるか)を組み立てる。
    // リフレクションで型のプロパティを直接数えないのは、それだと実態とずれるため:
    // 計算プロパティ(SeverityLabel / DeepestWhy など setter を持たない表示用プロパティ)は
    // 列にならないのに拾ってしまい、逆に将来 [NotMapped] や shadow property を使うと取りこぼす。
    // インターセプタが走査するのは EntityEntry.Properties(= EF のモデル)なので、検査もそこへ揃える
    private static AuditedModelProbe BuildModel()
    {
        // 実 DB へ接続せずにモデルだけを組み立てたいので InMemory プロバイダを使う
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        // OnModelCreating を通したモデルを持つコンテキストを作る
        var db = new ApplicationDbContext(options);
        // モデルだけを取り出し、コンテキストは呼び出し側で破棄できるよう包んで返す
        return new AuditedModelProbe(db);
    }

    // DbContext の後始末を確実に行うための小さな入れ物(using で破棄する)
    private sealed class AuditedModelProbe : IDisposable
    {
        // 破棄対象のコンテキスト
        private readonly ApplicationDbContext _db;

        // コンテキストを受け取って保持する
        public AuditedModelProbe(ApplicationDbContext db) => _db = db;

        // 指定 CLR 型に対応する「永続化される string 列」の CLR プロパティ名を返す。
        // 主キーは除外する(インターセプタ側も IsPrimaryKey() のとき ChangesJson へ書かずに読み飛ばす)
        public IReadOnlyList<string> PersistedStringPropertyNames(Type entityType)
        {
            // EF のモデルから対象エンティティの定義を引く(見つからなければ後続で落ちる)
            var entity = _db.Model.FindEntityType(entityType);
            // モデルに載っていない型を渡した場合は検査の前提が崩れるので、その場で失敗させる
            Assert.NotNull(entity);

            // 列として永続化されるプロパティのうち、主キー以外の string 型だけを名前で返す
            return entity!
                .GetProperties()
                .Where(p => !p.IsPrimaryKey())
                .Where(p => p.ClrType == typeof(string))
                .Select(p => p.Name)
                .ToList();
        }

        // 保持しているコンテキストを破棄する
        public void Dispose() => _db.Dispose();
    }

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void PersistedStringColumns_MustBeClassifiedAsSensitiveOrExplicitlyNotPhi(Type entityType)
    {
        // EF のモデルを組み立て、検査が終わったら確実に破棄する
        using var model = BuildModel();

        // このエンティティで実際に列になる string プロパティ名を取り出す
        var columnNames = model.PersistedStringPropertyNames(entityType);

        // 前提確認: 監査対象の 3 集約はいずれも文字列列を最低 1 つ持つはず。
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
        // EF のモデルを組み立て、検査が終わったら確実に破棄する
        using var model = BuildModel();

        // このエンティティで実際に列になる string プロパティ名を取り出す
        var columnNames = model.PersistedStringPropertyNames(entityType);

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
        // 対象のプロパティ情報を取り出す(public インスタンスプロパティのみ)
        var property = entityType.GetProperty(propertyName, BindingFlags.Public | BindingFlags.Instance);
        // EF の列名に対応する CLR プロパティが見つからない場合(shadow property)は属性を持ちえない
        if (property is null) return null;
        // 属性を取得して返す(継承元クラスに付けられた指定も対象にする)
        return property.GetCustomAttribute<T>(inherit: true);
    }
}
