// ApplicationDbContext(EF Core のモデル定義)を使うために取り込む
using IncidentInsight.Web.Data;
// DbContextOptionsBuilder / UseInMemoryDatabase / IModel を使うために取り込む
using Microsoft.EntityFrameworkCore;
// PropertyInfo / BindingFlags(CLR プロパティの探索)を使うために取り込む
using System.Reflection;

// テスト共通のヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// 「監査対象エンティティ」に関する検査が共通して使う土台。
///
/// 監査対象の一覧は <see cref="AuditSaveChangesInterceptor.AuditedEntities"/> が唯一の真実の源で、
/// テスト側はそこから導出する。テストが独自に一覧を持つと、監査対象を足したときに実装だけが増えて
/// 検査が追随せず、新しいエンティティの列が誰にも見られないまま ChangesJson へ平文で書かれる。
///
/// 列の判定に CLR のリフレクションではなく EF Core のモデルを使うのは、インターセプタが走査するのが
/// <c>EntityEntry.Properties</c>(= EF のモデル)だから。リフレクションだと計算プロパティ
/// (<c>SeverityLabel</c> / <c>DeepestWhy</c> など列にならない表示用)を誤検出し、
/// 逆に shadow property を取りこぼす。
/// </summary>
internal static class AuditedEntityModel
{
    /// <summary>
    /// 監査対象エンティティの CLR 型を、インターセプタが持つ名前の集合から導出して返す。
    /// 名前に対応するエンティティが EF のモデルに 1 つも無ければ例外で落とす(fail-closed) —
    /// 綴り違いやモデルからの削除で検査対象が静かに減るのを防ぐ。
    /// </summary>
    public static IReadOnlyList<Type> ResolveAuditedClrTypes()
    {
        // モデルだけを組み立てて、解決が終わったら破棄する
        using var probe = CreateModelProbe();

        // 導出した CLR 型を溜めるリスト
        var resolved = new List<Type>();

        // インターセプタが監査対象として宣言している名前を 1 つずつ解決する
        foreach (var entityName in AuditSaveChangesInterceptor.AuditedEntities)
        {
            // EF のモデルから同名のエンティティ定義を探す(型名の一致で引く。
            // インターセプタも Metadata.ClrType.Name で突き合わせているので同じ土俵になる)
            var entityType = probe.Model.GetEntityTypes()
                .FirstOrDefault(e => e.ClrType.Name == entityName);

            // 対応するエンティティがモデルに無いのは前提が崩れた状態なので、その場で落とす
            if (entityType is null)
            {
                // どの名前が解決できなかったのかを示して失敗させる
                throw new InvalidOperationException(
                    $"監査対象として宣言されている '{entityName}' に対応するエンティティが EF のモデルに見つかりません。" +
                    "AuditSaveChangesInterceptor.AuditedEntities と ApplicationDbContext の定義がずれています。");
            }

            // 解決できた CLR 型を積む
            resolved.Add(entityType.ClrType);
        }

        // 呼び出し順が実行ごとに揺れないよう型名で並べてから返す(失敗時のメッセージを安定させる)
        return resolved.OrderBy(t => t.Name, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// 指定エンティティで実際に列として永続化される <c>string</c> プロパティ名を返す。
    /// 主キーは除外する(インターセプタ側も <c>IsPrimaryKey()</c> のとき ChangesJson へ書かず読み飛ばす)。
    /// </summary>
    public static IReadOnlyList<string> PersistedStringColumnNames(Type entityType)
    {
        // モデルだけを組み立てて、取り出しが終わったら破棄する
        using var probe = CreateModelProbe();

        // EF のモデルから対象エンティティの定義を引く
        var entity = probe.Model.FindEntityType(entityType);

        // モデルに載っていない型を渡された場合は検査の前提が崩れるので落とす(fail-closed)
        if (entity is null)
        {
            // どの型が解決できなかったのかを示して失敗させる
            throw new InvalidOperationException(
                $"型 '{entityType.Name}' に対応するエンティティが EF のモデルに見つかりません。");
        }

        // 列として永続化されるプロパティのうち、主キー以外の string 型だけを名前で返す
        return entity
            .GetProperties()
            .Where(p => !p.IsPrimaryKey())
            .Where(p => p.ClrType == typeof(string))
            .Select(p => p.Name)
            .ToList();
    }

    /// <summary>
    /// EF の列名に対応する CLR プロパティを返す(見つからなければ <c>null</c> = shadow property)。
    ///
    /// 列の一覧は EF のモデルから引くのに対し、<c>[Sensitive]</c> / <c>[NotPhi]</c> / <c>[MaxLength]</c> は
    /// CLR プロパティに付く属性なので、両者を突き合わせる場所がここ 1 か所に要る。
    /// 検査側が個別に <c>GetProperty</c> を書くと、BindingFlags や inherit の指定が食い違ったときに
    /// 「片方の検査だけ属性を見つけられない」という気付きにくいずれが生まれる。
    /// </summary>
    public static PropertyInfo? FindClrProperty(Type entityType, string columnName)
    {
        // public なインスタンスプロパティから列名と同名のものを探す(EF の既定の対応付けと同じ土俵)
        return entityType.GetProperty(columnName, BindingFlags.Public | BindingFlags.Instance);
    }

    /// <summary>
    /// 指定エンティティの永続化 <c>string</c> 列のうち、CLR プロパティに対応するものだけを名前で返す。
    ///
    /// 属性ベースの検査(<c>[Sensitive]</c> / <c>[NotPhi]</c> / <c>[MaxLength]</c>)は、そもそも属性を
    /// 付けられる CLR プロパティが無ければ成立しない。shadow property をここで除くのは見逃しではなく、
    /// 「shadow property は属性で分類できないので存在自体を禁じる」という別の検査
    /// (<c>AuditedEntityPhiClassificationTests.PersistedStringColumns_MustHaveBackingClrProperty</c>)へ
    /// 責務を渡しているため。1 つの原因に対して各検査がそれぞれ的外れな対処法を案内するのを避ける。
    /// </summary>
    public static IReadOnlyList<(string Name, PropertyInfo Property)> ClrBackedStringColumns(Type entityType)
    {
        // 永続化される string 列を、対応する CLR プロパティと組にする(無い列は null が入る)
        return PersistedStringColumnNames(entityType)
            .Select(name => (Name: name, Property: FindClrProperty(entityType, name)))
            // CLR プロパティを持つ列だけに絞る。ここで絞った結果を組で返すことで、
            // 呼び出し側が「絞ったのだから null ではない」を null 免除演算子(!)で主張せずに済む
            .Where(pair => pair.Property != null)
            .Select(pair => (pair.Name, Property: pair.Property!))
            .ToList();
    }

    /// <summary>
    /// <see cref="ClrBackedStringColumns"/> の列名だけが要る呼び出し側のための薄い射影。
    /// </summary>
    public static IReadOnlyList<string> ClrBackedStringColumnNames(Type entityType)
    {
        // 組から列名だけを取り出して返す
        return ClrBackedStringColumns(entityType).Select(pair => pair.Name).ToList();
    }

    /// <summary>
    /// 指定エンティティの永続化 <c>string</c> 列のうち、CLR プロパティを持たない(= shadow property)
    /// ものを名前で返す。上の <see cref="ClrBackedStringColumnNames"/> の補集合。
    /// </summary>
    public static IReadOnlyList<string> ShadowStringColumnNames(Type entityType)
    {
        // 永続化される string 列のうち、対応する CLR プロパティが無いものだけを返す
        return PersistedStringColumnNames(entityType)
            .Where(name => FindClrProperty(entityType, name) == null)
            .ToList();
    }

    // 実 DB へ接続せずに OnModelCreating を通したモデルだけを得るための使い捨てコンテキストを作る
    private static ApplicationDbContext CreateModelProbe()
    {
        // モデルの組み立てだけが目的なので InMemory プロバイダで十分
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        // 呼び出し側が using で破棄する前提でコンテキストを返す
        return new ApplicationDbContext(options);
    }
}
