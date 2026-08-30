// ApplicationDbContext(EF Core のモデル定義)を使うために取り込む
using IncidentInsight.Web.Data;
// DbContextOptionsBuilder / UseInMemoryDatabase を使うために取り込む
using Microsoft.EntityFrameworkCore;
// IModel / IProperty(EF Core のモデル定義を読む型)を使うために取り込む
using Microsoft.EntityFrameworkCore.Metadata;
// PropertyInfo / BindingFlags(CLR プロパティの探索)を使うために取り込む
using System.Reflection;
// TheoryData(xUnit の [MemberData] へ渡すケース一覧)を使うために取り込む
using Xunit;

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
    // OnModelCreating を通した EF のモデル。組み立ては決定的なので 1 回で足りる。
    //
    // 毎回 CreateModelProbe() を呼ぶと、検査 1 件ごとに DbContext とモデルを組み直すうえ、
    // UseInMemoryDatabase(Guid) が EF のプロセス内ストアキャッシュ(InMemoryStoreCache)へ
    // 毎回別のストアを登録して、テストプロセスが終わるまで解放されない。
    // Lazy にしているのは、モデル組み立ての失敗をこのクラスに触れた検査へ確実に伝えるため
    private static readonly Lazy<IModel> Model = new(BuildModel);

    /// <summary>
    /// 監査対象エンティティの CLR 型を、インターセプタが持つ名前の集合から導出して返す。
    /// 名前に対応するエンティティが EF のモデルに 1 つも無ければ例外で落とす(fail-closed) —
    /// 綴り違いやモデルからの削除で検査対象が静かに減るのを防ぐ。
    /// </summary>
    public static IReadOnlyList<Type> ResolveAuditedClrTypes()
    {
        // 導出した CLR 型を溜めるリスト
        var resolved = new List<Type>();

        // インターセプタが監査対象として宣言している名前を 1 つずつ解決する
        foreach (var entityName in AuditSaveChangesInterceptor.AuditedEntities)
        {
            // EF のモデルから同名のエンティティ定義を探す(型名の一致で引く。
            // インターセプタも Metadata.ClrType.Name で突き合わせているので同じ土俵になる)
            var entityType = Model.Value.GetEntityTypes()
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
    /// 監査対象エンティティを xUnit の <c>[MemberData]</c> へ渡す形にして返す。
    ///
    /// 各テストクラスがこの詰め替えを書き写すと、片方だけに絞り込み(所有型の除外など)を入れたときに
    /// 一方の検出網だけが黙って狭くなる。ケース一覧の作り方もここ 1 か所に置く。
    /// </summary>
    public static TheoryData<Type> AuditedEntityTheoryData()
    {
        // xUnit へ渡す入れ物を用意する
        var data = new TheoryData<Type>();

        // インターセプタの宣言から導出した CLR 型を 1 つずつ積む
        foreach (var entityType in ResolveAuditedClrTypes())
        {
            // 1 ケース分として追加する
            data.Add(entityType);
        }

        // 組み上がったケース一覧を返す
        return data;
    }

    /// <summary>
    /// EF の列名に対応する CLR プロパティを返す(見つからなければ <c>null</c> = shadow property)。
    ///
    /// 列の一覧は EF のモデルから引くのに対し、<c>[Sensitive]</c> / <c>[NotPhi]</c> は CLR プロパティに
    /// 付く属性なので、両者を突き合わせる場所がここ 1 か所に要る。検査側が個別に <c>GetProperty</c> を
    /// 書くと、<c>BindingFlags</c> の指定が食い違ったときに「片方の検査だけ属性を見つけられない」という
    /// 気付きにくいずれが生まれる。
    ///
    /// <c>BindingFlags</c> は本番の <c>AuditSaveChangesInterceptor.LookupSensitiveMask</c> と
    /// **同一**にする(<c>NonPublic</c> を含む)。ここだけ <c>Public</c> に絞ると、非公開プロパティを列に
    /// マップした場合に「本番は <c>[Sensitive]</c> を読んでマスクするのに、検査からは shadow property に
    /// 見える」というずれが起き、実在して属性も付いている列に対して「CLR プロパティへ昇格させてください」
    /// という実行不能な指示を出してしまう。
    /// </summary>
    public static PropertyInfo? FindClrProperty(Type entityType, string columnName)
    {
        // 列名と同名の CLR プロパティを探す(探索条件は本番のマスク解決と同じ)
        return entityType.GetProperty(
            columnName,
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic);
    }

    /// <summary>
    /// 指定エンティティで実際に列として永続化される「文字列として保存される」列を
    /// CLR プロパティを持つもの／持たないもの(shadow property)に分けて返す。
    /// 主キーは除外する(インターセプタ側も <c>IsPrimaryKey()</c> のとき ChangesJson へ書かず読み飛ばす)。
    /// </summary>
    public static (IReadOnlyList<StringColumn> ClrBacked, IReadOnlyList<string> Shadow)
        PartitionStringColumns(Type entityType)
    {
        // EF のモデルから対象エンティティの定義を引く
        var entity = Model.Value.FindEntityType(entityType);

        // モデルに載っていない型を渡された場合は検査の前提が崩れるので落とす(fail-closed)
        if (entity is null)
        {
            // どの型が解決できなかったのかを示して失敗させる
            throw new InvalidOperationException(
                $"型 '{entityType.Name}' に対応するエンティティが EF のモデルに見つかりません。");
        }

        // 主キー以外で「文字列として保存される」列を集め、CLR プロパティと組にする
        var columns = entity
            .GetProperties()
            .Where(p => !p.IsPrimaryKey())
            .Where(IsStoredAsString)
            .Select(p => (
                Name: p.Name,
                Property: FindClrProperty(entityType, p.Name),
                // 長さ上限は EF のモデルから読む。[MaxLength] 属性だけを見ると、fluent API の
                // HasMaxLength() で設定した列(値変換を通す列はこちらで設定している)を
                // 「上限なし」と誤判定してしまう。DB の列長を決めているのはモデル側の値
                MaxLength: p.GetMaxLength()))
            .ToList();

        // CLR プロパティを持つ列(= 属性で分類できる列)
        var clrBacked = columns
            .Where(c => c.Property != null)
            .Select(c => new StringColumn(c.Name, c.Property!, c.MaxLength))
            .ToList();

        // CLR プロパティを持たない列(= 属性を付けようがない列)
        var shadow = columns
            .Where(c => c.Property == null)
            .Select(c => c.Name)
            .ToList();

        // 2 つに分けた結果をまとめて返す。
        // 両方が要る呼び出し側はこれを 1 回呼べば済む(薄い射影 ClrBackedStringColumns /
        // ShadowStringColumnNames はそれぞれ独立にここを呼ぶので、両方使うと走査は 2 回になる)。
        // 監査対象は 3 集約・各 20 列程度でリフレクションも属性読みだけなので、
        // メモ化して無効化のタイミングを抱えるより素直に再計算する方が安全と判断した
        return (clrBacked, shadow);
    }

    /// <summary>
    /// <see cref="PartitionStringColumns"/> のうち CLR プロパティを持つ列だけを返す薄い射影。
    ///
    /// shadow property を除くのは見逃しではなく、「shadow property は属性で分類できないので存在自体を
    /// 禁じる」という別の検査
    /// (<c>AuditedEntityPhiClassificationTests.PersistedStringColumns_MustHaveBackingClrProperty</c>)へ
    /// 責務を渡しているため。1 つの原因に対して各検査がそれぞれ的外れな対処法を案内するのを避ける。
    /// </summary>
    public static IReadOnlyList<StringColumn> ClrBackedStringColumns(Type entityType)
    {
        // 分割済みの結果から CLR プロパティを持つ側だけを返す
        return PartitionStringColumns(entityType).ClrBacked;
    }

    /// <summary>
    /// <see cref="PartitionStringColumns"/> のうち CLR プロパティを持たない列名だけを返す薄い射影。
    /// </summary>
    public static IReadOnlyList<string> ShadowStringColumnNames(Type entityType)
    {
        // 分割済みの結果から shadow property 側だけを返す
        return PartitionStringColumns(entityType).Shadow;
    }

    /// <summary>
    /// 「文字列として保存される」列 1 つぶんの情報。
    /// <paramref name="MaxLength"/> は EF のモデルが持つ長さ上限で、<c>null</c> なら上限なし。
    /// </summary>
    /// <param name="Name">EF のモデル上の列名</param>
    /// <param name="Property">列に対応する CLR プロパティ(属性はここから読む)</param>
    /// <param name="MaxLength">EF のモデルに設定された長さ上限(未設定なら null)</param>
    public sealed record StringColumn(string Name, PropertyInfo Property, int? MaxLength);

    // その列が最終的に「文字列として」保存されるかを判定する。
    //
    // CLR の型が string かどうかだけでは足りない: HasConversion<string>() を通した列
    // (Incident.Severity / IncidentType, PreventiveMeasure.Status / MeasureType など)は
    // ClrType が enum のままなので「string 列ではない」と誤判定され、検出網から丸ごと外れる。
    // 判定を「DB に文字列として入るか」に置くことで、将来 HasConversion<string>() で保存する
    // 自由記述の値オブジェクトを足しても、分類と長さ上限の検査が自動で追随する
    private static bool IsStoredAsString(IProperty property)
    {
        // 変換後の型は書き方によって現れる場所が違うため、両方を見る(実測で確認済み):
        //   - HasConversion<string>()        → GetProviderClrType() が string / GetValueConverter() は null
        //     (例: Incident.Severity, PreventiveMeasure.Status / MeasureType)
        //   - HasConversion(v => ..., v => ...) → GetValueConverter() が string / GetProviderClrType() は null
        //     (例: Incident.IncidentType)
        // 片方だけを見ると、もう一方の書き方で保存される文字列列が検出網から丸ごと外れる
        var storedType = property.GetProviderClrType()
            ?? property.GetValueConverter()?.ProviderClrType
            ?? property.ClrType;

        // 最終的に文字列として保存されるなら検査対象
        return storedType == typeof(string);
    }

    // 実 DB へ接続せずに OnModelCreating を通したモデルだけを組み立てる
    private static IModel BuildModel()
    {
        // モデルの組み立てだけが目的なので InMemory プロバイダで十分
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        // コンテキストは使い捨て。取り出した IModel は破棄後も読めるので保持して使い回す
        using var probe = new ApplicationDbContext(options);
        return probe.Model;
    }
}
