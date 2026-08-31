// ApplicationDbContext(EF Core のモデル定義)を使うために取り込む
using IncidentInsight.Web.Data;
// AuditLog(長さ上限の管理対象から除くエンティティ)を名前で参照するために取り込む
using IncidentInsight.Web.Models;
// DbContextOptionsBuilder / UseInMemoryDatabase を使うために取り込む
using Microsoft.EntityFrameworkCore;
// IModel / IProperty(EF Core のモデル定義を読む型)を使うために取り込む
using Microsoft.EntityFrameworkCore.Metadata;
// [MaxLength] / [StringLength] / [Length] を読み取るために取り込む
using System.ComponentModel.DataAnnotations;
// PropertyInfo / BindingFlags(CLR プロパティの探索)を使うために取り込む
using System.Reflection;
// TheoryData(xUnit の [MemberData] へ渡すケース一覧)を使うために取り込む
using Xunit;

// テスト共通のヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// EF Core のモデルを読む検査が共通して使う土台。
///
/// <b>独立した 2 つの関心事</b>を扱う。名前に「Audited」と付いているが、後者を前者から導いてはいけない:
///   1. <b>監査対象</b>（PHI 分類・ラベル網羅）… 一覧は
///      <see cref="AuditSaveChangesInterceptor.AuditedEntities"/> が唯一の真実の源。
///   2. <b>長さ上限の管理対象</b>（<see cref="LengthGovernedEntityTypes"/> /
///      <see cref="LengthGovernanceExclusions"/> / <see cref="AppDeclaredStringColumnLengths"/>）…
///      監査対象**とは無関係に**、自アセンブリのマップ済みエンティティから導出する。
///
/// 2 を 1 から導くと、監査ポリシーの変更（あるエンティティを監査対象から外す）が無関係なはずの
/// 長さ管理まで黙って外す（すべて fail-open。CLAUDE.md §3）。同じ型に同居させているのは
/// EF のモデルの組み立てを 1 回で共有するためで、**関心事としては分けたまま**にすること。
///
/// 監査対象の一覧をテストが独自に持つと、監査対象を足したときに実装だけが増えて
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
        // 導出した監査対象をそのままケース一覧に詰め替える
        return ToTheoryData(ResolveAuditedClrTypes());
    }

    /// <summary>
    /// 型の一覧を xUnit の <c>[MemberData]</c> へ渡す形に詰め替える。
    /// 各テストクラスがこのループを書き写さないよう、ここ 1 か所に置く。
    /// </summary>
    public static TheoryData<Type> ToTheoryData(IEnumerable<Type> types)
    {
        // xUnit へ渡す入れ物を用意する
        var data = new TheoryData<Type>();

        // 渡された型を 1 つずつ積む
        foreach (var type in types)
        {
            // 1 ケース分として追加する
            data.Add(type);
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
    public static (IReadOnlyList<StringColumn> ClrBacked, IReadOnlyList<ShadowColumn> Shadow)
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
            .Where(IsStringColumn)
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

        // CLR プロパティを持たない列(= 属性を付けようがない列)。
        // 上限は持たせる —— 属性は付けられなくても fluent で長さは設定できるため、
        // 「裸の数値が設定されていないか」の検査は shadow 列にも掛ける必要がある
        var shadow = columns
            .Where(c => c.Property == null)
            .Select(c => new ShadowColumn(c.Name, c.MaxLength))
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
    /// 文字数上限の管理対象となる業務エンティティを EF のモデルから導出して返す。
    ///
    /// **監査対象の一覧から導出しない**のが要点。「どのエンティティを監査するか」と
    /// 「どのエンティティの列長を管理するか」は別の関心事で、前者から後者を導くと
    /// 監査ポリシーの変更（あるエンティティを監査対象から外す）が、無関係なはずの
    /// 長さ管理まで黙って外してしまう —— 裸の <c>[MaxLength(200)]</c> も、上限の付け忘れも、
    /// 値変換した列の切り詰めも、まとめて素通りするようになる（すべて fail-open）。
    ///
    /// 代わりに「自分たちのアセンブリで定義された、マップ済みのエンティティ」を条件にする。
    /// こうすると新しいエンティティは何もしなくても検査対象に入る（列挙を書き写さない）。
    ///
    /// 条件を**名前空間の完全一致から所属アセンブリへ変えてある**のが要点。
    /// 以前は <c>t.Namespace == "IncidentInsight.Web.Models"</c> という文字列の一致で絞っていたが、
    /// この repo は既に <c>Models/Enums</c> / <c>Models/Auditing</c> / <c>Models/Validation</c> 等の
    /// サブフォルダを持っており、エンティティを 1 つサブフォルダへ移すだけで名前空間が変わって
    /// 一致しなくなる。そうなるとそのエンティティは長さ上限に関する検査**すべて**
    /// （裸の数値の禁止・上限の付け忘れ・値変換列の切り詰め・その網羅ガード）から
    /// 同時に、しかも黙って外れる —— 実測でも「あるエンティティが導出集合から外れ、
    /// 同時にその列の上限が消える」変異が全件緑のまま通った（唯一の痕跡はテスト件数が
    /// 496 → 490 に減ることだけで、これは正当なリファクタと見分けが付かない）。
    /// アセンブリ単位なら、名前空間をどう切り直しても対象から外れない。
    ///
    /// エンティティ単位の除外は <see cref="LengthGovernanceExclusions"/>（理由付きの表）だけが決める。
    /// この表の中身をここに書き写さない（写した瞬間に、除外を足したときこの説明だけが古くなる）。
    /// 除外の綴りが EF のモデル上に実在することは
    /// <c>FieldLengthsTests.LengthGovernanceExclusions_AreAllStillReal</c> が固定する
    /// （このメソッド自身は確認しない。両方に置くと同じ検査が 2 か所に散る）。
    ///
    /// **<c>ApplicationUser</c> はエンティティごと除外しない。** 列長を Identity が決めるのは
    /// Identity 自身が宣言した列（<c>UserName</c> / <c>Email</c> など）だけで、
    /// <c>DisplayName</c> / <c>Department</c> はこのリポジトリが足した業務列だから。
    /// 型ごと外すと、この 2 列が長さ管理から永久に外れる（実際 <c>DisplayName</c> は個人名、
    /// <c>Department</c> は <c>Incident.Department</c> と同じ語彙なのに上限が無かった）。
    /// 代わりに<b>列単位</b>で「自分たちが宣言した列か」を見る（<see cref="AppDeclaredStringColumnLengths"/>）。
    ///
    /// この導出が正しく効いているかは <c>FieldLengthsTests.LengthGovernedTypes_CoverEveryOwnedDbSet</c>
    /// が**独立な手がかり**（<c>ApplicationDbContext</c> の <c>DbSet&lt;T&gt;</c> 宣言と、
    /// 基底の総称 DbContext へ渡した自アセンブリの型引数）で照合する。
    /// </summary>
    public static IReadOnlyList<Type> LengthGovernedEntityTypes()
    {
        // マップ済みエンティティのうち、自分たちのアセンブリで定義されたものを集めて返す
        return Model.Value.GetEntityTypes()
            .Select(e => e.ClrType)
            // Identity の内部エンティティ(AspNetRoles 等)は別アセンブリなのでここで落ちる
            .Where(IsOwnAssemblyType)
            // 意図的に外している型(現在は AuditLog のみ。理由は LengthGovernanceExclusions)を除く
            .Where(t => !LengthGovernanceExclusions.ContainsKey(ExclusionKeyFor(t)))
            // 同じ CLR 型が複数のエンティティ型にマップされることがある(所有型を 2 つの所有者に
            // 置く / shared-type entity type)。GetEntityTypes はエンティティ型ごとに 1 件返すので、
            // ここで畳まないと [MemberData] に同じ型のケースが 2 つ並ぶ(TheoryData は畳まない)
            .Distinct()
            // 実行ごとに順序が揺れないよう型名で並べる
            .OrderBy(t => t.Name, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// 長さ上限の管理対象から意図的に外している型と、その理由。
    ///
    /// **この表が「意図的な除外」の唯一の真実の源**で、導出（<see cref="LengthGovernedEntityTypes"/>）と
    /// 網羅ガード（<c>FieldLengthsTests.LengthGovernedTypes_CoverEveryOwnedDbSet</c>）と
    /// 属性側の対象導出（<c>FieldLengthsTests.GovernedTypes</c>）の 3 つが同じここを読む。
    ///
    /// 以前は導出側が <c>nameof(AuditLog)</c> をローカル定数で持ち、ガード側が別の表を持つ
    /// 写しの形だった。その形だとどちらへ除外を足しても片方が取り残される —— 実測でも、
    /// ガード側の表にだけ <c>CauseCategory</c> を登録するとモデル側 3 検査は除外せずに走り、
    /// 「除外したはずの型」で検査が落ちた（逆に導出側だけへ足すと、ガードが
    /// 「導出条件がずれている」という**誤った原因**を指して落ちる）。
    ///
    /// 理由を必須にしているのは <c>[NotPhi("理由")]</c> と同じ考え方で、
    /// 「とりあえず検出網を黙らせる」使い方を残さないため。
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> LengthGovernanceExclusions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // キーは**完全修飾名**。単純名で持つと、将来同じ単純名のエンティティ
            // (Models.Reporting.AuditLog のような集計用テーブル)を足したときに、
            // それも巻き添えで 4 検査すべてから外れる —— しかも綴りの検査は同じ単純名で
            // 突き合わせるため緑のまま。typeof(...).FullName で引くので綴りは手で書かない
            [typeof(AuditLog).FullName!] = "列長の出所が監査証跡スキーマで、業務入力の上限(FieldLengths)ではないため",
        };

    /// <summary>
    /// 除外表を引くためのキー（完全修飾名）を返す。引き方を各所で書き写さないためのヘルパー。
    /// </summary>
    public static string ExclusionKeyFor(Type type) => type.FullName ?? type.Name;

    /// <summary>
    /// 長さ上限の管理対象エンティティを xUnit の <c>[MemberData]</c> へ渡す形にして返す。
    ///
    /// 長さ上限の検査は 3 つのテストクラス（<c>FieldLengthsTests</c> /
    /// <c>FreeTextMaxLengthAttributeTests</c> / <c>ConvertedEnumColumnLengthTests</c>）に分かれており、
    /// 以前はそれぞれが同じ詰め替えを書き写していた。監査対象側に
    /// <see cref="AuditedEntityTheoryData"/> を用意したのと同じ理由（どれか 1 箇所に絞り込みを
    /// 足すと、そのクラスの検出網だけが黙って狭くなる）がこちらにも当てはまるので、
    /// ケース一覧の作り方をここ 1 か所に置く。
    /// </summary>
    public static TheoryData<Type> LengthGovernedTheoryData()
    {
        // 導出した長さ管理対象をそのままケース一覧に詰め替える
        return ToTheoryData(LengthGovernedEntityTypes());
    }

    /// <summary>
    /// 長さ上限の検査に掛ける「自分たちが宣言した」文字列列を、列名と上限の組で返す。
    ///
    /// CLR プロパティを持つ列と shadow 列の両方を対象にするが、<b>基底クラスが宣言した列は落とす</b>。
    /// <c>ApplicationUser</c> は <c>IdentityUser</c> を継承しており、<c>UserName</c> /
    /// <c>Email</c> / <c>PasswordHash</c> などの列長は ASP.NET Core Identity が決める
    /// （<c>FieldLengths</c> の定数を当てはめる対象ではない）。一方
    /// <c>DisplayName</c> / <c>Department</c> はこのリポジトリが足した業務列なので管理対象。
    ///
    /// 「エンティティごと外す」のではなく列単位で切るのが要点。型ごと外すと、その型に足した
    /// 業務列まで巻き添えで長さ管理から外れる（すべて fail-open）。
    ///
    /// shadow property（CLR プロパティを持たない列）は<b>残す</b>。宣言元をたどれないが、
    /// これは自分たちの <c>OnModelCreating</c> か EF の規約が作った列であり、
    /// 上限の検査は属性を読まないので対象にできる。
    ///
    /// <b>既知のトレードオフ</b>: <c>ApplicationUser</c> だけは基底の
    /// <c>base.OnModelCreating</c>（ASP.NET Core Identity）も列を構成するため、
    /// 「shadow 列＝自分たちのモデル由来」という前提が唯一崩れうる。将来 Identity が
    /// 上限の無い shadow の文字列列をユーザーエンティティへ足すと、
    /// <c>PersistedStringColumns_MustHaveMaxLength</c> が「自分たちには直せない列に
    /// <c>FieldLengths</c> の定数を付けろ」という実行不能な指示を出す。
    ///
    /// 現時点でそのような列は 1 つも無いため、先回りの仕組みは入れていない（§6 の
    /// 「将来を見越した過度な抽象化を避ける」）。実際に起きたときの正しい対処は
    /// <b>列単位の除外を足す</b>ことで、<see cref="LengthGovernanceExclusions"/>（エンティティ単位）
    /// で <c>ApplicationUser</c> ごと外してはいけない —— それをやると
    /// <c>DisplayName</c> / <c>Department</c> がまた長さ管理から落ちる。
    /// </summary>
    public static IReadOnlyList<(string Name, int? MaxLength, bool IsClrString)>
        AppDeclaredStringColumnLengths(Type entityType)
    {
        // CLR プロパティを持つ列と shadow 列に分けて取り出す
        var (clrBacked, shadow) = PartitionStringColumns(entityType);

        // CLR プロパティを持つ列のうち、自分たちが宣言したものだけを残す。
        // IsClrString は「CLR の型が string か」で、値変換した enum 列と区別するために持つ
        // (件数を突き合わせる前提確認が、種類の違う列を数え合わせないようにするため)
        return clrBacked
            .Where(c => IsDeclaredInOwnAssembly(c.Property))
            .Select(c => (c.Name, c.MaxLength, c.Property.PropertyType == typeof(string)))
            // shadow 列は宣言元をたどれないが自分たちのモデル由来なので残す。
            // CLR プロパティが無いので IsClrString は false
            .Concat(shadow.Select(c => (c.Name, c.MaxLength, false)))
            .ToList();
    }

    /// <summary>
    /// そのプロパティを「自分たちが宣言したもの」とみなすかを返す（宣言元の型が自アセンブリか）。
    ///
    /// **列だけに使う判定ではない**。用途は 2 つある:
    ///   - エンティティの列を絞る（<c>ApplicationUser</c> の <c>UserName</c> など、
    ///     ASP.NET Core Identity が宣言した列を長さ管理から外す）
    ///   - ViewModel / DTO のプロパティを絞る（基底クラスが宣言した入力欄を対象外にする）
    /// EF のモデルを参照しないのは意図的で、モデルに載らない型（ViewModel）にも同じ判定を
    /// 使うため。ここに「EF のモデルにある列か」を足すと、属性側の 3 検査が黙って
    /// エンティティだけに狭まり、ViewModel の裸の数値を見逃すようになる。
    ///
    /// 判定を 1 か所に置くのは、この絞り込みを使う検査が複数あるため。各検査が
    /// <c>DeclaringType?.Assembly == …</c> を書き写すと、条件を直したときに片方だけが
    /// 取り残されて対象が食い違う。
    /// </summary>
    public static bool IsDeclaredInOwnAssembly(PropertyInfo property)
    {
        // 宣言元の型が自分たちのアセンブリにあれば自前の宣言
        return property.DeclaringType != null && IsOwnAssemblyType(property.DeclaringType);
    }

    /// <summary>
    /// 指定エンティティの「長さ上限が設定されている、自分たちが宣言した列」を返す。
    ///
    /// <see cref="AppDeclaredStringColumnLengths"/> との違いは<b>文字列列に限らない</b>点。
    /// 属性側の裸の数値の検査は <c>byte[]</c> や値変換した enum 列まで見るのに、モデル側が
    /// 文字列列しか見ないと、その差分がそのまま死角になる —— 実測でも
    /// <c>byte[]</c> の列へ fluent で <c>HasMaxLength(300)</c> と書くと、裸の 300 も
    /// 属性との食い違いも 4 つの検査すべてを素通りした（fluent が抜け道になる形そのもの）。
    ///
    /// 「上限が設定されている列」だけを返すので、上限を持たない列（<c>int</c> や
    /// <c>DateTime</c>）を巻き込むことはない。上限の<b>付け忘れ</b>は文字列列に対してだけ
    /// 意味があるので、そちらは <see cref="AppDeclaredStringColumnLengths"/> が担う。
    /// </summary>
    public static IReadOnlyList<(string Name, int MaxLength, PropertyInfo? Property)>
        AppDeclaredColumnsWithLength(Type entityType)
    {
        // EF のモデルから対象エンティティの定義を引く
        var entity = Model.Value.FindEntityType(entityType);

        // モデルに載っていない型は対象外(呼び出し側はマップ済みの型だけを渡す)
        if (entity is null) return Array.Empty<(string, int, PropertyInfo?)>();

        // 主キー以外で長さ上限が設定されている列を集める
        return entity.GetProperties()
            .Where(p => !p.IsPrimaryKey())
            .Where(p => p.GetMaxLength() != null)
            .Select(p => (Name: p.Name, MaxLength: p.GetMaxLength()!.Value, Property: FindClrProperty(entityType, p.Name)))
            // 基底クラスが宣言した列は対象外(上限を決めているのが自分たちではない)。
            // shadow 列は宣言元をたどれないが自分たちのモデル由来なので残す
            .Where(c => c.Property == null || IsDeclaredInOwnAssembly(c.Property))
            .ToList();
    }

    /// <summary>
    /// その CLR プロパティが「EF のモデル上で文字列として保存される列」かを返す。
    ///
    /// 「値変換して文字列として保存する enum 列」だけに許す緩和を、宣言型ではなく
    /// <b>プロパティそのもの</b>で判定するために使う。宣言型がマップ済みエンティティかどうかで
    /// 見ると、同じ型にある <c>[NotMapped]</c> の enum プロパティや、既定の int マッピングのまま
    /// 文字列として保存されない enum 列にも緩和が届いてしまう。
    /// </summary>
    public static bool IsStringPersistedColumn(PropertyInfo property)
    {
        // 宣言型が分からなければ判定できない
        var declaringType = property.DeclaringType;
        if (declaringType is null) return false;

        // 宣言型が EF のモデルに載っていなければ列ではない(ViewModel など)
        var entity = Model.Value.FindEntityType(declaringType);
        if (entity is null) return false;

        // 同名の列を引き、文字列として保存されるかを共有の判定に委ねる
        var efProperty = entity.FindProperty(property.Name);
        return efProperty != null && IsStringColumn(efProperty);
    }

    /// <summary>
    /// そのエンティティが宣言する「マップ済み・主キー以外・自前・CLR 型が <c>string</c>」の
    /// プロパティ数を返す。
    ///
    /// <see cref="AppDeclaredStringColumnLengths"/> が 0 件を返したときに、それが
    /// 「そもそも対象の列を持たない正当な型」なのか「検出網が対象を拾えなくなった」のかを
    /// 見分けるための<b>独立な手がかり</b>。
    ///
    /// 独立させる相手は 2 つあり、どちらも<b>あえて共有しない</b>:
    ///   - <see cref="IsStringColumn"/> … CLR の型が <c>string</c> かどうかで判定する
    ///   - <see cref="IsDeclaredInOwnAssembly"/> … 宣言元アセンブリをここで直接比べる
    ///
    /// 後者が要点。守る対象と同じ述語を通すと、その 1 つを狭めた瞬間にガードも一緒に狭まって
    /// 発火しなくなる —— 実測でも、<c>IsDeclaredInOwnAssembly</c> へ「Identity 由来の列を外す」
    /// という一見リファクタに見える条件を足し、同時に <c>ApplicationUser</c> の
    /// <c>[MaxLength]</c> を消すと、506 → 504 で<b>全件緑のまま</b>通った
    /// （この PR が塞いだ穴が、テスト件数が 2 減るだけの痕跡で開き直る）。
    ///
    /// 主キーと未マップ（<c>[NotMapped]</c> / 計算プロパティ）を除くのが要点。
    /// 単純に「自前の <c>string</c> プロパティがあるか」で見ると、文字列を主キーにしたマスタ型や
    /// 計算プロパティしか持たない型に対して「条件が実装とずれている」という<b>誤った原因</b>で
    /// 落ちる —— 直しようがないので、いずれ検査を緩める方向へ倒れる。
    /// </summary>
    public static int OwnDeclaredMappedStringPropertyCount(Type entityType)
    {
        // EF のモデルから対象エンティティの定義を引く
        var entity = Model.Value.FindEntityType(entityType);

        // モデルに載っていなければ数えようがないので 0
        if (entity is null) return 0;

        // ガードが守る対象と同じアセンブリ(綴りを書かずモデルの型から引く)。
        // IsDeclaredInOwnAssembly をあえて呼ばない理由は上のコメントを参照
        var ownAssembly = typeof(Incident).Assembly;

        // マップ済み・主キー以外の列のうち、自前で宣言した string プロパティを数える
        return entity.GetProperties()
            .Where(p => !p.IsPrimaryKey())
            .Select(p => FindClrProperty(entityType, p.Name))
            .Count(pi => pi != null
                         && pi.PropertyType == typeof(string)
                         && pi.DeclaringType?.Assembly == ownAssembly);
    }

    /// <summary>
    /// そのプロパティに付いた「長さ上限を表す属性」を<b>すべて</b>読み取り、
    /// 上限値・エラーメッセージ・属性名の組で返す（無ければ空）。
    ///
    /// <b>長さ上限の属性は <c>[MaxLength]</c> だけではない。</b>
    /// <c>[StringLength]</c> と .NET 8 の <c>[Length(min, max)]</c> も MVC の入力検証が尊重し、
    /// <c>[StringLength]</c> は EF Core の列長にもなる。<c>[MaxLength]</c> だけを見ると
    /// <b>綴りを変えるだけの抜け道</b>になり、実測でも ViewModel に <c>[StringLength(200)]</c> /
    /// <c>[Length(1, 200)]</c> を書くと全件緑のまま通った（後者はテスト件数すら変わらない）。
    ///
    /// <b>最初の 1 つで打ち切らない。</b> 1 つのプロパティに複数の長さ属性を並べられるため、
    /// 正しい <c>[MaxLength]</c> の横に裸の <c>[StringLength]</c> を足すだけで 2 つ目が視界から外れる
    /// —— MVC は両方の validator を走らせるので実効上限は小さい方になる。
    ///
    /// <c>inherit: true</c> で読むのは、基底クラスで宣言し派生側で <c>override</c> した列を
    /// 「属性なし」と誤判定しないため（誤判定すると fluent の <c>HasMaxLength()</c> との
    /// 食い違いが黙って素通りする）。
    ///
    /// 解釈をここ 1 か所に集約するのが要点で、DataAnnotations に長さ上限の属性が増えたら
    /// ここへ足す（名前空間・型名の接尾辞への依存をやめたのと同じ理由で、属性名への依存も残さない）。
    /// </summary>
    public static IReadOnlyList<(int Length, string? ErrorMessage, string AttributeName)>
        ReadLengthLimits(PropertyInfo property)
    {
        // 見つけた上限を溜めるリスト
        var limits = new List<(int, string?, string)>();

        // [MaxLength] … 上限だけを表す。この repo の標準の綴り
        foreach (var attribute in property.GetCustomAttributes<MaxLengthAttribute>(inherit: true))
        {
            // 上限値とメッセージを積む
            limits.Add((attribute.Length, attribute.ErrorMessage, nameof(MaxLengthAttribute)));
        }

        // [StringLength] … 最大長を上限として扱う(最小長はこの検査の関心事ではない)
        foreach (var attribute in property.GetCustomAttributes<StringLengthAttribute>(inherit: true))
        {
            // 最大長とメッセージを積む
            limits.Add((attribute.MaximumLength, attribute.ErrorMessage, nameof(StringLengthAttribute)));
        }

        // [Length(min, max)] … .NET 8 で追加。こちらも最大長を上限として扱う
        foreach (var attribute in property.GetCustomAttributes<LengthAttribute>(inherit: true))
        {
            // 最大長とメッセージを積む
            limits.Add((attribute.MaximumLength, attribute.ErrorMessage, nameof(LengthAttribute)));
        }

        // 見つかった上限をすべて返す
        return limits;
    }

    /// <summary>
    /// その型が自分たちのアセンブリ（<c>IncidentInsight.Web</c>）で定義されているかを返す。
    ///
    /// <see cref="IsDeclaredInOwnAssembly"/> と同じ理由で 1 か所に置く。以前はこの述語が
    /// 導出・DbSet の絞り込み・基底型引数の絞り込み・除外の実在検査の 4 箇所へ直書きされていた。
    /// 将来この条件を変える（業務エンティティを 2 つ目のアセンブリへ切り出す等）ときに
    /// 導出だけ広げてガードを直し忘れると、網羅ガードが新しいエンティティを見なくなり
    /// 「取りこぼしゼロ＝緑」のまま無力化される。
    /// </summary>
    public static bool IsOwnAssemblyType(Type type)
    {
        // 定義元アセンブリが DbContext と同じなら自前の型
        return type.Assembly == typeof(ApplicationDbContext).Assembly;
    }

    /// <summary>
    /// 組み立て済みの EF モデル。検査ごとに DbContext を作り直さないよう共有する
    /// (作り直すと InMemory のストアがプロセス内キャッシュへ溜まり続ける)。
    /// </summary>
    public static IModel EfModel => Model.Value;

    /// <summary>
    /// その型が EF のモデルにエンティティとして載っているかを返す。
    /// ViewModel のようにモデルを持たない型を <see cref="PartitionStringColumns"/> へ渡すと
    /// fail-closed で落ちるため、モデル側の検査に掛ける型を選り分けるのに使う。
    /// </summary>
    public static bool IsMappedEntity(Type type)
    {
        // モデルに載っていれば true
        return Model.Value.FindEntityType(type) != null;
    }

    /// <summary>
    /// <see cref="PartitionStringColumns"/> のうち CLR プロパティを持たない列名だけを返す薄い射影。
    /// </summary>
    public static IReadOnlyList<string> ShadowStringColumnNames(Type entityType)
    {
        // 分割済みの結果から shadow property 側の列名だけを返す
        return PartitionStringColumns(entityType).Shadow.Select(c => c.Name).ToList();
    }

    /// <summary>
    /// 「文字列として保存される」列 1 つぶんの情報。
    /// <paramref name="MaxLength"/> は EF のモデルが持つ長さ上限で、<c>null</c> なら上限なし。
    /// </summary>
    /// <param name="Name">EF のモデル上の列名</param>
    /// <param name="Property">列に対応する CLR プロパティ(属性はここから読む)</param>
    /// <param name="MaxLength">EF のモデルに設定された長さ上限(未設定なら null)</param>
    public sealed record StringColumn(string Name, PropertyInfo Property, int? MaxLength);

    /// <summary>
    /// CLR プロパティを持たない文字列列(shadow property)1 つぶんの情報。
    /// 属性は付けられないが、fluent で長さ上限だけは設定できるので保持する。
    /// </summary>
    /// <param name="Name">EF のモデル上の列名</param>
    /// <param name="MaxLength">EF のモデルに設定された長さ上限(未設定なら null)</param>
    public sealed record ShadowColumn(string Name, int? MaxLength);

    // その列を検査対象の「文字列列」とみなすかを判定する。
    // 同じ規則を各検査が書き写すと、規則を直したときに片方だけが取り残されて黙って対象が
    // 狭くなるため、外からもここを呼ぶ(可視性の都合だけの別名は置かない)。
    //
    // CLR の型が string かどうかだけでは足りない: HasConversion<string>() を通した列
    // (Incident.Severity / IncidentType, PreventiveMeasure.Status / MeasureType など)は
    // ClrType が enum のままなので「string 列ではない」と誤判定され、検出網から丸ごと外れる。
    // 判定を「DB に文字列として入るか」に置くことで、将来 HasConversion<string>() で保存する
    // 自由記述の値オブジェクトを足しても、分類と長さ上限の検査が自動で追随する
    public static bool IsStringColumn(IProperty property)
    {
        // (a) CLR の型が string —— これが本命。インターセプタの SerializeChanges が ChangesJson へ
        //     書くのは prop.CurrentValue / prop.OriginalValue、すなわち**変換前の CLR 側の値**
        //     だから、PHI が漏れるかどうかは CLR の型に付いて回る。
        //     たとえば自由記述列に暗号化の値変換(string → byte[])を足すと「DB へは文字列として
        //     保存されない」列になるが、ChangesJson へ流れるのは相変わらず平文の string。
        //     ここを変換後の型だけで判定すると、その列が検出網から丸ごと外れてしまう
        if (property.ClrType == typeof(string)) return true;

        // (b) DB へ文字列として保存される —— CLR が enum などでも、閉じた語彙かどうかの判断と
        //     列長の管理が要るので対象に入れる。変換後の型が現れる場所は書き方によって違う(実測):
        //       - HasConversion<string>()          → GetProviderClrType() が string
        //                                            (Severity / Status / MeasureType)
        //       - HasConversion(v => …, v => …)    → GetValueConverter() が string
        //                                            (IncidentType)
        //     片方だけを見ると、もう一方の書き方で保存される文字列列が丸ごと素通りする
        var storedType = property.GetProviderClrType() ?? property.GetValueConverter()?.ProviderClrType;

        // (a) と (b) の**和集合**にするのが要点。どちらか一方への置き換えにすると、
        //     置き換えで外れた側が「誰も見ていない列」になる
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
