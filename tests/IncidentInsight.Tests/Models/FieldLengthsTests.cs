// 文字数上限の唯一の真実の源(FieldLengths)を検証対象として取り込む
using IncidentInsight.Web.Models.Validation;
// 監査対象エンティティをインターセプタの宣言から導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// 網羅ガードが読む DbSet<T> の宣言元(ApplicationDbContext)を使うために取り込む
using IncidentInsight.Web.Data;
// DbSet<> 型そのものを判定に使うために取り込む
using Microsoft.EntityFrameworkCore;
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
    // [MaxLength] 属性側の検査対象となる型の一覧。
    //
    // **型名を書き並べない**のが要点。以前はエンティティを EF のモデルから導出する一方で、
    // ViewModel だけ 4 型を直書きしていた。その形だと Models/ViewModels へ新しい入力用
    // ViewModel を足し、そのプロパティに裸の [MaxLength(200)]（あるいは ErrorMessage 未指定の
    // [MaxLength]）を書いても、この検査も ViewModelMaxLength_UsesJapaneseSharedErrorMessage も
    // 対象に含めないため CI は緑のまま通る。結果として画面側の上限だけがエンティティ
    // （ShortText=100 等）とずれ、SQL Server / PostgreSQL 配備では保存時に列長超過
    // （未捕捉の DbUpdateException = HTTP 500）になり、日本語 UI に英語の既定検証メッセージが混ざる。
    // 「写しが取り残される」形そのものなので、条件を「[MaxLength] を 1 つでも宣言している型」に置く。
    //
    // 名前空間や型名の接尾辞（"ViewModel"）ではなく**属性の有無**を条件にしているので、
    // 置き場所を変えても、命名規約から外れた型を足しても、対象から外れない。
    private static IReadOnlyList<Type> GovernedTypes()
    {
        // 長さ上限の管理対象から意図的に外している型（理由は LengthGovernanceExclusions）
        var excluded = LengthGovernanceExclusions.Keys.ToHashSet(StringComparer.Ordinal);

        // 自分たちのアセンブリで [MaxLength] を 1 つでも宣言している型を集める
        return typeof(ApplicationDbContext).Assembly
            .GetTypes()
            // 意図的な除外(AuditLog は監査証跡スキーマ固有の列長)を外す
            .Where(t => !excluded.Contains(t.Name))
            // 自分たちが宣言したプロパティに [MaxLength] があるものだけを残す
            .Where(t => t.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(AuditedEntityModel.IsAppDeclaredColumn)
                .Any(p => p.GetCustomAttribute<MaxLengthAttribute>(inherit: false) != null))
            // 実行ごとに順序が揺れないよう型名で並べる
            .OrderBy(t => t.Name, StringComparer.Ordinal)
            .ToList();
    }

    public static TheoryData<Type> LengthGovernedTypes => AuditedEntityModel.ToTheoryData(GovernedTypes());

    // [MaxLength] 属性に書いてよい上限。利用者が入力する項目の上限だけを許す。
    //
    // ここに EnumCode / EnumCodeJapanese を混ぜてはいけない。混ぜると ViewModel の入力欄に
    // 裸の [MaxLength(20)] / [MaxLength(50)] を書いても「FieldLengths の定数だ」として通り、
    // 対応するエンティティ側の列は ShortText(100) のまま——FieldLengths が防ぐために作られた
    // 層またぎのずれがそのまま復活する(この 2 つは値変換した enum 列にしか意味を持たない)
    private static readonly int[] AttributeAllowedLengths =
    {
        FieldLengths.FreeText,
        FieldLengths.ShortText,
    };

    // EF のモデルに設定してよい上限。上に加えて、値変換した enum 列専用の 2 つを許す。
    // 属性側と意図的に別集合にしている(理由は上のコメント)。共有すると片方が黙って緩む
    private static readonly int[] ModelAllowedLengths = AttributeAllowedLengths
        .Concat(new[] { FieldLengths.EnumCode, FieldLengths.EnumCodeJapanese })
        .ToArray();

    // EF のモデル側の上限を検査する対象(= 長さ上限の管理対象となる業務エンティティ)。
    // ViewModel は EF のモデルを持たないので入らない
    public static TheoryData<Type> ModelBackedTypes => AuditedEntityModel.LengthGovernedTheoryData();

    [Theory]
    [MemberData(nameof(LengthGovernedTypes))]
    public void EveryMaxLength_UsesAFieldLengthsConstant(Type type)
    {
        // 属性に書いてよい上限の集合(ここに無い値は裸のマジックナンバーとみなす)
        var allowed = AttributeAllowedLengths;

        // 対象型の公開プロパティのうち [MaxLength] が付いているものを列挙する
        var offenders = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            // 基底クラス(Identity など)が宣言したプロパティは対象外。列長を決めているのが
            // 自分たちではない以上、FieldLengths の定数を当てはめる対象でもない
            .Where(AuditedEntityModel.IsAppDeclaredColumn)
            .Select(p => new { Property = p, Attribute = p.GetCustomAttribute<MaxLengthAttribute>(inherit: false) })
            .Where(x => x.Attribute != null)
            // 許容値のいずれとも一致しない上限を違反として拾う
            .Where(x => !allowed.Contains(x.Attribute!.Length))
            .Select(x => $"{type.Name}.{x.Property.Name} = {x.Attribute!.Length}")
            .ToList();

        // 違反ゼロであること(あればどのプロパティが裸の数値かをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "[MaxLength] に FieldLengths 以外の裸の数値が使われています " +
            $"(許容値: {string.Join(" / ", allowed)}): " + string.Join(", ", offenders));
    }

    [Theory]
    [MemberData(nameof(ModelBackedTypes))]
    public void EveryModelMaxLength_UsesAFieldLengthsConstant(Type entityType)
    {
        // モデルに設定してよい上限の集合(属性側 + 値変換した enum 列専用の 2 つ)
        var allowed = ModelAllowedLengths;

        // 上の EveryMaxLength_UsesAFieldLengthsConstant は CLR の [MaxLength] 属性しか見えない。
        // ところが FreeTextMaxLengthAttributeTests は上限の充足を EF のモデル(GetMaxLength())で
        // 判定するようになり、fluent の HasMaxLength() も「上限あり」として通るようになった。
        // 属性側だけを検査したままだと、その fluent 経路が裸の数値の抜け道になる
        // ——「長さ上限はある(緑)」「でもその値は FieldLengths 由来ではない(誰も見ていない)」。
        // エスケープハッチを足したぶん検出網が狭くなるのを防ぐため、モデル側の値も同じ集合で見る
        // CLR プロパティの有無を問わず全 string 列を見る。属性を読まない検査なので shadow 列も
        // 対象にできる —— ClrBacked に絞ると、fluent で裸の数値を設定した shadow 列が
        // 「属性を付けられないから対象外」という無関係な理由で素通りする
        var offenders = AuditedEntityModel.AppDeclaredStringColumnLengths(entityType)
            // 上限が設定されている列だけが対象(未設定は FreeTextMaxLengthAttributeTests が落とす)
            .Where(c => c.MaxLength != null)
            // 許容値のいずれとも一致しない上限を違反として拾う
            .Where(c => !allowed.Contains(c.MaxLength!.Value))
            .Select(c => $"{entityType.Name}.{c.Name} = {c.MaxLength}")
            .ToList();

        // 違反ゼロであること(あればどの列が裸の数値かをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "EF のモデルに FieldLengths 以外の裸の数値が長さ上限として設定されています " +
            $"(許容値: {string.Join(" / ", allowed)}): " + string.Join(", ", offenders));
    }

    [Theory]
    [MemberData(nameof(ModelBackedTypes))]
    public void ModelMaxLength_AgreesWithMaxLengthAttribute(Type entityType)
    {
        // 属性と EF のモデルの両方に上限があり、しかも値が食い違う列を探す
        var offenders = AuditedEntityModel.ClrBackedStringColumns(entityType)
            // 基底クラス(Identity など)が宣言した列は対象外(上限を決めているのが自分たちではない)
            .Where(c => AuditedEntityModel.IsAppDeclaredColumn(c.Property))
            // 属性側の上限(無ければ検査対象外 —— 付け忘れは別の検査が落とす)
            .Select(c => new
            {
                c.Name,
                c.MaxLength,
                Attribute = c.Property.GetCustomAttribute<MaxLengthAttribute>(inherit: true),
            })
            .Where(x => x.Attribute != null && x.MaxLength != null)
            // 値が一致しないものが違反
            .Where(x => x.Attribute!.Length != x.MaxLength!.Value)
            .Select(x => $"{entityType.Name}.{x.Name}: [MaxLength]={x.Attribute!.Length} / モデル={x.MaxLength}")
            .ToList();

        // fluent の HasMaxLength() は属性より優先されるため、両方書いて値が違うと
        // 「画面は属性の上限で検証し、DB は fluent の上限で作られる」という層またぎのずれになる。
        // 上限の**充足**を EF のモデルで判定するようにした以上、モデル側だけを見ても
        // 食い違いには気付けない(どちらも「上限あり」なので緑のまま)。ここで一致を固定する
        Assert.True(offenders.Count == 0,
            "同じ列に [MaxLength] と fluent の HasMaxLength() があり、値が食い違っています " +
            "(fluent が優先されるため、画面の検証は通るのに保存時に列長超過で落ちます): "
            + string.Join(", ", offenders));
    }

    [Theory]
    [MemberData(nameof(LengthGovernedTypes))]
    public void ViewModelMaxLength_UsesJapaneseSharedErrorMessage(Type type)
    {
        // 入力用の型だけが画面へエラーメッセージを出す。エンティティ側の [MaxLength] は
        // EF Core の列長定義にしか使われず、メッセージが利用者に見えないため検査対象外にする。
        //
        // 判定を型名の接尾辞("ViewModel")ではなく**EF のモデルに載っているか**で行うのが要点。
        // 対象の導出(GovernedTypes)は「[MaxLength] を宣言している型」へ広げてあるのに、ここだけ
        // 接尾辞で絞ると導出だけが広がって検査が広がらない —— 実測でも、Models/ViewModels へ
        // 接尾辞の無い MeasureForm を足して ErrorMessage 無しの [MaxLength] を書くと全件緑で通り、
        // 日本語 UI に英語の既定メッセージ("The field ... maximum length of '500'.")が混ざった。
        // 「エンティティか、画面へ出す入力用の型か」を分けたいのだから、命名規約ではなく
        // モデルに載っているかどうかで切る
        if (AuditedEntityModel.IsMappedEntity(type)) return;

        // [MaxLength] が付いた公開プロパティのうち、共通の日本語書式を使っていないものを拾う。
        // 既定のメッセージは英語("The field ... maximum length of '500'.")のため、
        // 指定漏れがあると日本語 UI に英文の検証エラーが混ざる(CLAUDE.md §1)
        var offenders = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            // 基底クラスが宣言したプロパティは対象外(自分たちが書いた文言ではない)
            .Where(AuditedEntityModel.IsAppDeclaredColumn)
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

    // 長さ上限の管理対象から意図的に外している型と理由。導出・網羅ガード・属性側の対象導出の
    // 3 つが同じ表を読むよう、唯一の真実の源である AuditedEntityModel 側を参照する
    // (ここに写しを置くと、どちらへ除外を足しても片方が取り残される)
    private static IReadOnlyDictionary<string, string> LengthGovernanceExclusions =>
        AuditedEntityModel.LengthGovernanceExclusions;

    [Fact]
    public void LengthGovernedTypes_CoverEveryOwnedDbSet()
    {
        // 長さ上限の検査は 4 つ(裸の数値の禁止・上限の付け忘れ・値変換列の切り詰め・
        // その網羅ガード)あるが、対象範囲はすべて
        // AuditedEntityModel.LengthGovernedEntityTypes() の 1 か所が決めている。
        // つまりこの導出が 1 つでもエンティティを取りこぼした瞬間、そのエンティティは
        // 4 つの検査から**同時に、しかも黙って**外れる(すべて fail-open)。
        //
        // 実測: あるエンティティが導出集合から外れ、同時にその列の [MaxLength] が消える変異は
        // 全件緑のまま通った。唯一の痕跡はテスト件数が 496 → 490 に減ることだけで、
        // これは正当なリファクタと見分けが付かない。
        //
        // そこで「管理対象であるべきエンティティ」を導出とは**独立した手がかり**で求める。
        // 導出側は「EF のモデル上のエンティティを所属アセンブリで絞る」経路なので、
        // ここでは別の宣言箇所である ApplicationDbContext の DbSet<T> 宣言を読む。
        // 同じ経路でガードを書くと、導出が狭まったときにガードも一緒に狭まり、
        // 「取りこぼしゼロ = 緑」として無力化される(この repo が各所で避けている形)。
        // 手がかり (a): ApplicationDbContext が**自分で宣言した** DbSet<T>。
        // DeclaredOnly を付けるのは、基底の IdentityDbContext が宣言する DbSet(Users / Roles など)
        // をまとめて拾うと、Identity が列長を決める型まで業務エンティティと取り違えるため
        var declaredDbSetTypes = OwnDbContextTypes()
            .SelectMany(t => t.GetProperties(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            // DbSet<T> 型のプロパティだけを拾う
            .Where(p => p.PropertyType.IsGenericType
                        && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
            // 型引数 T(= エンティティの CLR 型)を取り出す
            .Select(p => p.PropertyType.GetGenericArguments()[0])
            // ここで確定させる。遅延のままだと下の前提確認と ownedEntityTypes が
            // それぞれ独立に走査を回し、「前提を確認した列」と「実際に使う列」が別の値になる
            .Distinct()
            .ToList();

        // 手がかり (b): 基底の総称 DbContext へ**自分たちが渡した型引数**
        // (IdentityDbContext<ApplicationUser> の ApplicationUser など)。
        //
        // (a) だけでは足りない。ApplicationUser は Identity 側の DbSet(Users)で公開されるため
        // DeclaredOnly に掛からず、本 PR で唯一新たに管理対象へ入れた型なのにガードの視界の外だった。
        // 実測でも、導出へ IdentityUser 派生の除外を戻すと ApplicationUser が長さ関連 4 検査から
        // 同時に消えるのに 504 → 500 で全件緑のまま通った(痕跡はテスト件数の減少だけ)。
        // 「自分たちが型引数として名指しした自アセンブリの型」は、DbSet の宣言と同じく
        // 導出とは独立した宣言箇所なので、手がかりとして加える
        var identityUserTypes = OwnDbContextBaseTypeArguments();

        // 2 つの手がかりを合わせたものが「管理対象であるべき」型の下限
        var ownedEntityTypes = declaredDbSetTypes.Concat(identityUserTypes).Distinct().ToList();

        // 手がかりが 1 つも読めないのは前提が崩れた状態(リフレクションの条件が古い)なので落とす。
        // ここを素通りさせると「見るべき対象ゼロ = 緑」でガード自体が無力化される
        Assert.True(declaredDbSetTypes.Count > 0,
            "ApplicationDbContext から DbSet<T> の宣言を 1 つも読み取れませんでした。" +
            "このガードが対象を取得する条件が実装とずれています(このままでは常に緑になります)。");
        Assert.True(identityUserTypes.Count > 0,
            "ApplicationDbContext の基底へ渡した自アセンブリの型引数(ApplicationUser など)を " +
            "1 つも読み取れませんでした。このガードが対象を取得する条件が実装とずれています。");

        // 現在の導出結果(検査対象になっているエンティティ)
        var governed = AuditedEntityModel.LengthGovernedEntityTypes();

        // DbSet で公開しているのに、管理対象でも「意図的な除外」でもないエンティティを拾う
        var missing = ownedEntityTypes
            .Where(t => !governed.Contains(t))
            .Where(t => !LengthGovernanceExclusions.ContainsKey(t.Name))
            .Select(t => t.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // 取りこぼしが 1 件も無いことを確認する(fail-closed)
        Assert.True(missing.Count == 0,
            "DbSet で公開している業務エンティティが、長さ上限の管理対象から外れています: " +
            string.Join(", ", missing) +
            "。AuditedEntityModel.LengthGovernedEntityTypes() の導出条件(所属アセンブリ)が " +
            "実装とずれている可能性があります —— このままだと裸の [MaxLength]・上限の付け忘れ・" +
            "値変換列の切り詰めの検査が、そのエンティティについて黙って効かなくなります。" +
            "意図的に外すなら LengthGovernanceExclusions へ理由付きで登録してください。");
    }

    /// <summary>
    /// <c>ApplicationDbContext</c> が基底の総称 DbContext へ渡した型引数のうち、
    /// 自分たちのアセンブリで定義された型を返す（<c>IdentityDbContext&lt;ApplicationUser&gt;</c> の
    /// <c>ApplicationUser</c> など）。
    ///
    /// これも「自分たちが名指しした宣言」なので、導出（EF のモデルをアセンブリで絞る経路）とは
    /// 独立した手がかりになる。Identity 側の型引数（<c>IdentityRole</c> 等）は別アセンブリなので落ちる。
    /// </summary>
    private static IReadOnlyList<Type> OwnDbContextBaseTypeArguments()
    {
        // 自分たちのアセンブリ(綴りを書かず DbContext の所属から引く)
        var ownAssembly = typeof(ApplicationDbContext).Assembly;

        // 見つけた型引数を溜めるリスト
        var found = new List<Type>();

        // ApplicationDbContext から基底へ 1 つずつさかのぼる
        for (var type = typeof(ApplicationDbContext); type != null; type = type.BaseType)
        {
            // 総称でない基底には型引数が無いので読み飛ばす
            if (!type.IsGenericType) continue;

            // 型引数のうち自分たちのアセンブリのものだけを積む
            found.AddRange(type.GetGenericArguments().Where(a => a.Assembly == ownAssembly));
        }

        // マップ済みエンティティに限る。型引数には EF のエンティティでないものも来うるため
        // (自己参照する総称基底 AppContextBase<ApplicationDbContext> や、宣言だけして
        // まだマップしていないロール型など)。絞らないとそれが「管理対象であるべき型」に混ざり、
        // 導出は EF のモデルを読むので当然含まれず、ガードが
        // 「導出条件がずれている」という**誤った原因**を指して落ちる —— このガードが
        // 本来なくそうとしている「原因の分かりにくい失敗」そのものになる
        return found.Distinct().Where(AuditedEntityModel.IsMappedEntity).ToList();
    }

    // 網羅ガードが DbSet<T> の宣言を探す型の並び。
    //
    // ApplicationDbContext から基底をたどり、**自分たちのアセンブリで定義された型だけ**を返す
    // (EF / Identity の基底型で止まる)。DeclaredOnly と組み合わせることで、
    //   - Identity が宣言する DbSet(Users / Roles など)は拾わない
    //   - 将来 DbSet を自前の中間基底クラスへ移しても拾い続ける
    // の両立になる。「DbSet がどこで宣言されているか」だけで絞っており、
    // 導出側(エンティティの CLR 型を所属アセンブリと派生関係で絞る)とは別の手がかりを使う
    private static IEnumerable<Type> OwnDbContextTypes()
    {
        // 自分たちのアセンブリ(綴りを書かず DbContext の所属から引く)
        var ownAssembly = typeof(ApplicationDbContext).Assembly;

        // ApplicationDbContext から基底へ 1 つずつさかのぼる
        for (var type = typeof(ApplicationDbContext); type != null; type = type.BaseType)
        {
            // 自分たちのアセンブリの外(EF / Identity の基底)へ出たらそこで打ち切る
            if (type.Assembly != ownAssembly) yield break;

            // 自分たちが書いた DbContext 型として返す
            yield return type;
        }
    }

    [Fact]
    public void LengthGovernanceExclusions_AreAllStillReal()
    {
        // 除外の名前が EF のモデル上に実在するかを確かめる。
        //
        // **この検査が捉えるのは「モデルから消えた」場合だけ**で、リネームは捉えられない。
        // キーは nameof(AuditLog) なので、型をリネームすれば C# のリファクタが自動追随し、
        // 除外と実装は常に一致する（そして除外は正しく効き続ける）。捉える必要があるのは
        // 「エンティティをモデルから外した／マップをやめたのに除外だけが残る」場合で、
        // そのとき除外は何も除かない飾りになり、読み手には効いているように見える。
        //
        // 上のガードは「除外に無いなら管理対象のはず」として正しく落ちるが、失敗の原因が
        // 「除外が実在しない名前を指している」ことだとは分からない。ここで名指しして迷わせない
        var stale = LengthGovernanceExclusions.Keys
            .Where(name => AuditedEntityModel.EfModel.GetEntityTypes().All(e => e.ClrType.Name != name))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // 実在しない名前を指している除外が無いこと
        Assert.True(stale.Count == 0,
            "長さ上限の管理対象から除外している名前が、EF のモデル上のエンティティを指していません: " +
            string.Join(", ", stale) + "。エンティティをモデルから外したのに除外だけが残っています " +
            "(このままだとその除外は何も除かない飾りになります)。");
    }

    [Fact]
    public void LengthGovernanceExclusions_AllHaveAReason()
    {
        // 除外表は「理由を必須にすることで、とりあえず検出網を黙らせる使い方を塞ぐ」意図で
        // 値に理由を持たせている。ところが読み手は .Keys と .ContainsKey だけで、
        // **値は誰も見ていなかった** —— 理由を空文字や空白にしても通ってしまう。
        //
        // 実測: [nameof(CauseCategory)] = "   " を足すと CauseCategory が長さ関連 4 検査すべてから
        // 外れるのに 504 → 498 で全件緑のまま通った(痕跡はテスト件数の減少だけ)。
        // NotPhiAttribute は同じ意図を実行時の throw で強制している。同じ強度をここにも与える
        var missingReason = LengthGovernanceExclusions
            .Where(pair => string.IsNullOrWhiteSpace(pair.Value))
            .Select(pair => pair.Key)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 理由の無い除外が 1 件も無いこと
        Assert.True(missingReason.Count == 0,
            "長さ上限の管理対象から外す除外に理由が書かれていません: " +
            string.Join(", ", missingReason) +
            "。理由を必須にしているのは [NotPhi(\"理由\")] と同じで、" +
            "「とりあえず検出網を黙らせる」使い方を残さないためです。");
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
