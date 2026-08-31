// ドメインモデル(Incident)をガードのアンカーとして参照するために取り込む
using IncidentInsight.Web.Models;
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
    /// <summary>
    /// 網羅ガードが使う「手がかり」を実際に読み取れたことを確かめる。
    ///
    /// この形の表明はガード側に 3 か所あり（DbSet の手がかり 1 つ、基底型引数の手がかり 2 つ）、
    /// どれも前提が崩れたら緑ではなく赤で知らせる必要がある
    /// （空のまま素通りさせると「対象ゼロ＝緑」で無力化される）。
    /// 同じ表明を書き写すと、手がかりの導出を変えたときに一部だけが古い前提を確かめ続けるので、
    /// 文言も強さもここ 1 か所に置き、どの手がかりかだけを引数で渡す。
    /// </summary>
    private static void AssertClueIsReadable(IReadOnlyList<Type> clueTypes, string clueDescription)
    {
        // 1 つも読み取れないのは、対象を取得する条件が実装とずれている状態
        Assert.True(clueTypes.Count > 0,
            $"{clueDescription}を 1 つも読み取れませんでした。" +
            "このガードが対象を取得する条件が実装とずれています(このままでは常に緑になります)。");
    }

    // 手がかりの説明(失敗メッセージに埋め込む)。両方の呼び出し元がここから引く
    private const string DeclaredDbSetClue = "ApplicationDbContext が自分で宣言した DbSet<T>";
    private const string BaseTypeArgumentClue =
        "ApplicationDbContext の基底へ渡した自アセンブリの型引数(ApplicationUser など)";

    /// <summary>
    /// 網羅ガード専用の「自分たちのアセンブリの型か」判定。
    ///
    /// <b>共有ヘルパー <c>AuditedEntityModel.IsOwnAssemblyType</c> をあえて呼ばない。</b>
    /// このガードの存在意義は「導出が対象を取りこぼしていないか」を<b>独立した手がかり</b>で
    /// 照合することにある。導出と同じ述語を通すと、その 1 つを狭めた瞬間に導出とガードが
    /// <b>一緒に</b>狭まり、ガードは「取りこぼしゼロ＝緑」で無力化される —— 実測でも、
    /// 共有述語へ条件を 1 つ足して同時にそのエンティティの <c>[MaxLength]</c> を消すと
    /// 507 → 501 件で<b>全件緑のまま</b>通った（痕跡はテスト件数の減少だけ）。
    ///
    /// つまりここは DRY より<b>手がかりの独立性</b>を優先する箇所で、重複は意図的。
    /// アンカーをモデルの型（<c>Incident</c>）に変えて、別経路で同じ問いに答える。
    /// </summary>
    private static bool IsGuardOwnAssemblyType(Type type)
    {
        // ドメインモデルが置かれているアセンブリと同じなら自前の型
        return type.Assembly == typeof(Incident).Assembly;
    }

    // プロパティの走査条件。DeclaredOnly を付けて「その型自身が宣言した」ものだけを見る。
    //
    // 付けないと、自前の基底クラスを持つ ViewModel で同じプロパティが基底と派生の両方から
    // 拾われ、同じ違反が 2 つの型名で二重に報告される(走査も 2 度走る)。
    // 継承したプロパティは、それを宣言している型のケースで検査される
    private const BindingFlags DeclaredInstanceProperties =
        BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly;

    /// <summary>
    /// 長さ上限の属性が付いた数値が「何を数えているか」の分類。
    /// </summary>
    private enum LimitKind
    {
        /// <summary>文字数（<c>string</c> / <c>char[]</c> / 文字列として保存する列）。</summary>
        CharacterLength,

        /// <summary>バイト長（<c>byte[]</c>）。</summary>
        ByteLength,

        /// <summary>コレクションの「要素数」（<c>List&lt;T&gt;</c> など）。</summary>
        ItemCount,
    }

    /// <summary>
    /// そのプロパティの長さ属性が何を数えているかを分類する。
    ///
    /// <b>分類はここ 1 か所だけで行う。</b> 以前は「検査に掛けるか」と「どの文言を要求するか」が
    /// それぞれ同じ判定を持っており、片方にだけ種類を足すと
    /// 「文字数の文言は要求されるのに裸の数値は誰も見ない」という食い違いが生まれた。
    ///
    /// 種類を「長さ / 要素数」の 2 つにまとめてもいけない（実測で 2 つの穴が出た）:
    ///   - <c>byte[]</c> を「長さ」に含めると、バイト長の上限に文字数の文言
    ///     （「添付は100<b>文字</b>以内で…」）を強制してしまう
    ///   - <c>char[]</c> を「要素数」に落とすと、文字数の上限なのに裸の数値が
    ///     どの検査にも掛からず、文言も「◯◯は333<b>件</b>以内で…」になる
    /// </summary>
    private static LimitKind ClassifyLimit(PropertyInfo property)
    {
        // 対象の型
        var type = property.PropertyType;

        // string と char[] は文字数を数える
        if (type == typeof(string) || type == typeof(char[])) return LimitKind.CharacterLength;

        // byte[] はバイト数を数える(文字数とは別の文言が要る)
        if (type == typeof(byte[])) return LimitKind.ByteLength;

        // それ以外のコレクションは要素数を数える
        if (typeof(System.Collections.IEnumerable).IsAssignableFrom(type)) return LimitKind.ItemCount;

        // 残り(値変換して文字列として保存する enum 列など)は保存される文字列の文字数
        return LimitKind.CharacterLength;
    }

    /// <summary>
    /// そのプロパティに期待される書式の<b>定数名</b>を返す。
    /// 失敗メッセージには生の文字列ではなくこちらを出す —— 生の文字列だけを見せると、
    /// 開発者はそれを直書きして緑にしてしまい、定数を本番へ置いた意味（一元管理）が失われる。
    /// </summary>
    private static string ExpectedMessageConstantNameFor(PropertyInfo property)
    {
        // 分類に対応する定数名を返す
        return ClassifyLimit(property) switch
        {
            LimitKind.ItemCount => nameof(FieldLengths.ItemCountMessage),
            LimitKind.ByteLength => nameof(FieldLengths.ByteLengthMessage),
            _ => nameof(FieldLengths.MaxLengthMessage),
        };
    }

    /// <summary>
    /// そのプロパティの上限に付けるべき日本語メッセージの書式を返す（分類は <see cref="ClassifyLimit"/>）。
    ///
    /// コレクション（要素数の上限）に文字数の書式を流用すると、
    /// <c>[MaxLength(3)] List&lt;string&gt; Tags</c> が「タグは3文字以内で入力してください。」という
    /// 誤った文言になる（実際に制限しているのは件数）。かといってコレクションを検査から外すと、
    /// 今度は英語の既定メッセージが日本語 UI に出るのを止められない（実測で両方を確認した）。
    /// どちらにも倒さず、<b>種類に応じた正しい書式</b>を要求する。
    /// </summary>
    private static string ExpectedMessageFor(PropertyInfo property)
    {
        // 分類に対応する書式を返す
        return ClassifyLimit(property) switch
        {
            // 要素数は「件」で伝える
            LimitKind.ItemCount => FieldLengths.ItemCountMessage,
            // バイト長は「バイト」で伝える
            LimitKind.ByteLength => FieldLengths.ByteLengthMessage,
            // 残りは文字数
            _ => FieldLengths.MaxLengthMessage,
        };
    }

    /// <summary>
    /// 裸の数値の検査に掛けるプロパティかを返す。
    ///
    /// 条件は「その数値が<b>長さ</b>を意味する」こと（走査側が
    /// <c>BindingFlags.DeclaredOnly</c> で自アセンブリの型だけを見ているので、
    /// 「自分たちが宣言した」かどうかはここでは判定しない）。
    /// 除くのは<b>要素数を数える制約だけ</b>（<c>List&lt;T&gt;</c> などのコレクション）で、
    /// <c>string</c> はもちろん <c>byte[]</c>（バイト長）や値変換した enum 列（保存される文字列の長さ）は<b>残す</b>。
    ///
    /// ここを <c>string</c> 限定にすると穴が開く（実測）: 値変換した enum 列
    /// （<c>PreventiveMeasure.Status</c> など）へ裸の <c>[MaxLength(20)]</c> を書くと、
    /// CLR 型が enum なのでこの検査から外れ、モデル側の検査は 20 を <c>EnumCode</c> として許し、
    /// 属性とモデルの一致検査も（値が同じなので）通って<b>全件緑</b>になった。
    /// 実行不能な指示を避けたいのはコレクションの要素数だけなので、除外もそこに限る。
    /// </summary>
    private static bool IsNakedNumberCheckedProperty(PropertyInfo property)
    {
        // 長さ(文字数・バイト数)を数えているものだけが FieldLengths の定数と突き合わせる対象。
        // 要素数の上限に FreeText(500) を当てろというのは実行不能な指示になる
        return ClassifyLimit(property) != LimitKind.ItemCount;
    }

    /// <summary>
    /// そのプロパティの上限として許してよい値の集合を返す。
    ///
    /// 利用者が入力する項目は <see cref="AttributeAllowedLengths"/> だけ。
    /// <c>EnumCode</c> / <c>EnumCodeJapanese</c> を許すのは<b>enum のプロパティだけ</b>。
    /// この 2 つは「値変換して文字列として保存する enum 列」にしか意味を持たないので、
    /// 「string でなければ何でも」に広げてはいけない —— 実測でも、その形だと
    /// <c>[MaxLength(20)] byte[] Attachment</c> のような裸の数値が通ってしまった
    /// （<c>main</c> では全プロパティを <c>{500, 100}</c> と突き合わせていたので捕まっていた）。
    /// </summary>
    private static int[] AllowedLengthsFor(PropertyInfo property)
    {
        // Nullable を剥がした素の型
        var type = Nullable.GetUnderlyingType(property.PropertyType) ?? property.PropertyType;

        // 緩和の根拠は「値変換して**文字列として保存する enum 列**」なので、判定も
        // そのプロパティ自身が文字列として保存される列かどうかで行う。
        //
        // 「宣言型がマップ済みエンティティか」で見ると広すぎる: 同じ型にある [NotMapped] の
        // enum プロパティや、既定の int マッピングのまま文字列として保存されない enum 列にも
        // 20 / 50 が通ってしまい、しかもモデル側の検査は文字列列しか見ないので誰も見ない。
        // 「型が enum か」だけでも広すぎる: ViewModel の enum プロパティに [MaxLength] を書くと
        // MaxLengthAttribute が実行時に InvalidCastException を投げ、その画面の POST が
        // 毎回 HTTP 500 になる(実測)
        return type.IsEnum && AuditedEntityModel.IsStringPersistedColumn(property)
            ? ModelAllowedLengths
            : AttributeAllowedLengths;
    }

    /// <summary>
    /// 属性側の検査対象となる型の一覧。
    ///
    /// <b>型名を書き並べない</b>のが要点。以前はエンティティを EF のモデルから導出する一方で、
    /// ViewModel だけ 4 型を直書きしていた。その形だと <c>Models/ViewModels</c> へ新しい入力用
    /// ViewModel を足し、そのプロパティに裸の <c>[MaxLength(200)]</c>（あるいは <c>ErrorMessage</c>
    /// 未指定の <c>[MaxLength]</c>）を書いても、どの検査も対象に含めないため CI は緑のまま通る。
    /// 結果として画面側の上限だけがエンティティ（<c>ShortText</c>=100 等）とずれ、
    /// SQL Server / PostgreSQL 配備では保存時に列長超過（未捕捉の <c>DbUpdateException</c> = HTTP 500）に
    /// なり、日本語 UI に英語の既定検証メッセージが混ざる。
    ///
    /// 名前空間や型名の接尾辞（"ViewModel"）ではなく<b>長さ上限の属性の有無</b>を条件にしているので、
    /// 置き場所を変えても、命名規約から外れた型を足しても、対象から外れない。
    /// </summary>
    private static IReadOnlyList<Type> GovernedTypes()
    {
        // 自分たちのアセンブリで長さ上限の属性を 1 つでも宣言している型を集める
        return typeof(ApplicationDbContext).Assembly
            .GetTypes()
            // 意図的な除外(AuditLog は列長の出所が監査証跡スキーマ)を外す。
            //
            // 除外表は「エンティティ」に対する表なので、マップ済みであることも併せて確かめる。
            // キーが完全修飾名である限り同名衝突は起きえない(同一アセンブリに同じ完全修飾名の型は
            // 2 つ作れない)ので、この条件は今のところ結果を変えない —— それでも残すのは、
            // 除外表がエンティティに対するものだという不変条件をここに明示しておくため。
            // 辞書引きを先に置いて、アセンブリ内の全型に対して EF モデル検索が走らないようにする
            .Where(t => !(LengthGovernanceExclusions.ContainsKey(AuditedEntityModel.ExclusionKeyFor(t))
                          && AuditedEntityModel.IsMappedEntity(t)))
            // 自分たちが宣言したプロパティに長さ上限の属性があるものだけを残す。
            //
            // 選別の述語は、実際に検査する 2 つの述語の**和集合**(= 広い方)にする。
            // ここだけ string に絞ると、長さ属性が非 string プロパティにしか付いていない型
            // (例: [MaxLength(200)] byte[] Blob と [MaxLength(333)] MeasureStatus Status だけを
            // 持つ ViewModel)が [Theory] のケースにすら入らず、裸の数値が誰にも見られない
            // ——実測でも 506 → 506 件、テスト件数すら変わらずに全件緑で通った。
            // 「検査する範囲」より「対象を選ぶ範囲」が狭いと、その差分がそのまま死角になる
            .Where(t => t.GetProperties(DeclaredInstanceProperties)
                .Any(p => AuditedEntityModel.ReadLengthLimits(p).Count > 0))
            // 実行ごとに順序が揺れないよう型名で並べる
            .OrderBy(t => t.Name, StringComparer.Ordinal)
            .ToList();
    }

    // 属性側(= [MaxLength] を宣言している型)の検査対象。
    //
    // モデル側の集合(ModelBackedTypes / AuditedEntityModel.LengthGovernedEntityTypes)とは
    // **中身が違う**(こちらは ViewModel を含み、あちらはマップ済みエンティティだけ)。
    // 以前は両方が LengthGovernedTypes / LengthGovernedEntityTypes という紛らわしい名前で、
    // [MemberData] に取り違えて配線しても**コンパイルが通ってしまう**状態だった
    // (取り違えると、属性側の検査がエンティティだけに狭まって ViewModel の裸の数値を見逃すか、
    //  逆にモデル側へ ViewModel が流れて PartitionStringColumns が例外で落ちる)。
    // 役割がそのまま名前に出るようにして取り違えを防ぐ
    // アセンブリ全体のリフレクション走査は決定的なので 1 度だけ行う。
    // xUnit は [MemberData] を検査ごと(検出時と実行時)に評価するため、素の式のままだと
    // 同じ走査が何度も走る(EF のモデルを Lazy で 1 度だけ組み立てているのと同じ理由)
    private static readonly Lazy<IReadOnlyList<Type>> GovernedTypesCache = new(GovernedTypes);

    public static TheoryData<Type> MaxLengthDeclaringTypes =>
        AuditedEntityModel.ToTheoryData(GovernedTypesCache.Value);

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
    [MemberData(nameof(MaxLengthDeclaringTypes))]
    public void EveryMaxLength_UsesAFieldLengthsConstant(Type type)
    {
        // 対象型の公開プロパティのうち長さ上限が付いているものを列挙する
        var offenders = type
            .GetProperties(DeclaredInstanceProperties)
            // 数値が「長さ」を意味するプロパティだけを見る(理由は IsNakedNumberCheckedProperty)
            .Where(IsNakedNumberCheckedProperty)
            // 1 つのプロパティに複数の長さ属性が付くこともあるので**すべて**を見る。
            // 最初の 1 つで打ち切ると、[MaxLength](正しい値) と [StringLength](裸の値) を
            // 並べるだけで 2 つ目が視界から外れる —— MVC は両方の validator を走らせるので
            // 実効上限は小さい方になり、綴りではなく「属性を 1 つ足す」形の抜け道になる
            .SelectMany(p => AuditedEntityModel.ReadLengthLimits(p).Select(limit => new { Property = p, Limit = limit }))
            // 許容値のいずれとも一致しない上限を違反として拾う
            .Where(x => !AllowedLengthsFor(x.Property).Contains(x.Limit.Length))
            .Select(x => $"{type.Name}.{x.Property.Name} = {x.Limit.Length} ([{x.Limit.AttributeName}])")
            .ToList();

        // 違反ゼロであること(あればどのプロパティが裸の数値かをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "長さ上限の属性([MaxLength] / [StringLength] / [Length])に FieldLengths 以外の裸の数値が " +
            $"使われています(許容値: 文字列は {string.Join(" / ", AttributeAllowedLengths)}、" +
            $"値変換して保存する列は {string.Join(" / ", ModelAllowedLengths)}、" +
            "バイト長は専用の定数がまだ無いので FieldLengths へ追加が必要): " + string.Join(", ", offenders));
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
        // 対象は「長さ上限が設定されている列」すべて。文字列列に絞ると、属性側が byte[] や
        // 値変換した enum 列まで見ているのに対してモデル側だけが狭くなり、その差分が死角になる
        // (実測: byte[] の列へ fluent で HasMaxLength(300) と書くと 4 検査すべてを素通りした)
        var offenders = AuditedEntityModel.AppDeclaredColumnsWithLength(entityType)
            // 許容値のいずれとも一致しない上限を違反として拾う
            .Where(c => !allowed.Contains(c.MaxLength))
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
        // 対象は「長さ上限が設定されている列」すべて(文字列列に限らない)。
        // 属性側が byte[] まで見ている以上、一致検査の範囲も同じにそろえる
        var offenders = AuditedEntityModel.AppDeclaredColumnsWithLength(entityType)
            // CLR プロパティを持たない shadow 列には属性が付けられないので対象外
            .Where(c => c.Property != null)
            // 属性側の上限は 1 つとは限らないのですべて取り出して突き合わせる
            .SelectMany(c => AuditedEntityModel.ReadLengthLimits(c.Property!)
                .Select(limit => new { c.Name, c.MaxLength, Limit = limit }))
            // 値が一致しないものが違反
            .Where(x => x.Limit.Length != x.MaxLength)
            .Select(x => $"{entityType.Name}.{x.Name}: [{x.Limit.AttributeName}]={x.Limit.Length} / モデル={x.MaxLength}")
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
    [MemberData(nameof(MaxLengthDeclaringTypes))]
    public void NonEntityMaxLength_UsesJapaneseSharedErrorMessage(Type type)
    {
        // 検査対象は「EF のモデルに載っていない型」= 画面やリクエストの入力を受ける型。
        // エンティティ側の [MaxLength] は EF Core の列長定義にしか使われず、メッセージが
        // 利用者に見えないため対象外にする。
        //
        // 判定を型名の接尾辞("ViewModel")ではなく**EF のモデルに載っているか**で行うのが要点。
        // 対象の導出(GovernedTypes)は「[MaxLength] を宣言している型」へ広げてあるのに、ここだけ
        // 接尾辞で絞ると導出だけが広がって検査が広がらない —— 実測でも、Models/ViewModels へ
        // 接尾辞の無い MeasureForm を足して ErrorMessage 無しの [MaxLength] を書くと全件緑で通り、
        // 日本語 UI に英語の既定メッセージ("The field ... maximum length of '500'.")が混ざった。
        // 「エンティティか、入力を受ける型か」を分けたいのだから、命名規約ではなく
        // モデルに載っているかどうかで切る。
        //
        // この条件は "ViewModel" より**広い**。画面を持たない DTO(取り込み用の行、API の
        // リクエスト record、ジョブのペイロード等)に [MaxLength] を付けた場合も対象になり、
        // 共通の日本語メッセージを要求される。意図的にこの向きへ倒している —— 判定を
        // 「利用者に見えるか」に寄せようとすると結局は命名規約や属性の有無に頼ることになり、
        // 見落とし(fail-open)の側へ倒れる。付けるコストは ErrorMessage 1 つぶんで、
        // 逆に日本語 UI へ英語の既定メッセージが出る事故は利用者に見えるため、
        // 「要求しすぎ」より「見落とし」の方が高くつく。
        // メソッド名も対象に合わせてある(ViewModel ではなく非エンティティ)
        if (AuditedEntityModel.IsMappedEntity(type)) return;

        // [MaxLength] が付いた公開プロパティのうち、共通の日本語書式を使っていないものを拾う。
        // 既定のメッセージは英語("The field ... maximum length of '500'.")のため、
        // 指定漏れがあると日本語 UI に英文の検証エラーが混ざる(CLAUDE.md §1)
        var offenders = type
            .GetProperties(DeclaredInstanceProperties)
            // 型を問わず、その型が宣言したプロパティをすべて見る
            // (自アセンブリかどうかは走査条件 DeclaredInstanceProperties が担保している)。
            //
            // 裸の数値の検査(IsNakedNumberCheckedProperty)はコレクションを除くが、その除外を
            // ここへ流用してはいけない。除外の根拠は「要素数に FieldLengths の定数を当てろ」が
            // 実行不能だという点であって、ErrorMessage を書くことは対象がコレクションでも
            // 実行可能だから。流用すると [MaxLength(3)] List<string> Tags のような宣言が
            // 裸の数値もメッセージ漏れも両方素通りし、日本語 UI に
            // "The field Tags must be a string or array type with a maximum length of '3'." が出る
            // (実測。main では捕まっていた退行)
            .SelectMany(p => AuditedEntityModel.ReadLengthLimits(p).Select(limit => new { Property = p, Limit = limit }))
            // 違反は 2 種類:
            //  (a) [MaxLength] 以外の綴り([StringLength] / [Length])を使っている
            //  (b) [MaxLength] だが ErrorMessage が共通書式でない
            //
            // (a) を違反にする理由は綴りによって違う:
            //   - [Length] … FormatErrorMessage が {1} に**最小長**を渡すため、
            //     共通書式({1} が上限の前提)を付けると「◯◯は1文字以内で…」と壊れる(実測)
            //   - [StringLength] … {1} は上限なので文言自体は壊れない。それでも弾くのは、
            //     同じことを表す綴りが増えるほど検出網に抜け道ができるから
            //     (この PR は [MaxLength] しか見ていなかった時代に [StringLength] が
            //      丸ごと抜け道になっていたのを塞いだ)。入力を受ける型では綴りを 1 つに保つ
            .Where(x => x.Limit.AttributeName != nameof(MaxLengthAttribute)
                        || x.Limit.ErrorMessage != ExpectedMessageFor(x.Property))
            .Select(x => $"{type.Name}.{x.Property.Name} ([{x.Limit.AttributeName}]) " +
                         $"→ 期待する書式: FieldLengths.{ExpectedMessageConstantNameFor(x.Property)}")
            .ToList();

        // 違反ゼロであること
        Assert.True(offenders.Count == 0,
            "入力を受ける型(EF のモデルに載っていない型)の長さ上限は、[MaxLength] に " +
            "共通の日本語エラーメッセージ書式を指定してください(文字数は FieldLengths.MaxLengthMessage、" +
            "バイト長は FieldLengths.ByteLengthMessage、コレクションの件数は FieldLengths.ItemCountMessage。" +
            "[StringLength] / [Length] は書式の {1} の意味が違うため使わない): " + string.Join(", ", offenders));
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
            // 自分たちのアセンブリの型だけを残す。外すと「便宜のために DbSet<IdentityRole> を
            // 生やしただけ」でガードが赤くなり、しかも「導出条件がずれている」という誤った
            // 原因を指す(唯一の逃げ道が「フレームワークの型を除外表へ足す」になってしまう)。
            //
            // ただし判定には**あえて共有ヘルパーを使わない**(IsGuardOwnAssemblyType)。理由は
            // そちらのコメントを参照
            .Where(IsGuardOwnAssemblyType)
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
        AssertClueIsReadable(declaredDbSetTypes, DeclaredDbSetClue);
        AssertClueIsReadable(identityUserTypes, BaseTypeArgumentClue);

        // 現在の導出結果(検査対象になっているエンティティ)
        var governed = AuditedEntityModel.LengthGovernedEntityTypes();

        // DbSet で公開しているのに、管理対象でも「意図的な除外」でもないエンティティを拾う
        var missing = ownedEntityTypes
            .Where(t => !governed.Contains(t))
            .Where(t => !LengthGovernanceExclusions.ContainsKey(AuditedEntityModel.ExclusionKeyFor(t)))
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
        // 見つけた型引数を溜めるリスト
        var found = new List<Type>();

        // ApplicationDbContext から基底へ 1 つずつさかのぼる
        for (var type = typeof(ApplicationDbContext); type != null; type = type.BaseType)
        {
            // 総称でない基底には型引数が無いので読み飛ばす
            if (!type.IsGenericType) continue;

            // 型引数のうち自分たちのアセンブリのものだけを積む
            found.AddRange(type.GetGenericArguments().Where(IsGuardOwnAssemblyType));
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
        // ApplicationDbContext から基底へ 1 つずつさかのぼる
        for (var type = typeof(ApplicationDbContext); type != null; type = type.BaseType)
        {
            // 自分たちのアセンブリの外(EF / Identity の基底)へ出たらそこで打ち切る
            if (!IsGuardOwnAssemblyType(type)) yield break;

            // 自分たちが書いた DbContext 型として返す
            yield return type;
        }
    }

    [Fact]
    public void LengthGovernanceExclusions_AreAllStillReal()
    {
        // 除外の名前が EF のモデル上に実在するかを確かめる。
        //
        // **この検査が捉えるのは「導出の対象から消えた」場合だけ**で、リネームは捉えられない。
        // キーは typeof(AuditLog).FullName なので、型のリネームにも名前空間の移動にも
        // C# のリファクタが自動追随し、除外と実装は常に一致する
        // （そして除外は正しく効き続ける）。捉える必要があるのは
        // 「エンティティをモデルから外した／マップをやめたのに除外だけが残る」場合で、
        // そのとき除外は何も除かない飾りになり、読み手には効いているように見える。
        //
        // 上のガードは「除外に無いなら管理対象のはず」として正しく落ちるが、失敗の原因が
        // 「除外が実在しない名前を指している」ことだとは分からない。ここで名指しして迷わせない
        // 突き合わせ先は**導出が見ているのと同じ範囲**(自アセンブリのマップ済みエンティティ)。
        // モデル全体と突き合わせると、フレームワークの型(IdentityRole など)を登録した除外が
        // 「実在する」として通ってしまう —— 導出はその前段で自アセンブリに絞るので、
        // その登録は何も除かない飾りのまま、人がレビューすべき表だけが膨らむ
        var ownMappedEntityKeys = AuditedEntityModel.EfModel.GetEntityTypes()
            .Select(e => e.ClrType)
            .Where(AuditedEntityModel.IsOwnAssemblyType)
            .Select(AuditedEntityModel.ExclusionKeyFor)
            .ToHashSet(StringComparer.Ordinal);

        // 除外表のキーのうち、その範囲に実在しないものを拾う
        var stale = LengthGovernanceExclusions.Keys
            .Where(key => !ownMappedEntityKeys.Contains(key))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        // 実在しない名前を指している除外が無いこと
        Assert.True(stale.Count == 0,
            "長さ上限の管理対象から除外しているキーが、自アセンブリのマップ済みエンティティを指していません: " +
            string.Join(", ", stale) + "。エンティティをモデルから外した、あるいは自アセンブリ外の型を " +
            "登録しています(どちらの場合もその除外は何も除かない飾りになります)。");
    }

    [Fact]
    public void LengthGovernanceExclusions_CannotDropIdentityBackedEntities()
    {
        // 除外表はエスケープハッチなので、**この PR が塞いだ穴をそのまま開け直せてはいけない**。
        //
        // 実測: typeof(ApplicationUser).FullName をキーに "列長は ASP.NET Core Identity 側が決めるため" という
        // (もっともらしい)理由で登録し、ApplicationUser の [MaxLength] を 2 つとも消すと
        // 505 件すべて緑のまま通った。導出から外れるので長さ関連 4 検査が効かなくなり、
        // 上の網羅ガードも「意図的な除外」として素通りさせるため。理由の有無を見る検査も、
        // 文言がもっともらしい以上まったく助けにならない。
        //
        // そこで、手がかり (b) で拾う型 —— 基底の総称 DbContext へ自分たちが渡した型
        // (ApplicationUser) —— は除外表に載せられないことを固定する。この型は
        // 「フレームワークが持つ型に自分たちが業務列を足したもの」で、列長の管理を
        // やめてよい列とやめてはいけない列が同居しているため、**エンティティ単位で外すこと自体が誤り**。
        // 正しい対処は列単位(AuditedEntityModel.IsDeclaredInOwnAssembly)で切ることで、それは既に効いている
        // 手がかりが空だとこのガードは 0 == 0 を確かめるだけの空振りになる。
        // 他の検出網と同じく、前提が崩れたら緑ではなく赤で知らせる(fail-closed)
        var baseTypeArguments = OwnDbContextBaseTypeArguments();
        AssertClueIsReadable(baseTypeArguments, BaseTypeArgumentClue);

        // 手がかり (b) の型のうち、除外表に載っているものを拾う(載せてはいけない型)
        var identityBacked = baseTypeArguments
            .Where(t => LengthGovernanceExclusions.ContainsKey(AuditedEntityModel.ExclusionKeyFor(t)))
            .Select(t => t.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // そのような除外が 1 件も無いこと
        Assert.True(identityBacked.Count == 0,
            "基底の DbContext へ渡した型を長さ上限の管理対象から除外しています: " +
            string.Join(", ", identityBacked) +
            "。この型にはフレームワークが決める列と自分たちが足した業務列が同居しているため、" +
            "エンティティ単位で外すと後者(ApplicationUser なら DisplayName / Department)まで" +
            "巻き添えで長さ管理から落ちます。列単位の除外で対処してください。");
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

    [Theory]
    [MemberData(nameof(MaxLengthDeclaringTypes))]
    public void NonEntityLengthAttribute_OnlyOnMeasurableTypes(Type type)
    {
        // 対象は入力を受ける型(EF のモデルに載っていない型)。エンティティ側の [MaxLength] は
        // EF Core の列長定義にしか使われず、DataAnnotations の検証は走らない
        if (AuditedEntityModel.IsMappedEntity(type)) return;

        // MaxLengthAttribute.IsValid が測れない型に付いた長さ属性を拾う
        var offenders = type
            .GetProperties(DeclaredInstanceProperties)
            .Where(p => AuditedEntityModel.ReadLengthLimits(p).Count > 0)
            .Where(p => !IsMeasurableByLengthAttribute(p.PropertyType))
            .Select(p => $"{type.Name}.{p.Name} ({p.PropertyType.Name})")
            .ToList();

        // MVC の検証時に例外になる宣言が 1 つも無いこと。
        //
        // 上限の**値**や**文言**の検査だけでは足りない: enum / int / DateTime に
        // [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)] と
        // 書くと、値は許容集合に入り文言も規約どおりなので全検査が緑になる。ところが
        // MaxLengthAttribute.IsValid は測れない型に対して InvalidCastException を投げるため、
        // その画面への POST は毎回 HTTP 500 になる(実測)
        Assert.True(offenders.Count == 0,
            "長さ上限の属性が、MaxLengthAttribute では測れない型のプロパティに付いています: " +
            string.Join(", ", offenders) +
            "。MVC の検証時に InvalidCastException(\"must be a string, array or ICollection type\") が" +
            "投げられ、その画面への POST が毎回 HTTP 500 になります。" +
            "長さ属性を外すか、対象を string / char[] / byte[] / ICollection にしてください。");
    }

    /// <summary>
    /// <c>MaxLengthAttribute.IsValid</c> がその型の長さを測れるかを返す。
    ///
    /// .NET 8 の実装は「<c>string</c>」「配列」「<b>読み取れる <c>int Count</c> を持つ型</b>」を
    /// 受け入れ、それ以外で <c>InvalidCastException</c> を投げる。
    ///
    /// 条件を <c>ICollection</c> / <c>ICollection&lt;T&gt;</c> に狭めてはいけない（実測）:
    /// <c>IReadOnlyCollection&lt;string&gt;</c> も、<c>int Count</c> だけを持つ独自型も、
    /// 属性側は<b>例外を投げず検証に通る</b>のに、狭い判定では「実行時に HTTP 500 になる」という
    /// <b>事実と異なる診断</b>で赤にしてしまい、開発者を正しい宣言を外す方向へ誘導する。
    /// </summary>
    private static bool IsMeasurableByLengthAttribute(Type type)
    {
        // string は長さを測れる
        if (type == typeof(string)) return true;

        // 配列(char[] / byte[] / T[])は Length を持つ
        if (type.IsArray) return true;

        // 読み取れる int Count を持つ型(ICollection / ICollection<T> / IReadOnlyCollection<T> /
        // 独自の Count プロパティ)は、属性が Count 経由で長さを測れる
        return HasReadableIntCount(type)
               || type.GetInterfaces().Any(HasReadableIntCount);
    }

    /// <summary>
    /// その型に「読み取れる <c>int Count</c> プロパティ」があるかを返す
    /// （<c>MaxLengthAttribute</c> が長さを測るのに使う手がかり）。
    /// </summary>
    private static bool HasReadableIntCount(Type type)
    {
        // 公開インスタンスプロパティ Count を探す
        var count = type.GetProperty("Count", BindingFlags.Public | BindingFlags.Instance);

        // int を返し、読み取れるものだけが該当する
        return count != null && count.PropertyType == typeof(int) && count.CanRead;
    }

    [Fact]
    public void MaxLengthDeclaringTypes_CoverEveryTypeWithALengthAttribute()
    {
        // 属性側の対象選別は ReadLengthLimits(= 実際に検査する述語そのもの)だけに依存している。
        // つまり ReadLengthLimits を狭める「整理」を入れると、対象からも同時に落ちて
        // 検出網が黙って無力化される —— たとえば [MaxLength] だけを見る形へ戻すと、
        // (a) [StringLength] / [Length] の禁止が消え、(b) 長さ属性が [StringLength] だけの
        // ViewModel は [Theory] のケースにすら入らなくなるが、そういう型が現時点で存在しない
        // ため 517/517 緑のまま・テスト件数も変わらずに通る(痕跡ゼロ)。
        //
        // そこで対象を**独立した手がかり**で照合する。導出は「属性の型を引く」経路なので、
        // ここでは「属性の**名前**が Length で終わるか」という別の経路で数える。
        // 同じ経路でガードを書くと、導出が狭まったときにガードも一緒に狭まって意味がない。
        var expected = typeof(ApplicationDbContext).Assembly
            .GetTypes()
            // 意図的な除外(AuditLog)は対象外
            .Where(t => !(LengthGovernanceExclusions.ContainsKey(AuditedEntityModel.ExclusionKeyFor(t))
                          && AuditedEntityModel.IsMappedEntity(t)))
            // 名前が "LengthAttribute" で終わる属性を宣言プロパティに持つ型を拾う
            .Where(t => t.GetProperties(DeclaredInstanceProperties)
                .Any(p => p.GetCustomAttributes(inherit: true)
                    .Any(a => a.GetType().Name.EndsWith("LengthAttribute", StringComparison.Ordinal))))
            .ToList();

        // 手がかりが空だとこのガードは空振りになるので fail-closed で落とす
        AssertClueIsReadable(expected, "名前が LengthAttribute で終わる属性を持つ型");

        // 現在の導出結果
        var governed = GovernedTypesCache.Value;

        // 手がかりにあるのに対象へ入っていない型を拾う
        var missing = expected
            .Where(t => !governed.Contains(t))
            .Select(t => t.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        // 取りこぼしが 1 件も無いこと(fail-closed)
        Assert.True(missing.Count == 0,
            "長さ上限の属性を持つ型が、属性側の検査対象から外れています: " + string.Join(", ", missing) +
            "。AuditedEntityModel.ReadLengthLimits が対象の属性を拾えなくなっている可能性があります " +
            "——このままだとその型の裸の数値もメッセージ漏れも黙って素通りします。");
    }

    [Fact]
    public void ByteLengthMessage_FormatsDisplayNameAndLimit()
    {
        // 実際に MaxLengthAttribute が組み立てるメッセージを確認する。
        // 本番の利用箇所がまだ無い定数なので、書式を固定しておかないと
        // プレースホルダの取り違えに最初の利用者まで誰も気付けない
        var attribute = new MaxLengthAttribute(FieldLengths.ShortText)
        {
            ErrorMessage = FieldLengths.ByteLengthMessage
        };

        // 表示名「添付ファイル」に対するエラーメッセージを生成する
        var message = attribute.FormatErrorMessage("添付ファイル");

        // 項目名と上限バイト数の両方が含まれた日本語メッセージになっていること
        Assert.Equal($"添付ファイルは{FieldLengths.ShortText}バイト以内で入力してください。", message);
    }

    [Fact]
    public void ItemCountMessage_FormatsDisplayNameAndLimit()
    {
        // 上と同じ理由で、要素数用の書式も固定する
        var attribute = new MaxLengthAttribute(FieldLengths.ShortText)
        {
            ErrorMessage = FieldLengths.ItemCountMessage
        };

        // 表示名「タグ」に対するエラーメッセージを生成する
        var message = attribute.FormatErrorMessage("タグ");

        // 項目名と上限件数の両方が含まれた日本語メッセージになっていること
        Assert.Equal($"タグは{FieldLengths.ShortText}件以内で入力してください。", message);
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
