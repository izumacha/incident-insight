// 本番と同じ構成のモデルバインダを組み立てるため
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
// クエリ文字列の値プロバイダ(?severity=99 と同じ経路で値を渡すため)
using Microsoft.AspNetCore.Http;
// MVC サービス一式(AddControllersWithViews)を登録するため
using Microsoft.Extensions.DependencyInjection;
// ログを捨てるためのヌルファクトリ(バインダのコンストラクタが要求する)
using Microsoft.Extensions.Logging.Abstractions;
// 束縛名と値の組を作るための型
using Microsoft.Extensions.Primitives;
// グローバリゼーション(値プロバイダが要求するカルチャ指定)
using System.Globalization;
// 検査対象の enum(このリポジトリで実際に絞り込み・更新に使っている型)
using IncidentInsight.Web.Models.Enums;

// 既存の Models 配下テストと同じ名前空間に置く
namespace IncidentInsight.Tests.Models;

/// <summary>
/// <b>定義に無い enum 値がモデルバインドでどう扱われるか</b>を、
/// <b>本番と同じ構成で組み立てたバインダ</b>を動かして固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(issue #215)。</b> このリポジトリのコントローラ級テストは
/// <c>controller.Index((IncidentSeverity)99, …)</c> と<b>アクションを直接呼ぶ</b>ので、
/// モデルバインドを一度も通らない。そのためかつて
/// 「<c>?severity=99</c> は変換が通り <c>ModelState</c> にエラーを積まない(実測)」
/// という<b>誤った結論</b>が「実測」としてドキュメントに残り、旗と文面を 2 つに分ける
/// 判断の根拠になっていた。<b>測る場所を、実際に効く場所に合わせる</b> ——
/// <c>AuditedEntityPhiClassificationTests</c> が「CLR のリフレクションではなく
/// EF Core のモデルを読む」としているのと同じ規則。</para>
///
/// <para><b>バインダを自前で <c>new</c> しない(要点)。</b> 本番でどのバインダが選ばれるかを
/// 決めるのは <c>EnumTypeModelBinderProvider</c> で、<c>new EnumTypeModelBinder(...)</c> と
/// 書くとその選定を飛ばしてしまう。飛ばすと、上流が「enum に別のバインダを返す」
/// 「本物の opt-out を足す」と変わったときに<b>この検査だけが緑のまま</b>になり、
/// <c>/Incidents?severity=99</c> が再び <c>(IncidentSeverity)99</c> として束縛される
/// —— 訂正後の記述が「もう起きない」と言っているまさにその退行を見逃す。
/// そこで <c>AddControllersWithViews()</c> で本番と同じサービスを組み、
/// <c>IModelBinderFactory</c> に選ばせる(<c>FormViewModelBindingMetadataTests</c> が
/// 「自前の <c>MvcOptions</c> を渡さないのが要点」としているのと同じ理由で、
/// <c>MvcOptions</c> は既定のまま読む)。</para>
///
/// <para><b>対象は本番の引数の形にそろえる。</b> 絞り込みの 3 画面は
/// <c>IncidentSeverity?</c> / <c>IncidentTypeKind?</c> / <c>MeasureStatus?</c> と
/// <b><c>Nullable&lt;T&gt;</c></b> で受け、<c>UpdateStatus</c> だけが非 null 許容の
/// <c>MeasureStatus</c> で受ける。この 2 つは<b>同じ挙動ではない</b>(空文字を渡すと
/// 前者は「値なしとして束縛成功」、後者は「束縛失敗」。実測)ので、両方を並べる。</para>
///
/// <para><b>落ちたときの直し方。</b> 上流の挙動が変わったということなので、
/// <b>テストを緩めるのではなく</b>
/// <see cref="IncidentInsight.Web.Models.Validation.SearchFilter"/> /
/// <see cref="IncidentInsight.Web.Controllers.Internal.UnlistedEnumFilterResolver"/> /
/// <c>PreventiveMeasuresController.UpdateStatus</c> / <c>CLAUDE.md</c> の記述を
/// 新しい事実へ合わせる。門番自体は他の理由が残るので撤去しない。</para>
/// </remarks>
public class UndefinedEnumModelBindingTests
{
    /// <summary>本番の絞り込み画面が受ける引数の形(いずれも <c>Nullable&lt;T&gt;</c>)。</summary>
    public static TheoryData<Type, string> FilterShapesWithUndefinedValue() => new()
    {
        // /Incidents?severity=99 (IncidentSeverity の定義は Level0..Level5 で 99 は無い)
        { typeof(IncidentSeverity?), "99" },
        // /Incidents?incidentType=0 (**99 ではない** —— Other が 99 として定義済みのため)
        { typeof(IncidentTypeKind?), "0" },
        // /PreventiveMeasures?status=99
        { typeof(MeasureStatus?), "99" },
        // UpdateStatus が受ける非 null 許容の形(保存を伴う経路)
        { typeof(MeasureStatus), "99" },
    };

    /// <summary>定義済みの値(誤検知が出ないことを見るための対になるケース)。</summary>
    public static TheoryData<Type, string> FilterShapesWithDefinedValue() => new()
    {
        // 重症度の定義済みの値
        { typeof(IncidentSeverity?), nameof(IncidentSeverity.Level5) },
        // 種別の定義済みの値(99 = Other は「正しく絞り込まれる」側)
        { typeof(IncidentTypeKind?), "99" },
        // 対策ステータスの定義済みの値
        { typeof(MeasureStatus?), nameof(MeasureStatus.Completed) },
        // 非 null 許容の形でも同じであること
        { typeof(MeasureStatus), nameof(MeasureStatus.Completed) },
    };

    /// <summary>
    /// <c>?&lt;name&gt;=&lt;rawValue&gt;</c> 1 件だけを供給する束縛文脈を組み立てる。
    /// </summary>
    private static DefaultModelBindingContext QueryContext(Type modelType, string rawValue,
        IModelMetadataProvider metadataProvider)
    {
        // 実際の経路と同じクエリ文字列の値プロバイダへ 1 件だけ載せる
        var query = new QueryCollection(new Dictionary<string, StringValues> { ["value"] = rawValue });
        // 束縛の文脈(束縛名・エラーの置き場・値の出どころ・束縛先の型)
        return new DefaultModelBindingContext
        {
            // 束縛する引数の名前(コントローラの引数名に相当する)
            ModelName = "value",
            // 束縛エラーが積まれる先(ここを観測する)
            ModelState = new ModelStateDictionary(),
            // クエリ文字列を値の出どころにする
            ValueProvider = new QueryStringValueProvider(
                BindingSource.Query, query, CultureInfo.InvariantCulture),
            // 束縛先の型情報
            ModelMetadata = metadataProvider.GetMetadataForType(modelType),
        };
    }

    /// <summary>
    /// <b>本番と同じ構成</b>(既定の <c>MvcOptions</c>)でバインダを選ばせ、束縛を実行する。
    /// </summary>
    private static (bool IsModelSet, int ErrorCount, object? Model) BindAsConfigured(
        Type modelType, string rawValue)
    {
        // 本番と同じ MVC サービスを組み立てる(自前の MvcOptions を渡さないのが要点)
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        using var provider = services.BuildServiceProvider();

        // メタデータとバインダ工場を本番の登録から取り出す
        var metadataProvider = provider.GetRequiredService<IModelMetadataProvider>();
        var binderFactory = provider.GetRequiredService<IModelBinderFactory>();

        // 束縛文脈を用意する
        var context = QueryContext(modelType, rawValue, metadataProvider);
        // **この型に対して本番が選ぶバインダ**を作らせる(provider の選定を通る)
        var binder = binderFactory.CreateBinder(new ModelBinderFactoryContext
        {
            // 束縛先の型情報
            Metadata = context.ModelMetadata,
        });

        // 束縛を実行する(同期的に完了するので待ち合わせる)
        binder.BindModelAsync(context).GetAwaiter().GetResult();

        // 「値が入ったか」「エラーが積まれたか」「入った値は何か」を返す。
        // **ここで ModelState.IsValid を見てはいけない** —— バインダが作る項目は
        // 検証前(Unvalidated)なので、束縛が成功しても IsValid は false のままになる
        // (実測: raw="Level5" は Model=Level5 が入るのにエラー 0 件で IsValid=false)。
        // 「エラーが積まれたか」を見たいのだから、数えるのは ErrorCount の方
        return (context.Result.IsModelSet, context.ModelState.ErrorCount, context.Result.Model);
    }

    /// <summary>
    /// <c>EnumTypeModelBinder</c> を<b>フラグを指定して直接</b>組み立てて束縛する。
    /// フラグが効くかどうかを見る 1 件だけがこれを使う(他は本番の選定を通す)。
    /// </summary>
    private static (bool IsModelSet, int ErrorCount) BindWithSuppressFlag(
        Type modelType, string rawValue, bool suppressBindingUndefinedValueToEnumType)
    {
        // メタデータだけは既定の提供元から取る
        var metadataProvider = new EmptyModelMetadataProvider();
        // 束縛文脈を用意する
        var context = QueryContext(modelType, rawValue, metadataProvider);
        // フラグを明示して組み立てる(この引数の効き目が主題)
        var binder = new EnumTypeModelBinder(
            suppressBindingUndefinedValueToEnumType, modelType, NullLoggerFactory.Instance);

        // 束縛を実行する
        binder.BindModelAsync(context).GetAwaiter().GetResult();

        // 比較に使う 2 つだけを返す
        return (context.Result.IsModelSet, context.ModelState.ErrorCount);
    }

    [Theory]
    [MemberData(nameof(FilterShapesWithUndefinedValue))]
    public void UndefinedValue_IsRejectedByTheConfiguredBinder(Type modelType, string rawValue)
    {
        // 本番と同じ構成で束縛する
        var result = BindAsConfigured(modelType, rawValue);

        // 未定義値は束縛されない(門番 UnlistedEnumFilterResolver へは届かない)
        Assert.False(result.IsModelSet);
        // 失敗の事実は ModelState に残る(= 画面には「読めなかった」側の文面が出る根拠)
        Assert.True(result.ErrorCount > 0);
    }

    [Theory]
    [MemberData(nameof(FilterShapesWithDefinedValue))]
    public void DefinedValue_StillBindsNormally(Type modelType, string rawValue)
    {
        // 本番と同じ構成で束縛する。
        // **この対のケースが無いと「常に拒否する」変異でも上の検査は緑のまま通る**
        var result = BindAsConfigured(modelType, rawValue);

        // 値が入ること
        Assert.True(result.IsModelSet);
        // エラーが積まれていないこと
        Assert.Equal(0, result.ErrorCount);
        // 値が失われていないこと(null へ潰れていない)
        Assert.NotNull(result.Model);
    }

    [Fact]
    public void ConfiguredBinderForEnums_IsStillTheEnumTypeModelBinder()
    {
        // 本番と同じ MVC サービスを組み立てる
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        using var provider = services.BuildServiceProvider();
        var metadataProvider = provider.GetRequiredService<IModelMetadataProvider>();
        var binderFactory = provider.GetRequiredService<IModelBinderFactory>();

        // 絞り込みが実際に使う形でバインダを選ばせる
        var binder = binderFactory.CreateBinder(new ModelBinderFactoryContext
        {
            Metadata = metadataProvider.GetMetadataForType(typeof(IncidentSeverity?)),
        });

        // **enum 専用バインダが選ばれ続けていること。** ここが別のバインダに変わると、
        // 上の 2 つの検査は「新しいバインダの挙動」を測ることになり、
        // 訂正後の記述(EnumTypeModelBinder の話)との対応が黙って切れる
        Assert.IsType<EnumTypeModelBinder>(binder);
    }

    [Fact]
    public void SuppressFlag_IsIgnored_ForBothUndefinedAndDefinedValues()
    {
        // **これが「設定で無効にはできない」という訂正後の記述の根拠そのもの。**
        // 公式リファレンス(net8.0)は suppressBindingUndefinedValueToEnumType を
        // "currently ignored" と明記しているが、文言を写すだけでは実装が変わったときに
        // 気付けない(このリポジトリが Stripe の API 版で学んだ形)ので挙動で見る。
        // 未定義値・定義済みの値の**両方**で比べるのは、本番の provider が
        // このフラグに true を渡すため —— true 側だけが定義済みの値まで拒否するように
        // 変わると、全画面のドロップダウンが壊れるのに未定義値の検査は緑のままになる。
        foreach (var rawValue in new[] { "99", nameof(IncidentSeverity.Level5) })
        {
            // フラグを倒した 2 通りの結果を取る
            var withoutFlag = BindWithSuppressFlag(typeof(IncidentSeverity), rawValue, false);
            var withFlag = BindWithSuppressFlag(typeof(IncidentSeverity), rawValue, true);

            // 束縛されたかどうかが一致すること
            Assert.Equal(withoutFlag.IsModelSet, withFlag.IsModelSet);
            // 積まれたエラーの件数も一致すること
            Assert.Equal(withoutFlag.ErrorCount, withFlag.ErrorCount);
        }
    }
}
