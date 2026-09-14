// 実際に効くモデルバインダ(enum 専用)をそのまま動かして挙動を測るため
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
// クエリ文字列の値プロバイダ(?severity=99 と同じ経路で値を渡すため)
using Microsoft.AspNetCore.Http;
// ログを捨てるためのヌルファクトリ(バインダのコンストラクタが要求する)
using Microsoft.Extensions.Logging.Abstractions;
// グローバリゼーション(値プロバイダが要求するカルチャ指定)
using System.Globalization;
// 検査対象の enum(このリポジトリで実際に絞り込みに使っている型)
using IncidentInsight.Web.Models.Enums;

// 既存の Models 配下テストと同じ名前空間に置く
namespace IncidentInsight.Tests.Models;

/// <summary>
/// <b>定義に無い enum 値がモデルバインドでどう扱われるか</b>を、実際に効くバインダを
/// 動かして固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(issue #215)。</b> このリポジトリのコントローラ級テストは
/// <c>controller.Index((IncidentSeverity)99, …)</c> と<b>アクションを直接呼ぶ</b>ので、
/// モデルバインドを一度も通らない。そのためかつて
/// 「<c>?severity=99</c> は変換が通り <c>ModelState</c> にエラーを積まない(実測)」
/// という<b>誤った結論</b>が「実測」としてドキュメントに残り、旗と文面を 2 つに分ける
/// 判断の根拠になっていた。<b>測る場所を、実際に効く場所に合わせる</b> ——
/// <c>AuditedEntityPhiClassificationTests</c> が「CLR のリフレクションではなく
/// EF Core のモデルを読む」としているのと同じ規則で、ここではバインダ自身を動かす。</para>
///
/// <para><b>何を固定するのか。</b> 訂正後の記述
/// (<see cref="IncidentInsight.Web.Models.Validation.SearchFilter"/> /
/// <see cref="IncidentInsight.Web.Controllers.Internal.UnlistedEnumFilterResolver"/>)は
/// 「未定義値の拒否を<b>設定で無効にする手段は無い</b>」を前提に、門番を残す理由を
/// 組み立てている。その前提が上流の変更で崩れたら記述ごと見直す必要があるので、
/// <b>前提そのもの</b>をここで固定する。文言ではなく<b>挙動</b>を見るのが要点で、
/// 「公式ドキュメントにこう書いてある」を写すだけでは、実装が変わったときに
/// 気付けない(このリポジトリが Stripe の API 版で学んだ形と同じ)。</para>
///
/// <para><b>落ちたときの直し方。</b> 上流がフラグを尊重し始めた / 設定が追加された
/// ということなので、<b>テストを緩めるのではなく</b>上の 2 か所(と
/// <c>PreventiveMeasuresController.UpdateStatus</c> ・ <c>CLAUDE.md</c>)の記述を
/// 新しい事実へ合わせる。門番自体は (b)(c) の理由が残るので撤去しない。</para>
/// </remarks>
public class UndefinedEnumModelBindingTests
{
    /// <summary>
    /// クエリ文字列 1 件をそのまま渡す束縛文脈を組み立て、束縛を実行して結果を返す。
    /// </summary>
    /// <param name="suppressBindingUndefinedValueToEnumType">
    /// バインダのコンストラクタが受け取る「未定義値への束縛を抑止しない」フラグ。
    /// <b>この引数が効くかどうかがこのテストの主題</b>なので、呼び出し側から与える。
    /// </param>
    private static (bool IsModelSet, int ErrorCount, object? Model) BindQueryValue<TEnum>(
        string rawValue,
        bool suppressBindingUndefinedValueToEnumType)
        where TEnum : struct, Enum
    {
        // 実際に効く enum 専用バインダを、指定されたフラグで組み立てる
        var binder = new EnumTypeModelBinder(
            suppressBindingUndefinedValueToEnumType,
            typeof(TEnum),
            NullLoggerFactory.Instance);

        // ?severity=<rawValue> と同じ形で値を供給する(実際の経路と同じ値プロバイダを使う)
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            // 束縛名と値の組(モデル名はコントローラの引数名に相当する)
            ["value"] = rawValue,
        });

        // 束縛の文脈を組み立てる(モデル名・状態・値の出どころ・メタデータ)
        var context = new DefaultModelBindingContext
        {
            // 束縛する引数の名前
            ModelName = "value",
            // 束縛エラーが積まれる先(ここを観測する)
            ModelState = new ModelStateDictionary(),
            // クエリ文字列を値の出どころにする
            ValueProvider = new QueryStringValueProvider(
                BindingSource.Query, query, CultureInfo.InvariantCulture),
            // 束縛先の型情報
            ModelMetadata = new EmptyModelMetadataProvider().GetMetadataForType(typeof(TEnum)),
        };

        // 束縛を実行する(同期的に完了するので待ち合わせる)
        binder.BindModelAsync(context).GetAwaiter().GetResult();

        // 「値が入ったか」「エラーが積まれたか」「入った値は何か」を返す。
        // **ここで ModelState.IsValid を見てはいけない** —— バインダが作る項目は
        // 検証前(Unvalidated)なので、束縛が成功しても IsValid は false のままになる
        // (実測: raw="Level5" は Model=Level5 が入るのに IsValid=false・エラー 0 件)。
        // 「エラーが積まれたか」を見たいのだから、数えるのは ErrorCount の方
        return (context.Result.IsModelSet, context.ModelState.ErrorCount, context.Result.Model);
    }

    [Theory]
    // 重症度の未定義値(issue #208 / #215 が例として挙げている URL)
    [InlineData(false)]
    // フラグを立てても同じであることを見る(= フラグが効かない)
    [InlineData(true)]
    public void UndefinedSeverity_IsRejectedRegardlessOfSuppressFlag(bool suppress)
    {
        // ?severity=99 に相当する値を束縛する
        var result = BindQueryValue<IncidentSeverity>("99", suppress);

        // 未定義値は束縛されない(門番 UnlistedEnumFilterResolver へは届かない)
        Assert.False(result.IsModelSet);
        // 失敗の事実は ModelState に残る(= 読めなかった側として扱われる根拠)
        Assert.True(result.ErrorCount > 0);
    }

    [Theory]
    // 対策ステータスの未定義値(/PreventiveMeasures?status=99)
    [InlineData(false)]
    // こちらもフラグの有無で変わらないことを見る
    [InlineData(true)]
    public void UndefinedMeasureStatus_IsRejectedRegardlessOfSuppressFlag(bool suppress)
    {
        // ?status=99 に相当する値を束縛する
        var result = BindQueryValue<MeasureStatus>("99", suppress);

        // 未定義値は束縛されない
        Assert.False(result.IsModelSet);
        // 失敗の事実は ModelState に残る
        Assert.True(result.ErrorCount > 0);
    }

    [Fact]
    public void SuppressFlag_DoesNotChangeTheOutcome()
    {
        // フラグを倒した 2 通りの結果を取る
        var withoutFlag = BindQueryValue<IncidentSeverity>("99", suppressBindingUndefinedValueToEnumType: false);
        var withFlag = BindQueryValue<IncidentSeverity>("99", suppressBindingUndefinedValueToEnumType: true);

        // **フラグは公式に "currently ignored"**。両者が一致することが、
        // 「設定で無効にはできない」という訂正後の記述の根拠そのもの
        Assert.Equal(withoutFlag.IsModelSet, withFlag.IsModelSet);
        Assert.Equal(withoutFlag.ErrorCount, withFlag.ErrorCount);
    }

    [Fact]
    public void DefinedSeverity_StillBindsNormally()
    {
        // 定義済みの値は今までどおり束縛される(誤検知が出ないことの確認)。
        // これが無いと「常に拒否する」変異でも上の 3 つは緑のまま通る
        var result = BindQueryValue<IncidentSeverity>(nameof(IncidentSeverity.Level5), suppressBindingUndefinedValueToEnumType: false);

        // 値が入ること
        Assert.True(result.IsModelSet);
        // エラーが積まれていないこと
        Assert.Equal(0, result.ErrorCount);
        // 入った値が期待どおりであること
        Assert.Equal(IncidentSeverity.Level5, result.Model);
    }
}
