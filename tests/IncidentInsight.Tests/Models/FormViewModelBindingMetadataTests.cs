// ViewModel の型をリフレクションで走査するために使う
using System.Reflection;
using IncidentInsight.Web.Models.ViewModels;
// 検証器へ渡す ActionContext を組み立てるために使う
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace IncidentInsight.Tests.Models;

/// <summary>
/// POST でモデルバインドされるフォーム ViewModel の「ドロップダウン選択肢」プロパティが、
/// モデルバインドと入力検証の<b>どちらの対象にもなっていない</b>ことを固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(実測)。</b> このプロジェクトは <c>&lt;Nullable&gt;enable&lt;/Nullable&gt;</c> なので、
/// MVC は<b>非 null 許容の参照型プロパティに <c>[Required]</c> を自動で足す</b>
/// (<c>MvcOptions.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes</c> は既定の <c>false</c>)。
/// 選択肢はコントローラが詰めるものでフォームは送らないため、モデルバインド後は
/// <b>初期値が無ければ null のまま</b>になり、自動で足された <c>[Required]</c> が必ず落ちる。
/// 実測では <c>IncidentCreateEditViewModel.DepartmentOptions</c> を
/// <c>required</c>(＝初期値なし)にした時点で、<c>ModelState</c> に
/// 「The DepartmentOptions field is required.」が積まれ <c>ModelState.IsValid</c> が常に false になり、
/// <b>インシデントを 1 件も登録・編集できなくなった</b>。対応する入力欄が画面に無いので
/// 利用者には直しようがなく、しかも日本語 UI に英語の既定メッセージが出る。</para>
///
/// <para><b>なぜ既存のテストで捕まらないのか。</b> コントローラ級のテストは
/// <c>ModelState</c> を手で組み立て、モデルバインドと入力検証を<b>通らない</b>。
/// そのため 607 件すべてが緑のまま、実際の画面だけが完全に壊れる ——
/// この repo が繰り返し当たっている「テストは緑なのに特定の経路でだけ壊れる」形そのもの。
/// ここだけが実際の <see cref="IModelMetadataProvider"/> を通して MVC の判断を見る。</para>
///
/// <para><b>初期値があれば今は通る、では守りにならない。</b> <c>CauseCategoryOptions</c> は
/// <c>= new()</c> の初期値があるおかげで自動 <c>[Required]</c> を通せているが、
/// 初期値を外した瞬間に同じ「全 POST が失敗する」状態になる。役割が同じプロパティの
/// 片方だけを守ると差が読み取れなくなるので、<b>初期値の有無に依存しない条件</b>
/// (バインド対象か / 検証対象か)で見る。</para>
///
/// <para><b>対象の導き方。</b> 型は「POST でモデルバインドされるフォーム ViewModel」を
/// 明示的に列挙し、プロパティは命名規約(<c>Options</c> で終わる)で拾う。
/// どちらも 0 件になったら fail-closed で落とす —— 命名や置き場所を変えたときに
/// 「対象ゼロ＝緑」で検出網が黙って死ぬのを防ぐ。</para>
/// </remarks>
public class FormViewModelBindingMetadataTests
{
    // 「コントローラが詰める選択肢」を表すプロパティ名の接尾辞。
    // 型名や名前空間ではなく役割で拾うので、置き場所を変えても対象から外れない
    private const string OptionsSuffix = "Options";

    /// <summary>
    /// POST でモデルバインドされるフォーム ViewModel。
    /// </summary>
    /// <remarks>
    /// <para>ここは<b>意図的に手書きの列挙</b>にしてある。「POST で束縛されるか」を
    /// 型から機械的に見分ける確かな目印が無いためで、アセンブリ内の全 ViewModel を
    /// 対象にすると、コントローラが組み立てるだけの表示用 ViewModel
    /// (<c>IncidentListViewModel</c> / <c>IncidentDetailViewModel</c> など)まで
    /// <c>[BindNever]</c> を要求してしまう ——実行不能な指示を出す検出網は、
    /// いずれ緩められる(この repo が繰り返し避けている形)。</para>
    ///
    /// <para><b>フォーム ViewModel を新しく足す人がここへ 1 行足すこと。</b>
    /// 足し忘れるとその型だけが検査から外れる。ただし壊れ方は静かではない ——
    /// 選択肢を持つ POST 束縛の型を足せば、その画面の POST が最初の手動確認で必ず失敗する。</para>
    /// </remarks>
    public static TheoryData<Type> BoundFormViewModels() => new()
    {
        // インシデント登録・編集ウィザード(発生部署・原因分類の 2 つの選択肢を持つ)
        typeof(IncidentCreateEditViewModel),
        // なぜなぜ分析のサブフォーム(上の入れ子としても、単独の POST でも束縛される)
        typeof(CauseAnalysisFormViewModel),
    };

    // 選択肢のプロパティが、モデルバインドと入力検証のどちらの対象にもなっていないこと。
    //
    // 2 つを 1 つのテストで見るのは、片方だけでは守れないため:
    //   - 検証だけ外すと overposting が残る(利用者が選択肢を送り込める)
    //   - バインドだけ外しても、自動で足された [Required] は検証側の判断なので残る
    //     (=この検査が無かったときに実際に起きた「全 POST が失敗する」状態)
    //
    // 検証側は<b>メタデータではなく実際の検証結果</b>で判定する。[ValidateNever] は
    // ModelMetadata.IsRequired を false に<b>しない</b>(自動で足された [Required] は
    // メタデータ上に残り、検証の実行時に PropertyValidationFilter が飛ばす)ので、
    // IsRequired を見る書き方は「属性を付けても落ちたまま」になり、直しようがない
    // 検出網になる —— 実測でそうなった。実際に検証器へ通せば、どのメタデータ面に
    // 現れるかに依存せず「エラーが積まれるかどうか」だけを見られる
    [Theory]
    [MemberData(nameof(BoundFormViewModels))]
    public void OptionProperties_AreNeitherBoundNorValidated(Type viewModelType)
    {
        // 本番と同じ構成の MVC サービスを組み立てる。
        // 自前の MvcOptions を渡さないのが要点 —— 既定値のまま読むことで、
        // 「非 null 許容の参照型に [Required] を自動で足す」本番の挙動をそのまま見る
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddControllersWithViews();
        using var provider = services.BuildServiceProvider();
        var metadataProvider = provider.GetRequiredService<IModelMetadataProvider>();
        var validator = provider.GetRequiredService<IObjectModelValidator>();

        // 対象の型のプロパティメタデータを取り出す
        var metadata = metadataProvider.GetMetadataForType(viewModelType);

        // 命名規約に当てはまるプロパティ(コントローラが詰める選択肢)だけを拾う
        var optionProperties = metadata.Properties
            .Where(p => p.PropertyName != null
                        && p.PropertyName.EndsWith(OptionsSuffix, StringComparison.Ordinal))
            .ToList();

        // 1 つも見つからないのは「選択肢が無くなった」より「命名規約が変わった」可能性が高い。
        // 黙って 0 件で緑にすると検出網が消えるので、ここで落として人に決めさせる
        Assert.True(optionProperties.Count > 0,
            $"{viewModelType.Name} に *{OptionsSuffix} という名前のプロパティが 1 つも無い。"
            + "命名規約を変えたなら、この検査も同じ変更セットで直すこと"
            + "(直さないと、選択肢のプロパティが検査から黙って外れる)。");

        // モデルバインドの対象になっていないこと([BindNever])。
        // 対象のままだと、利用者がフォームへ選択肢を送り込める(overposting)
        foreach (var property in optionProperties)
        {
            Assert.False(property.IsBindingAllowed,
                $"{viewModelType.Name}.{property.PropertyName} に [BindNever] を付けること。"
                + "選択肢はコントローラが詰めるもので、利用者が送り込むものではない。");
        }

        // モデルバインド直後の状態を再現する。選択肢は POST ボディに含まれないので、
        // 初期値を持たないプロパティは null のまま検証へ入る
        // (required でも Activator 経由の生成は検査されないので、本番と同じ状態になる)
        var boundModel = Activator.CreateInstance(viewModelType)!;

        // 実際の検証器へ通す(本番のリクエストで走るのと同じ経路)
        var modelState = new ModelStateDictionary();
        var actionContext = new ActionContext(
            new DefaultHttpContext(), new RouteData(), new ActionDescriptor(), modelState);
        validator.Validate(actionContext, validationState: null, prefix: string.Empty, model: boundModel);

        // 選択肢のプロパティにエラーが積まれていないこと。
        // 他の必須項目(Department 等)のエラーは当然出るので、キーで絞って見る
        foreach (var property in optionProperties)
        {
            // このプロパティ自身と、その配下(Options[0].Text など)のキーを拾う
            var errors = modelState
                .Where(entry => entry.Key == property.PropertyName
                                || entry.Key.StartsWith($"{property.PropertyName}.", StringComparison.Ordinal)
                                || entry.Key.StartsWith($"{property.PropertyName}[", StringComparison.Ordinal))
                .SelectMany(entry => entry.Value.Errors.Select(e => $"{entry.Key}: {e.ErrorMessage}"))
                .ToList();

            Assert.True(errors.Count == 0,
                $"{viewModelType.Name}.{property.PropertyName} に [ValidateNever] を付けること。"
                + "非 null 許容の参照型には MVC が [Required] を自動で足すため、"
                + "フォームが送らないこのプロパティで ModelState.IsValid が常に false になり、"
                + "その画面の POST が 1 件も通らなくなる。"
                + $"実際に積まれたエラー: {string.Join(" / ", errors)}");
        }
    }

    // 上の命名規約が選択肢のプロパティを取りこぼしていないことを、判定とは独立な手がかりで照合する。
    //
    // 手がかりを変えるのが要点(この repo が LengthGovernedTypes_CoverEveryOwnedDbSet 等で
    // 使っているのと同じやり方)。命名規約だけに頼ると、選択肢を 2 つ持つ型で片方を
    // 規約から外れた名前へ改名しても、もう片方が拾えるぶん「0 件」にならず上の門番を
    // すり抜け、改名した方だけが黙って検査から外れる。
    //
    // 独立な手がかりは CLR の型: 「ドロップダウンの選択肢」は必ずコレクションであり、
    // フォームが送る入力欄(string / DateTime? / enum? など)とは形が違う。
    // 対象の型が持つ「コレクション型のプロパティ」は、選択肢か、あるいは
    // フォームが実際に送るサブフォームの繰り返し(Measures)のどちらかしかない
    [Theory]
    [MemberData(nameof(BoundFormViewModels))]
    public void OptionsSuffix_CoversEveryDropdownCollection(Type viewModelType)
    {
        // 対象の型が宣言しているコレクション型のプロパティを集める(string は文字の列なので除く)
        var collectionProperties = viewModelType
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType != typeof(string)
                        && typeof(System.Collections.IEnumerable).IsAssignableFrom(p.PropertyType))
            .Select(p => p.Name)
            .ToList();

        // コレクションが 1 つも読めないなら手がかりが死んでいる。fail-closed で落とす
        Assert.True(collectionProperties.Count > 0,
            $"{viewModelType.Name} にコレクション型のプロパティが 1 つも無い。"
            + "この照合はコレクションを手がかりにしているので、形が変わったならここも直すこと。");

        // 選択肢でないコレクション = フォームが実際に送るサブフォームの繰り返し。
        // 現在は登録ウィザードの対策リストだけで、これは利用者の入力なので束縛・検証の対象で正しい。
        // ここへ足すのは「利用者が送るコレクション」だけ ——選択肢を足して黙らせないこと
        var postedCollections = new HashSet<string>(StringComparer.Ordinal)
        {
            // 再発防止策のサブフォーム(利用者が入力し、そのまま保存される)
            nameof(IncidentCreateEditViewModel.Measures),
        };

        foreach (var name in collectionProperties)
        {
            // 利用者が送るコレクションとして登録済みなら対象外
            if (postedCollections.Contains(name)) continue;
            // それ以外のコレクションは選択肢のはずなので、命名規約に当てはまっていること
            Assert.True(name.EndsWith(OptionsSuffix, StringComparison.Ordinal),
                $"{viewModelType.Name}.{name} はコレクションだが *{OptionsSuffix} という名前ではない。"
                + $"コントローラが詰める選択肢なら名前を *{OptionsSuffix} に揃えること"
                + "(揃えないと [BindNever] / [ValidateNever] の検査から黙って外れる)。"
                + "利用者が送るコレクションなら postedCollections へ理由とともに足すこと。");
        }
    }
}
