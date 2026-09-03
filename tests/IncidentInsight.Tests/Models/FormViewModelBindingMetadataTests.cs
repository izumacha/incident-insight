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
    ///
    /// <para><b>選択肢をまだ持たない型も載せる。</b> 検査は「今ある選択肢を守る」だけでなく
    /// 「選択肢を<b>足したとき</b>に守らせる」ためのもので、後者の方が実際の事故に近い
    /// ——この PR 自体が「既存の画面へ選択肢のプロパティを足して全 POST を壊した」変更だった。
    /// 載っていない型へ足すと、その型だけが黙って検査の外に出る。</para>
    /// </remarks>
    public static TheoryData<Type> BoundFormViewModels()
    {
        // xUnit の [MemberData] が読める形へ詰め直す(一覧そのものは下の定数が持つ)
        var data = new TheoryData<Type>();
        foreach (var type in BoundFormViewModelTypes) data.Add(type);
        return data;
    }

    // 上の一覧の実体。TheoryData のままだと LINQ で走査できないため、
    // 「列挙全体を見る門番」と共有できるよう素のリストで持つ(写しは作らない)
    private static readonly IReadOnlyList<Type> BoundFormViewModelTypes = new[]
    {
        // インシデント登録・編集ウィザード(発生部署・原因分類の 2 つの選択肢を持つ)
        typeof(IncidentCreateEditViewModel),
        // なぜなぜ分析のサブフォーム(上の入れ子としても、単独の POST でも束縛される)
        typeof(CauseAnalysisFormViewModel),
        // 再発防止策のサブフォーム。現在は選択肢のプロパティを持たない(担当部署の
        // ドロップダウンは /PreventiveMeasures が ViewBag で渡している)が、
        // この PR と同じ移行 —— ViewBag から ViewModel へ選択肢を移す —— をしたときに
        // 検査へ入っていなければ、同じ「全 POST が失敗する」状態を作れてしまう。
        // 束縛箇所は PreventiveMeasuresController の Create / Edit、
        // IncidentMeasuresController.AddMeasure、および上のウィザードの Measures[i]
        typeof(MeasureFormViewModel),
        // 効果評価フォーム。現在は選択肢のプロパティを持たないが、Review.cshtml が
        // 段階の一覧(EffectivenessScale.All)をビューで直接回しているため、
        // それをコントローラへ移す変更が起きうる ——そのとき検査へ入っていないと
        // /PreventiveMeasures/Review が送信できなくなる
        typeof(ReviewViewModel),
        // ログインフォーム。選択肢を持つ見込みは薄いが、POST で束縛される型を
        // 「持ちそうか」で選ぶと判断がぶれる。束縛される型はすべて載せる
        typeof(LoginViewModel),
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

        // ここでは「0 件なら落とす」をしない —— 選択肢をまだ持たない型も
        // 意図的に列挙へ載せてあるため(BoundFormViewModels の解説を参照)。
        // 検出網が命名規約ごと死んでいないことは、列挙全体を見る
        // OptionsSuffix_MatchesSomething が別途 fail-closed で確かめる。

        // モデルバインドの対象になっていないこと([BindNever])。
        // 対象のままだと、利用者がフォームへ選択肢を送り込める(overposting)
        foreach (var property in optionProperties)
        {
            Assert.False(property.IsBindingAllowed,
                $"{viewModelType.Name}.{property.PropertyName} に [BindNever] を付けること。"
                + "選択肢はコントローラが詰めるもので、利用者が送り込むものではない。");
        }

        // モデルバインド直後の状態を再現する。選択肢は POST ボディに含まれないので、
        // バインダはこのプロパティに触れない
        // (required でも Activator 経由の生成は検査されないので、本番と同じ状態になる)
        var boundModel = Activator.CreateInstance(viewModelType)!;

        // 選択肢のプロパティを明示的に null にしてから検証へ入れる。
        //
        // これが無いと<b>初期値(= new())を持つ選択肢では検査が空振りする</b>——
        // 非 null なら自動で足された [Required] は満たされてしまうので、
        // [ValidateNever] を外しても何のエラーも出ない。実測で、CauseCategoryOptions の
        // [ValidateNever] を 2 か所とも消しても全件緑・件数も不変のまま通った。
        // それではこのクラスの解説が約束している「初期値の有無に依存しない」が成り立たず、
        // 実際に守られているのは初期値を持たない DepartmentOptions だけになる。
        // null に揃えれば、どの選択肢も同じ条件(バインダが触れなかった状態)で検査に掛かる
        foreach (var property in optionProperties)
        {
            // メタデータのプロパティ名から実際の CLR プロパティを引く
            var clrProperty = viewModelType.GetProperty(property.PropertyName!);
            // 書き込めないプロパティは飛ばす(計算プロパティなど)
            if (clrProperty?.CanWrite != true) continue;
            // バインダが触れなかった状態＝null にする
            clrProperty.SetValue(boundModel, null);
        }

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
                // ModelStateDictionary は KeyValuePair<string, ModelStateEntry?> として列挙するので、
                // 値が null でないものだけに絞ってから中身を読む(素で読むと CS8602 が出る)
                .Where(entry => entry.Value is not null)
                .SelectMany(entry => entry.Value!.Errors.Select(e => $"{entry.Key}: {e.ErrorMessage}"))
                .ToList();

            Assert.True(errors.Count == 0,
                $"{viewModelType.Name}.{property.PropertyName} に [ValidateNever] を付けること。"
                + "非 null 許容の参照型には MVC が [Required] を自動で足すため、"
                + "フォームが送らないこのプロパティで ModelState.IsValid が常に false になり、"
                + "その画面の POST が 1 件も通らなくなる。"
                + $"実際に積まれたエラー: {string.Join(" / ", errors)}");
        }
    }

    // 命名規約とコレクションという 2 つの手がかりが、どちらも生きていることを確かめる。
    //
    // 型ごとに「0 件なら落とす」と書けない —— 選択肢をまだ持たない型
    // (MeasureFormViewModel)を意図的に列挙へ載せているため、型ごとの門番にすると
    // その型で必ず落ちる。かといって門番を丸ごと外すと、命名規約を変えたり
    // ViewModel の形が変わったりしたときに<b>全部の型で対象ゼロ＝全件緑</b>になり、
    // 検出網が黙って死ぬ(この repo が繰り返し当たっている形)。
    // そこで判定は型ごとに掛けたまま、<b>門番だけを列挙全体へ移す</b>。
    // 「どこかに 1 つは選択肢がある」「どこかに 1 つはコレクションがある」は、
    // 列挙に選択肢を持つ型が 1 つでもある限り必ず成り立つ
    [Fact]
    public void OptionsSuffix_MatchesSomething()
    {
        // 列挙した型すべてのプロパティを集める
        var allProperties = BoundFormViewModelTypes
            .SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            .ToList();

        // 命名規約に当てはまるプロパティが列挙全体で 1 つも無いなら、
        // 規約が変わったか対象の型がすべて外れている
        Assert.True(
            allProperties.Any(p => p.Name.EndsWith(OptionsSuffix, StringComparison.Ordinal)),
            $"列挙した ViewModel のどれにも *{OptionsSuffix} という名前のプロパティが無い。"
            + "命名規約を変えたなら、この検査も同じ変更セットで直すこと"
            + "(直さないと、選択肢のプロパティが検査から黙って外れる)。");

        // コレクションという手がかりも生きていること(取りこぼし照合が空振りしないため)
        Assert.True(
            allProperties.Any(p => p.PropertyType != typeof(string)
                                   && typeof(System.Collections.IEnumerable).IsAssignableFrom(p.PropertyType)),
            "列挙した ViewModel のどれにもコレクション型のプロパティが無い。"
            + "取りこぼしの照合はコレクションを手がかりにしているので、形が変わったならここも直すこと。");
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

        // ここでも「0 件なら落とす」はしない —— コレクションを 1 つも持たない型
        // (MeasureFormViewModel)を意図的に載せているため。手がかりが死んでいないことは
        // 列挙全体を見る OptionsSuffix_MatchesSomething が確かめる。

        // 選択肢でないコレクション = フォームが実際に送るサブフォームの繰り返し。
        // 現在は登録ウィザードの対策リストだけで、これは利用者の入力なので束縛・検証の対象で正しい。
        // ここへ足すのは「利用者が送るコレクション」だけ ——選択肢を足して黙らせないこと。
        //
        // キーは<b>(型, プロパティ名)の組</b>にする。名前だけで持つと、別の型に同じ名前の
        // コレクションが現れたとき——それが本当は選択肢でも——巻き添えで除外され、
        // 命名規約の検査も [BindNever] / [ValidateNever] の検査も同時に素通りする。
        // この repo が LengthGovernanceExclusions で完全修飾名をキーにしているのと同じ理由
        var postedCollections = new HashSet<(Type Owner, string Property)>
        {
            // 再発防止策のサブフォーム(利用者が入力し、そのまま保存される)
            (typeof(IncidentCreateEditViewModel), nameof(IncidentCreateEditViewModel.Measures)),
        };

        foreach (var name in collectionProperties)
        {
            // その型のプロパティとして「利用者が送るコレクション」に登録済みなら対象外
            if (postedCollections.Contains((viewModelType, name))) continue;
            // それ以外のコレクションは選択肢のはずなので、命名規約に当てはまっていること
            Assert.True(name.EndsWith(OptionsSuffix, StringComparison.Ordinal),
                $"{viewModelType.Name}.{name} はコレクションだが *{OptionsSuffix} という名前ではない。"
                + $"コントローラが詰める選択肢なら名前を *{OptionsSuffix} に揃えること"
                + "(揃えないと [BindNever] / [ValidateNever] の検査から黙って外れる)。"
                + "利用者が送るコレクションなら postedCollections へ理由とともに足すこと。");
        }
    }
}
