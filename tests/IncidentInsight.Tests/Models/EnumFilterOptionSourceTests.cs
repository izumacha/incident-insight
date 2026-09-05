// アクションの引数を走査するために使う(BindingFlags / ParameterInfo)
using System.Reflection;
// 絞り込みを配線しているコントローラ(検査対象の導出元)を使う
using IncidentInsight.Web.Controllers;
// 絞り込みの選択肢を作っている一元管理元(EnumLabels / IncidentTypeMapping)を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

/// <summary>
/// <b>enum の絞り込みで「採用してよいか」を決める手がかりと、ドロップダウンの選択肢を作る手がかりが
/// 一致している</b>ことと、<b>その判定(<c>Enum.IsDefined</c>)を使ってよい enum であること</b>を固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか。</b> <c>Controllers.Internal.UnlistedEnumFilterResolver</c> は
/// 採用の可否を <c>Enum.IsDefined</c> で決める(issue #208)。一方
/// <c>Views/Incidents/Index.cshtml</c> の <c>&lt;select&gt;</c> は
/// <c>EnumLabels.AllSeverities</c> / <c>IncidentTypeMapping.AllInDisplayOrder</c> から作る。
/// <b>この 2 つは別の宣言箇所</b>なので、片方にしかない値が生まれると
/// <see cref="IncidentInsight.Web.Models.Validation.SearchFilter"/> の表が守ろうとしている不変条件
/// 「<b>絞り込みに使った値は必ず選択肢にある</b>」がそのまま破れる ——
/// 利用者がそのフォームを再送信した時点で絞り込みが黙って解除される(issue #192 の症状)。</para>
///
/// <para><b>対象の enum は書き並べず、配線から導く。</b> 手書きの一覧にすると、
/// 3 つ目の enum 絞り込みを足した人が行を足し忘れた瞬間に<b>その enum だけが
/// ここのすべての検査から黙って外れる</b>(実測でその状態になっていた)。
/// 導出元は <c>IncidentsController.Index</c> が受ける <c>Nullable&lt;TEnum&gt;</c> の引数＝
/// <b>実際に解決処理へ通る入力の一覧</b>で、
/// <c>Controllers.UnlistedFilterValuePolicyTests</c> の Theory と同じ手がかり。</para>
///
/// <para><b>選択肢の出所だけは表で持つしかない。</b> 「どのコレクションがその enum の
/// ドロップダウンの出所か」は型からは導けないため <see cref="OptionSources"/> に書く。
/// 代わりに<b>表への載せ忘れを落とす</b>(<see cref="OptionSources_CoverEveryGovernedEnum"/>)ので、
/// 手書きが残るのは「対応の中身」だけで「対象の範囲」ではない
/// —— この repo が <c>LengthGovernanceExclusions</c> でやっているのと同じ形。</para>
///
/// <para><b>実測(この検査を足す前)。</b> <c>IncidentTypeKind</c> へ辞書に載せない値を 1 つ足すと、
/// ビルドも全テストも緑のまま次の 2 つが同時に起きた:</para>
/// <list type="number">
///   <item><description><b>絞り込み</b>: <c>Enum.IsDefined</c> は <c>true</c> なので採用され、
///     0 件が返るのに注意書きは出ず「フィルター適用中」バッジだけが出る。
///     <c>&lt;select&gt;</c> には一致する <c>&lt;option&gt;</c> が無いので
///     「種別（全て）」の位置に戻り、再送信で絞り込みが黙って解除される。</description></item>
///   <item><description><b>保存</b>: <c>ToDbString</c> は対応が無いと <c>kind.ToString()</c> へ
///     フォールバックするので、日本語の値が並ぶ列へ<b>英語の enum 名</b>が書かれる。
///     読み戻す <c>FromDbString</c> はその文字列を知らないので <c>Other</c>(その他)へ倒れ、
///     <b>保存した種別が黙って別の種別に化ける</b>。</description></item>
/// </list>
///
/// <para>どちらも例外もテストの失敗も出ないので気付く手掛かりが無い。
/// <b>対処法は「辞書へ 1 行足す」の 1 つだけ</b>なので、実行可能な指示として機械で落とせる。</para>
/// </remarks>
public class EnumFilterOptionSourceTests
{
    // 「その enum のドロップダウンの選択肢はどこから作るか」の対応表。
    //
    // 型からは導けないのでここだけ手で書く。載せ忘れは下の網羅ガードが落とすので、
    // 手書きが残るのは「対応の中身」だけで「対象の範囲」ではない
    private static readonly Dictionary<Type, Func<IEnumerable<Enum>>> OptionSources = new()
    {
        // インシデント種別: 手で保守する変換表のキーがそのまま選択肢になる(だから危うい)
        [typeof(IncidentTypeKind)] = () => IncidentTypeMapping.AllInDisplayOrder.Cast<Enum>(),
        // 重症度: Enum.GetValues から作るので現状は構造的に一致している
        [typeof(IncidentSeverity)] = () => EnumLabels.AllSeverities.Cast<Enum>()
    };

    // 検査対象の enum を、配線(IncidentsController.Index の Nullable<TEnum> 引数)から導く。
    //
    // 1 つも拾えなければ落とす(fail-closed)。引数の型を変えるような改修で
    // 「対象ゼロ＝全件緑」になり、この検査群が黙って死ぬのを防ぐ
    private static List<Type> GovernedEnumTypes()
    {
        // Index が受ける Nullable<TEnum> の引数から、その enum の型を取り出す
        var types = typeof(IncidentsController)
            .GetMethod(nameof(IncidentsController.Index))!
            .GetParameters()
            .Select(p => Nullable.GetUnderlyingType(p.ParameterType))
            .Where(t => t?.IsEnum == true)
            .Select(t => t!)
            // 実行ごとに順番が揺れないよう並びを固定する
            .OrderBy(t => t.FullName, StringComparer.Ordinal)
            .ToList();

        // 0 件は「対象が無くなった」より「引数の型か導出が変わった」可能性が高い
        Assert.True(types.Count > 0,
            $"{nameof(IncidentsController)}.{nameof(IncidentsController.Index)} に Nullable の enum 引数が 1 つも無い。"
            + "引数の型を変えたなら、この導出も同じ変更セットで直すこと。");
        return types;
    }

    // xUnit の [MemberData] が読める形へ、検査対象の enum を詰めて返す
    public static TheoryData<Type> GovernedEnums()
    {
        var data = new TheoryData<Type>();
        foreach (var type in GovernedEnumTypes()) data.Add(type);
        return data;
    }

    // 選択肢の出所の表が、配線されている enum を全網羅していること(fail-closed)。
    //
    // これが無いと、3 つ目の enum 絞り込みを足した人が表へ足し忘れた瞬間に
    // その enum だけが下の 3 つの検査から黙って外れる ——
    // 「対象ゼロ＝緑」ではなく「1 件だけ外れる」形なので、件数の減少すら痕跡にならない
    [Fact]
    public void OptionSources_CoverEveryGovernedEnum()
    {
        // 配線されている enum のうち、表に載っていないものを集める
        var missing = GovernedEnumTypes().Where(t => !OptionSources.ContainsKey(t)).ToList();
        // 1 つでもあれば、対処法(表へ 1 行足す)を名指しして落とす
        Assert.True(missing.Count == 0,
            $"次の enum が絞り込みに配線されているのに OptionSources に無い: "
            + $"{string.Join(", ", missing.Select(t => t.Name))}。"
            + "表へ「その enum のドロップダウンの選択肢を返す式」を 1 行足すこと"
            + "(足さないと、その enum だけが定義と選択肢の一致検査から黙って外れる)。");
    }

    // 表に、もう配線されていない enum が残っていないこと。
    // 残っていると「守っているつもりの対象」と実際の対象がずれ、表が信用できなくなる
    [Fact]
    public void OptionSources_HaveNoStaleEntries()
    {
        // 配線されている enum の集合
        var governed = GovernedEnumTypes().ToHashSet();
        // 表にあるが配線されていないものを集める
        var stale = OptionSources.Keys.Where(t => !governed.Contains(t)).ToList();
        Assert.True(stale.Count == 0,
            $"次の enum は OptionSources にあるが絞り込みに配線されていない: "
            + $"{string.Join(", ", stale.Select(t => t.Name))}。"
            + "配線を外したなら、表からも同じ変更セットで外すこと。");
    }

    // --- 定義 ⊆ 選択肢: 定義にあるのにドロップダウンに出ない値が無いこと -------------

    [Theory]
    [MemberData(nameof(GovernedEnums))]
    public void EveryDefinedEnumValue_IsOfferedInTheDropdown(Type enumType)
    {
        // その enum の選択肢を作る(表への載せ忘れは上のガードが落とすので、ここでは引くだけ)
        var options = OptionSources[enumType]().ToHashSet();

        // 定義値を 1 つずつ見て、選択肢に載っていることを確かめる
        Assert.All(Enum.GetValues(enumType).Cast<Enum>(), value =>
            Assert.True(options.Contains(value),
                $"{enumType.Name}.{value} がドロップダウンの選択肢に無い。"
                + "絞り込みは Enum.IsDefined で採用するのに選択肢には現れないため、"
                + "0 件になったうえで再送信すると絞り込みが黙って解除される(issue #192 / #208)。"
                + "選択肢の出所へその値を足すこと"
                + "(IncidentTypeKind なら IncidentTypeMapping の ToDb へ日本語の DB 文字列を 1 行。"
                + "足さないと ToDbString が英語の enum 名を日本語の列へ書き、読み戻しで Other へ化ける)。"));
    }

    // --- 選択肢 ⊆ 定義: ドロップダウンに定義に無い値が混ざっていないこと ---------------
    //
    // 片側だけを固定すると反対側が死角になる。解決処理と SearchFilter が前提として
    // 書いているのは<b>一致</b>なので、両方向を見る。
    //
    // <b>反対側の壊れ方はむしろ重い。</b> 変換表へ定義に無い値を書く
    // (`[(IncidentTypeKind)42] = "新種別"`)と、ドロップダウンに
    // `<option value="42">新種別</option>` が並ぶ。利用者がそれを<b>画面から選ぶ</b>と
    // Enum.IsDefined が false なので絞り込みは採用されず、「選べる値ではない」という
    // 注意書きが出て select は「（全て）」へ戻る ——URL を改ざんしなくても、
    // アプリが自分で出した選択肢を選んだだけで issue #192 の症状が起きる

    [Theory]
    [MemberData(nameof(GovernedEnums))]
    public void EveryDropdownOption_IsADefinedEnumValue(Type enumType)
    {
        // 選択肢を 1 つずつ見て、enum の定義に含まれることを確かめる
        Assert.All(OptionSources[enumType](), option =>
            Assert.True(Enum.IsDefined(enumType, option),
                $"ドロップダウンの選択肢にある {enumType.Name} の値 "
                + $"{Convert.ToInt64(option)} は定義に無い。"
                + "選択肢には並ぶのに絞り込みは Enum.IsDefined で弾くため、"
                + "画面から選んだだけで「選べる値ではない」と言われ、select が「（全て）」へ戻る。"
                + "enum へ定義を足すか、選択肢の出所からその行を外すこと。"));
    }

    // --- 前提: 採用の判定に Enum.IsDefined を使ってよい enum であること -------------
    //
    // Enum.IsDefined は<b>[Flags] の enum には使えない</b> —— `A|B` のような
    // 正当な組み合わせは単独の定義として存在しないので false になり、
    // 「画面が提示している組み合わせなのに『選べる値ではない』と言われる」ことになる。
    //
    // このリポジトリに [Flags] の enum は 1 つも無いので、解決処理側に分岐を先回りで
    // 用意しない(§6「将来を見越した過度な抽象化を避ける」)。代わりに<b>前提が崩れたら
    // 落ちる</b>ようにしておく —— 解決処理の解説は「enum の種類に依存する条件が 1 つも無い」
    // 「他の画面へ広げるのは配線だけで済む」と書いており、それを読んだ人が [Flags] の
    // 絞り込みを配線した瞬間に静かに壊れるため。落ちたときの対処は
    // 「解決処理に [Flags] の分岐を足す」で、実行可能な指示になっている。
    //
    // <b>対象は配線から導く</b>(手書きの [InlineData] にしない)。手書きだと、
    // まさに危ない [Flags] の絞り込みを足した人が行を足し忘れて、
    // 唯一のガードが対象外のまま全件緑で出荷される
    [Theory]
    [MemberData(nameof(GovernedEnums))]
    public void EnumsGatedByIsDefined_AreNotFlagsEnums(Type enumType)
    {
        // [Flags] が付いていないこと(付いていたら Enum.IsDefined は正しい判定にならない)
        Assert.False(enumType.IsDefined(typeof(FlagsAttribute), inherit: false),
            $"{enumType.Name} は [Flags] の enum なので、"
            + "UnlistedEnumFilterResolver の Enum.IsDefined による採用判定が使えない"
            + "(A|B のような正当な組み合わせが「定義に無い」と判定される)。"
            + "解決処理へ [Flags] の分岐を足すこと。");
    }
}
