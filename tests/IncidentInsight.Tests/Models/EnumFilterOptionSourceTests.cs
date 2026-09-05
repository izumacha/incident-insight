// 絞り込みの選択肢を作っている一元管理元(EnumLabels / IncidentTypeMapping)を検証対象として取り込む
using IncidentInsight.Web.Models.Enums;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

/// <summary>
/// <b>enum の絞り込みで「採用してよいか」を決める手がかりと、ドロップダウンの選択肢を作る手がかりが
/// 一致している</b>ことを固定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか。</b> <c>Controllers.Internal.UnlistedEnumFilterResolver</c> は
/// 採用の可否を <c>Enum.IsDefined</c> で決める(issue #208)。一方
/// <c>Views/Incidents/Index.cshtml</c> の <c>&lt;select&gt;</c> は
/// <c>EnumLabels.AllSeverities</c> / <c>IncidentTypeMapping.AllInDisplayOrder</c> から作る。
/// <b>この 2 つは別の宣言箇所</b>なので、片方にしかない値が生まれると
/// 「採用されるのに一致する <c>&lt;option&gt;</c> が無い」状態になり、
/// <see cref="IncidentInsight.Web.Models.Validation.SearchFilter"/> の表が守ろうとしている不変条件
/// 「<b>絞り込みに使った値は必ず選択肢にある</b>」がそのまま破れる ——
/// 利用者がそのフォームを再送信した時点で絞り込みが黙って解除される(issue #192 の症状)。</para>
///
/// <para><b>重症度は既に一致している。</b> <c>EnumLabels.AllSeverities</c> は
/// <c>Enum.GetValues&lt;IncidentSeverity&gt;()</c> から作るので、定義を足せば選択肢も自動で増える。
/// <b>危ういのはインシデント種別</b>で、<c>IncidentTypeMapping.AllInDisplayOrder</c> の実体は
/// <b>手で保守する辞書</b>(<c>ToDb</c>)のキー。
/// <c>IncidentTypeMapping</c> の解説は「追加 / 改称時はここの両辞書を必ず同時に更新すること」と
/// 書いているが、<b>それを機械で守るものが無かった</b>。</para>
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
    // インシデント種別のドロップダウンの選択肢が、enum の定義を 1 つも取りこぼしていないこと。
    //
    // 「辞書のキーが enum の定義の部分集合か」ではなく<b>全網羅か</b>を見る。
    // 部分集合だけを見ると、まさに問題の「定義にあるのに選択肢に無い値」が素通りする
    public static TheoryData<IncidentTypeKind> AllIncidentTypeKinds()
    {
        // xUnit の [MemberData] が読める形へ、enum の全定義値を詰める
        var data = new TheoryData<IncidentTypeKind>();
        foreach (var kind in Enum.GetValues<IncidentTypeKind>()) data.Add(kind);
        return data;
    }

    // 定義値 1 つずつに掛ける(まとめて 1 件で見ると、落ちたときにどの値が漏れたか分からない)
    [Theory]
    [MemberData(nameof(AllIncidentTypeKinds))]
    public void EveryIncidentTypeKind_IsOfferedInTheDropdown(IncidentTypeKind kind)
    {
        // ドロップダウンの選択肢を作っている一覧に、その定義値が載っていること
        Assert.True(IncidentTypeMapping.AllInDisplayOrder.Contains(kind),
            $"IncidentTypeKind.{kind} が IncidentTypeMapping の変換表に無い。"
            + "絞り込みは Enum.IsDefined で採用するのにドロップダウンには現れないため、"
            + "0 件になったうえで再送信すると絞り込みが黙って解除される(issue #192 / #208)。"
            + "さらに ToDbString が英語の enum 名を日本語の列へ書き、読み戻しで Other へ化ける。"
            + "IncidentTypeMapping の ToDb へ日本語の DB 文字列を 1 行足すこと。");
    }

    // 重症度も同じ不変条件を満たすこと。
    //
    // 現状 EnumLabels.AllSeverities は Enum.GetValues から作るので構造的に満たされているが、
    // <b>出所が変わったときに落ちる</b>ことに意味がある —— 種別と同じ「手で保守する一覧」へ
    // 差し替えられた瞬間、種別が踏んだのとまったく同じ穴が重症度にも開く。
    // 「今は自動だから検査は要らない」にすると、その差し替えを誰も見ていない状態になる
    [Theory]
    [MemberData(nameof(AllIncidentSeverities))]
    public void EveryIncidentSeverity_IsOfferedInTheDropdown(IncidentSeverity severity)
    {
        // ドロップダウンの選択肢を作っている一覧に、その定義値が載っていること
        Assert.True(EnumLabels.AllSeverities.Contains(severity),
            $"IncidentSeverity.{severity} が EnumLabels.AllSeverities に無い。"
            + "絞り込みは Enum.IsDefined で採用するのにドロップダウンには現れないため、"
            + "0 件になったうえで再送信すると絞り込みが黙って解除される(issue #192 / #208)。");
    }

    // 重症度の全定義値(上の Theory のケース)
    public static TheoryData<IncidentSeverity> AllIncidentSeverities()
    {
        // xUnit の [MemberData] が読める形へ、enum の全定義値を詰める
        var data = new TheoryData<IncidentSeverity>();
        foreach (var severity in Enum.GetValues<IncidentSeverity>()) data.Add(severity);
        return data;
    }

    // --- 逆向き: 選択肢に「定義に無い値」が混ざっていないこと ---------------------
    //
    // 上の 2 つが見るのは「定義 ⊆ 選択肢」だけ。解決処理と SearchFilter が前提として
    // 書いているのは<b>一致</b>なので、片側だけを固定すると反対側が死角になる。
    //
    // <b>反対側の壊れ方はむしろ重い。</b> 変換表へ定義に無い値を書く
    // (`[(IncidentTypeKind)42] = "新種別"`)と、ドロップダウンに
    // `<option value="42">新種別</option>` が並ぶ。利用者がそれを<b>画面から選ぶ</b>と
    // Enum.IsDefined が false なので絞り込みは採用されず、「選べる値ではない」という
    // 注意書きが出て select は「種別（全て）」へ戻る ——URL を改ざんしなくても、
    // アプリが自分で出した選択肢を選んだだけで issue #192 の症状が起きる。

    // インシデント種別の選択肢が、enum の定義に無い値を含まないこと
    [Fact]
    public void EveryIncidentTypeOption_IsADefinedEnumValue()
    {
        // 選択肢を 1 つずつ見て、enum の定義に含まれることを確かめる
        Assert.All(IncidentTypeMapping.AllInDisplayOrder, kind =>
            Assert.True(Enum.IsDefined(kind),
                $"IncidentTypeMapping の変換表にある {(int)kind} は IncidentTypeKind の定義に無い。"
                + "ドロップダウンには並ぶのに絞り込みは Enum.IsDefined で弾くため、"
                + "画面から選んだだけで「選べる値ではない」と言われ、select が「（全て）」へ戻る。"
                + "enum へ定義を足すか、変換表からその行を外すこと。"));
    }

    // 重症度の選択肢も同じく、enum の定義に無い値を含まないこと
    [Fact]
    public void EveryIncidentSeverityOption_IsADefinedEnumValue()
    {
        // 選択肢を 1 つずつ見て、enum の定義に含まれることを確かめる
        Assert.All(EnumLabels.AllSeverities, severity =>
            Assert.True(Enum.IsDefined(severity),
                $"EnumLabels.AllSeverities にある {(int)severity} は IncidentSeverity の定義に無い。"
                + "ドロップダウンには並ぶのに絞り込みは Enum.IsDefined で弾くため、"
                + "画面から選んだだけで「選べる値ではない」と言われ、select が「（全て）」へ戻る。"));
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
    // 「解決処理に [Flags] の分岐を足す」で、実行可能な指示になっている
    [Theory]
    // 現在この判定を通っている 2 つの enum
    [InlineData(typeof(IncidentTypeKind))]
    [InlineData(typeof(IncidentSeverity))]
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
