// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// <b>enum として束縛できたのに、その enum の定義に無い値</b>を「受け取ったが採用しなかった」として
/// 拾う共有処理。<c>/Incidents</c>(一覧)の種別・重症度が使う。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(issue #208)。</b> <c>?severity=99</c> は MVC の
/// <c>SimpleTypeModelBinder</c> が <c>EnumConverter</c> 経由で <c>(IncidentSeverity)99</c> へ
/// 変換し、<b><c>ModelState</c> にエラーを積まない</b>(実測: 変換は通り
/// <c>Enum.IsDefined</c> だけが <c>false</c>)。つまり
/// <see cref="MalformedFilterValueResolver"/>(束縛に<b>失敗した</b>値を拾う)では捕まらない。
/// その結果、絞り込みは<b>実際に掛かって 0 件</b>になる一方、重症度の
/// <c>&lt;select&gt;</c> には一致する <c>&lt;option&gt;</c> が無いので
/// 「重症度（全て）」の位置に戻り、そのフォームを再送信した瞬間に
/// <b>絞り込みが黙って解除される</b> ——
/// <see cref="Models.Validation.SearchFilter"/> の表が守ろうとしている不変条件
/// 「絞り込みに使った値は必ず選択肢にある」がそのまま破れている状態(issue #192 の症状)。
/// インシデント種別も同じで、そちらの未定義の例は <c>?incidentType=0</c>
/// (<b><c>?incidentType=99</c> ではない</b> —— <c>IncidentTypeKind.Other</c> が 99 として
/// 定義済みなので、その URL は「その他」で正しく絞り込まれる)。</para>
///
/// <para><b>前提: 選択肢の出所と enum の定義が一致していること。</b> 採用を
/// <c>Enum.IsDefined</c> で決める一方、<c>&lt;select&gt;</c> の選択肢は
/// <c>EnumLabels.AllSeverities</c> / <c>IncidentTypeMapping.AllInDisplayOrder</c> という
/// <b>別の宣言箇所</b>から作る。片方にしかない値が生まれると
/// 「採用されるのに一致する <c>&lt;option&gt;</c> が無い」＝上と同じ壊れ方に戻るので、
/// <c>Models.EnumFilterOptionSourceTests</c> がその一致を固定する
/// (種別の一覧は手で保守する辞書のキーなので、足し忘れだけで成立する)。</para>
///
/// <para><b>どちらの方式を採るか。</b> 表の 2 択のうち<b>「採用しない」</b>側。
/// enum の値の集合は<b>コード側で閉じていて</b>、DB の過去行も
/// (保存側が <c>[EnumDataType]</c> で未定義値を弾いているため)必ずその中に収まる。
/// リスト外は URL の打ち間違い・改ざん・古いブックマークなので、
/// <c>/AuditLogs</c> のエンティティ名・操作種別とまったく同じ形で、
/// <b>絞り込みを掛けず、画面へも値を返さない</b>。</para>
///
/// <para><b>旗を <see cref="MalformedFilterValueResolver"/> と分けるのは文面が違うから。</b>
/// あちらの理由は「その型の値として読めない」、こちらは「選べる値ではない」。
/// 逆に<b>種別と重症度でこちらの旗を分けない</b>のは、2 つとも理由が同一だから ——
/// 旗を分ける / まとめるの基準は<b>採用しなかった理由が同じかどうか</b>で、
/// この基準は既存の 3 つの旗と共通(理由の正本は
/// <see cref="Models.Validation.SearchFilter"/> の解説)。</para>
///
/// <para><b>なぜ総称(generic)にするのか。</b> 判定は <see cref="System.Enum.IsDefined{TEnum}(TEnum)"/>
/// だけで、<b>この判定が使える enum なら</b>種類に依存する条件が 1 つも無い。
/// 種別用・重症度用と写しを作ると、3 つ目の enum 絞り込みを足した人が片方だけ真似て、
/// もう片方の判定が取り残される(§6 DRY)。</para>
///
/// <para><b>ただし <c>[Flags]</c> の enum には使えない。</b>
/// <c>A|B</c> のような正当な組み合わせは単独の定義として存在しないため
/// <c>Enum.IsDefined</c> が <c>false</c> を返し、
/// <b>画面が提示している組み合わせなのに「選べる値ではない」と言われる</b>。
/// このリポジトリに <c>[Flags]</c> の enum は 1 つも無いので分岐を先回りで用意しない
/// (§6「将来を見越した過度な抽象化を避ける」)が、代わりに
/// <c>Models.EnumFilterOptionSourceTests.EnumsGatedByIsDefined_AreNotFlagsEnums</c> が
/// 前提が崩れたら落ちるようにしてある —— 下の「配線だけで済む」を読んだ人が
/// <c>[Flags]</c> の絞り込みを通した瞬間に静かに壊れるため。</para>
///
/// <para><b>渡し忘れは構造的には塞げない</b>ので(呼び出し側が enum の引数ごとに呼ぶ形)、
/// <c>Controllers.UnlistedFilterValuePolicyTests.IncidentsIndex_DropsAnEnumFilterValueOutsideItsDefinition</c>
/// が「<c>Index</c> が受ける <c>Nullable&lt;TEnum&gt;</c> の引数」という<b>独立な手がかり</b>から
/// 一覧を導いて、1 つずつ実際に採用されないことを確かめる ——3 つ目の enum 絞り込みを
/// 足した人がここを通し忘れると、その引数だけが黙って元の壊れ方に戻るため。</para>
/// </remarks>
internal static class UnlistedEnumFilterResolver
{
    /// <summary>
    /// enum の絞り込み値を、<b>その enum の定義にある値だけ</b>採用する形へ解決する。
    /// </summary>
    /// <remarks>
    /// <para><b>未指定と「定義に無い」を区別する。</b> 値が届いていない(<c>null</c>)のは
    /// 「採用しなかった」ではないので <c>Ignored</c> は <c>false</c> のまま。
    /// 受け取ったうえで定義に無いときだけ <c>true</c> にする
    /// (既存の 3 つの旗と同じ規則。未指定で注意書きを出すと、絞り込みを一度も使っていない
    /// 利用者の画面に出っぱなしの警告が並び、本物の注意書きまで読み飛ばされる)。</para>
    /// </remarks>
    /// <typeparam name="TEnum">絞り込みに使う enum の型。</typeparam>
    /// <param name="requested">クエリ文字列から届いた絞り込み値(未指定なら <c>null</c>)。</param>
    /// <returns>採用した値と、受け取ったのに採用しなかったかどうか。</returns>
    public static UnlistedEnumFilterSelection<TEnum> Resolve<TEnum>(TEnum? requested)
        // struct 制約と Enum 制約で「null 許容の enum」だけを受ける(int などは渡せない)
        where TEnum : struct, Enum
    {
        // そもそも値が届いていないなら「未指定」。採用も不採用もしていない
        if (requested is not TEnum value) return new UnlistedEnumFilterSelection<TEnum>(null, Ignored: false);

        // 束縛はできたが enum の定義に無い値(?severity=99 など)は採用しない。
        // 絞り込みを掛けずに画面へも返さないので、<select> は「(全て)」を指し、
        // ページャのリンクもその値を運ばない ——注意書きだけが「適用していません」と伝える
        if (!Enum.IsDefined(value)) return new UnlistedEnumFilterSelection<TEnum>(null, Ignored: true);

        // 定義にある値はそのまま採用する
        return new UnlistedEnumFilterSelection<TEnum>(value, Ignored: false);
    }

    /// <summary>
    /// <see cref="Resolve{TEnum}"/> の結果。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ真偽値だけでなく採用値も返すのか。</b> 呼び出し側は絞り込みの
    /// <c>Where</c> と画面へ返す値の<b>両方</b>で「採用した値」を使う。
    /// 真偽値だけを返して呼び出し側に <c>requested</c> を使わせると、
    /// 「採用しなかったのに <c>Where</c> には渡っている」「画面にだけ残っている」という
    /// 半端な状態を書けてしまう ——既存の 2 つ
    /// (<see cref="DepartmentFilterResolver.DepartmentFilterSelection"/> /
    /// <c>IncidentsController.CauseCategoryFilterSelection</c>)が
    /// <c>Effective</c> を返しているのと同じ理由。</para>
    /// </remarks>
    /// <typeparam name="TEnum">絞り込みに使う enum の型。</typeparam>
    /// <param name="Effective">絞り込みに<b>実際に使う</b>値。採用しなかったなら <c>null</c>。</param>
    /// <param name="Ignored"><b>値を受け取ったのに定義に無く採用しなかった</b>とき <c>true</c>。</param>
    public readonly record struct UnlistedEnumFilterSelection<TEnum>(TEnum? Effective, bool Ignored)
        // Resolve と同じ制約(null 許容の enum だけを載せる)
        where TEnum : struct, Enum;
}
