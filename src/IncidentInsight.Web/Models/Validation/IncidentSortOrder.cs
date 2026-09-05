// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// <c>/Incidents</c>(一覧)の並び順 <c>?sortBy=</c> について
/// 「どの値を受け付けるか」「受け取った値を採用するか」を決める唯一の真実の源
/// (single source of truth)。並び替えの適用側(コントローラの <c>switch</c>)と
/// 表示側(<c>&lt;select name="sortBy"&gt;</c> の選択肢)は、どちらもここから導く。
///
/// <para><b>なぜ 1 か所に集めるのか(issue #209)。</b> 以前は受け付ける値の綴りが
/// <b>2 か所に書き写されていた</b> —— <c>IncidentsController.Index</c> の
/// <c>switch</c> の <c>case</c> と、<c>Views/Incidents/Index.cshtml</c> の
/// 3 つの <c>&lt;option value="…"&gt;</c> ＋ その <c>selected</c> の比較式。
/// 写しがあると綴りを変えたときに<b>片方だけが取り残される</b>のに、
/// 症状は「そのメニュー項目を選んでも最新順のまま」という無言の劣化で、
/// 例外もエラー表示も出ない(<c>switch</c> の既定枝が黙って引き取るため)。
/// 値を足すときも同じで、コントローラにだけ足せば画面から到達できず、
/// 画面にだけ足せば選んでも効かない。</para>
///
/// <para><b>「採用しなかった値を画面へ返さない」もここで守る(issue #204 課題 2 と同じ規則)。</b>
/// <c>?sortBy=bogus</c> のような受け付けない値は並び替えに<b>使われない</b>が、
/// 受け取った値をそのまま ViewModel へ載せると<b>ページャのリンクが全部その値を運ぶ</b>
/// (<c>Views/Incidents/Index.cshtml</c> が <c>RouteValues["sortBy"] = Model.SortBy</c> と
/// 書いており、<c>PagerViewModel.RouteValuesFor</c> は <c>null</c> の条件だけを落とす)。
/// 画面の <c>&lt;select&gt;</c> は「最新順」を指しているのに URL だけが
/// <c>?sortBy=bogus&amp;page=2</c> と別のことを言う、という食い違いになる ——
/// 空白のみの検索語について <see cref="SearchFilter.Adopted"/> が塞いだのと同じ形。
/// <b>この経路は以前「手当てが要らない」と判断されていた</b>が、その根拠は
/// 並び替えの適用側と <c>&lt;select&gt;</c> の 2 つしか見ておらず、
/// <b>3 つ目の利用側であるページャを見落としていた</b>。</para>
///
/// <para><b>「採用しなかった」ことを画面の注意書きにはしない。</b>
/// <see cref="SearchFilter"/> の表が扱う絞り込みは<b>どの行を見せるか</b>を変えるので、
/// 黙って落とすと「絞り込んだつもりで全件」という取り違えが起きる。
/// 並び順が変えるのは<b>同じ行の並びだけ</b>で、しかも画面の
/// <c>&lt;select&gt;</c> が実際に適用された並び順(既定＝最新順)を正しく表示している。
/// 利用者から見て事実と食い違う表示は残らないので、注意書きを足すと
/// 情報量の無い警告が増えるだけになる。<b>受け取った値を運ばないことだけ</b>を守る。</para>
///
/// <para><b>照合はロケール非依存の序数比較(<see cref="StringComparison.Ordinal"/>)で行う。</b>
/// URL のクエリ文字列は識別子であって自然言語ではないので、
/// 実行環境のカルチャで結論が変わってはいけない
/// (検索語の大文字化を不変規則で行っている
/// <c>Controllers.Internal.IncidentControllerHelpers.NormalizeSearchKeyword</c> と同じ理由)。
/// 大文字小文字は区別する ——<c>?sortBy=Severity</c> は受け付けない値として扱い、
/// 既定の最新順で表示する(画面の <c>&lt;select&gt;</c> も最新順を指すので食い違わない)。</para>
/// </summary>
public static class IncidentSortOrder
{
    /// <summary>発生日の新しい順(既定)。</summary>
    public const string Latest = "latest";

    /// <summary>重症度の高い順。</summary>
    public const string Severity = "severity";

    /// <summary>未完了で期限を過ぎた対策を持つインシデントを優先。</summary>
    public const string Overdue = "overdue";

    /// <summary>
    /// 画面のドロップダウンに並べる選択肢(<b>表示順</b>)。
    /// </summary>
    /// <remarks>
    /// <para><b>先頭は必ず既定の並び順にする。</b> <c>?sortBy=</c> 未指定のときは
    /// どの <c>&lt;option&gt;</c> にも <c>selected</c> が付かず、ブラウザは先頭を選ぶ。
    /// 先頭が <see cref="Latest"/> でなければ、画面の表示と実際の並びが食い違う。</para>
    ///
    /// <para><b>日本語ラベルをここに置いている理由。</b> ラベルの一元管理先は本来
    /// <c>Models/Enums/EnumLabels.cs</c> だが、あちらが引くのはドメインの enum
    /// (重症度・部署・インシデント種別)で、並び順は DB にも保存されない
    /// <b>この画面の操作方法</b>。値とラベルを別の場所に置くと、値を足した人が
    /// ラベルを足し忘れて画面に生の <c>"overdue"</c> が出る(<c>EnumLabels</c> の
    /// フォールバックと同じ壊れ方)ので、対で 1 か所に持たせる。</para>
    /// </remarks>
    public static readonly IReadOnlyList<SortOrderOption> Options = new[]
    {
        // 既定の並び順。上の remarks のとおり先頭に置く
        new SortOrderOption(Latest, "最新順"),
        // 重症度の高いものから
        new SortOrderOption(Severity, "重症度高順"),
        // 未完了の期限超過対策を持つものを先に
        new SortOrderOption(Overdue, "未完了対策あり優先")
    };

    /// <summary>
    /// <b>実際に適用する</b>並び順を返す。受け付けない値・未指定は既定(<see cref="Latest"/>)。
    /// </summary>
    /// <remarks>
    /// 並び替えの <c>switch</c> と、画面の <c>selected</c> の判定は<b>どちらもこれを通す</b>。
    /// 片方だけ別の判定を書くと、「メニューは A を指しているのに並びは B」という
    /// 食い違いがそのまま利用者に見える。
    /// </remarks>
    /// <param name="requested">クエリ文字列から受け取った並び順(未指定なら <c>null</c>)。</param>
    /// <returns>受け付ける値ならその値、それ以外は <see cref="Latest"/>。</returns>
    public static string Effective(string? requested)
        // 受け付ける値だけをそのまま採用し、それ以外(未指定・綴り違い)は既定へ倒す
        => Adopted(requested) ?? Latest;

    /// <summary>
    /// 並び替えに<b>実際に使った値だけ</b>を返す。受け付けない値・未指定は <c>null</c>。
    /// 画面へ戻す値(＝ページャの URL に載る値)を組み立てるときに使う。
    /// </summary>
    /// <remarks>
    /// <para>役割は <see cref="SearchFilter.Adopted"/> と同じ ——
    /// 「採用しなかった値を画面へ返さない」。<see cref="Effective"/> と分けてあるのは
    /// 答える問いが違うため: あちらは<b>どう並べるか</b>(必ず 1 つに決まる)、
    /// こちらは<b>利用者が選んだ値として URL に残すか</b>(選んでいなければ残さない)。
    /// 1 つにまとめて常に <see cref="Latest"/> を返すと、並び順を選んでいない利用者の
    /// ページャ URL にまで <c>?sortBy=latest</c> が付く。</para>
    ///
    /// <para><c>?sortBy=latest</c> と明示された場合は<b>そのまま残す</b> ——
    /// 既定と同じ並びでも、利用者が選んだ結果である URL は共有・ブックマークできる
    /// ようにしておく(受け取った値を加工しないのは <see cref="SearchFilter.Adopted"/> と同じ)。</para>
    /// </remarks>
    /// <param name="requested">クエリ文字列から受け取った並び順(未指定なら <c>null</c>)。</param>
    /// <returns>並び替えに使った値。使わなかったなら <c>null</c>。</returns>
    public static string? Adopted(string? requested)
        // 選択肢に載っている値だけを採用する(照合は序数比較＝ロケール非依存・大文字小文字を区別)
        => Options.Any(option => string.Equals(option.Value, requested, StringComparison.Ordinal))
            // 受け付ける値だったので、受け取った文字列をそのまま返す
            ? requested
            // 未指定・綴り違い・大文字小文字違いは「選ばれていない」として潰す
            : null;

    /// <summary>
    /// ドロップダウンの選択肢 1 件(URL に載る値と、画面に出す日本語ラベル)。
    /// </summary>
    /// <remarks>
    /// <c>SelectListItem</c>(MVC の型)を使わないのは、この一覧が<b>要求ごとに作る
    /// 動的な選択肢ではなく静的な定義</b>だから ——部署・原因分類の選択肢は
    /// 実データから毎回組み立てるためコントローラが <c>SelectListItem</c> を作るが、
    /// こちらはコードで閉じている。<c>Models/Validation</c> から MVC の描画用の型へ
    /// 依存しないでおくと、この規則を画面以外(将来の API など)から使うときも困らない。
    /// </remarks>
    /// <param name="Value">URL とフォームで使う値(<c>?sortBy=</c> に載る)。</param>
    /// <param name="Label">画面に出す日本語ラベル。</param>
    public readonly record struct SortOrderOption(string Value, string Label);
}
