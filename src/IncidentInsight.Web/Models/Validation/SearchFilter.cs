// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// 一覧画面の絞り込み入力について「値が入っているか」を判定する唯一の真実の源
/// (single source of truth)。<c>?search=</c> のようなクエリ文字列から届く
/// <see cref="string"/> の絞り込み条件は、すべてこの判定を通してから使う。
///
/// <para><b>規則。</b> <c>null</c> / 空文字 / <b>空白のみ</b>の入力は「絞り込み無し」として扱う
/// (＝<see cref="HasValue"/> は <c>false</c> を返す)。空白のみを「入力あり」と数えないのは、
/// 利用者にとって空欄と見分けが付かないため。末尾スペースごとの貼り付け・IME の誤入力・
/// ブラウザのオートフィルで容易に発生する。</para>
///
/// <para><b>なぜ 1 か所に集めるのか(issue #187)。</b> 以前はこの判定が画面ごとに書かれ、
/// フリーワード検索を持つ 3 画面のうち <c>/PreventiveMeasures</c>(カンバン)だけが
/// <c>string.IsNullOrEmpty</c> を使っていた。そのため空白のみの入力に対して
/// <c>/Incidents</c> と <c>/AuditLogs</c> は「絞り込み無し」として全件を返すのに、
/// カンバンだけは絞り込みが<b>実際に走り</b>、
/// <c>ResponsiblePerson.ToUpper().Contains(&quot; &quot;)</c> がこのアプリの日本語の氏名・部署名に
/// まず一致しないため<b>盤面が空になっていた</b>。利用者からは原因が分からないまま
/// データが消えたように見える(CLAUDE.md §6 定数・規則の一元管理)。</para>
///
/// <para><b>絞り込みの適用側と「絞り込み中」の表示側で必ず同じ判定を使う。</b>
/// 一覧画面には、絞り込みが効いているかどうかで表示を変える箇所がある
/// (カンバンの <c>ViewBag.HasActiveFilter</c>＝0 件時の文言の出し分け、
/// <c>/Incidents</c> と <c>/AuditLogs</c> の絞り込みパネルを開いた状態にするかどうか)。
/// 片方だけ判定を変えると、<b>空白のみの入力で「絞り込み中」と表示しながら全件を返す</b>
/// (またはその逆の)食い違いが生まれる。両方をこの関数に通しておけば、規則を変えるときも
/// ここ 1 か所で揃う。</para>
///
/// <para><b>入力値そのものは加工しない。</b> この型が答えるのは「絞り込むかどうか」だけで、
/// 前後の空白を取り除いたりはしない。<c>&quot;田中 &quot;</c>(末尾スペース付き)のような
/// 入力は今までどおりそのまま検索語として使われる。トリミングは検索の一致範囲を変える
/// 別の判断なので、必要になったときに独立した変更として決めること。
/// 検索語の大文字化(ロケール非依存の正規化)は
/// <c>Controllers.Internal.IncidentControllerHelpers.NormalizeSearchKeyword</c> が担当する
/// ——こちらは EF Core のクエリを組み立てる経路でしか使わないためコントローラ側に置いてある。</para>
/// </summary>
public static class SearchFilter
{
    /// <summary>
    /// 絞り込み入力に「意味のある値」が入っているかを判定する。
    /// </summary>
    /// <param name="input">クエリ文字列やフォームから受け取った絞り込み条件(未入力なら <c>null</c>)。</param>
    /// <returns>絞り込みを適用すべきなら <c>true</c>、空・空白のみなら <c>false</c>。</returns>
    public static bool HasValue(string? input)
        // null・空文字・空白のみ(半角/全角スペース、タブ、改行など)はすべて「未入力」とみなす
        => !string.IsNullOrWhiteSpace(input);
}
