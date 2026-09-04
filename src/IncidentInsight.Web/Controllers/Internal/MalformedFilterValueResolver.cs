// ModelState(モデルバインドの結果と、その途中で出たエラー)を読むために使う
using Microsoft.AspNetCore.Mvc.ModelBinding;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// <b>型として解釈できなかった絞り込み値</b>を「受け取ったが採用しなかった」として拾う共有処理。
/// <c>/Incidents</c>(一覧)が使う。
/// </summary>
/// <remarks>
/// <para><b>なぜ要るのか(issue #198)。</b> クエリ文字列から届く絞り込みのうち
/// <b>文字列以外</b>の入力(<c>int?</c> / enum / <c>DateTime?</c>)は、値がその型として
/// 読めなければ MVC のモデルバインドが失敗して引数が <c>null</c> になり、
/// 失敗した事実は <see cref="ModelStateDictionary"/> にしか残らない。一覧のアクションが
/// それを見ないと、<c>?causeCategoryId=abc</c> は<b>「そもそも指定が無かった」と同じ扱い</b>に
/// なる ——絞り込みは掛からず、注意書きも「フィルター適用中」バッジも出ないまま
/// <b>全件</b>が返る。<c>?causeCategoryId=0</c>(実在しない id)なら注意書きが出るのに、
/// 綴りが数値でないと消える、という一貫性の欠如がここにあった。</para>
///
/// <para><b>「黙って落とさない」という規則自体は新しくない。</b> 発生部署・原因分類は
/// 既に「受け取ったのに採用しなかった」ことを画面へ伝えている
/// (規則と理由の正本は <see cref="Models.Validation.SearchFilter"/> の解説)。
/// あちらが答えるのは「<b>読めた</b>値をドロップダウンが表せないとき」で、ここが答えるのは
/// その手前の「<b>そもそも読めなかった</b>とき」。<b>利用者から見た結果は同じ</b>
/// (絞り込んだつもりで全件が返る)なので、伝えないままにしてよい理由が無い。</para>
///
/// <para><b>なぜ入力ごとに旗を分けないのか。</b> 既存の 2 つの注意書きが文面を分けているのは
/// <b>採用しなかった理由が入力ごとに違う</b>から(部署は「その部署の行が見える範囲に無い」、
/// 原因分類は「その分類がマスタに無い」)。読めなかった場合の理由は
/// <b>5 つの入力すべてで同一</b>(「その型の値として読めない」)なので、文面を分ける根拠が無い。
/// 分ければ同じ文章が 5 つ並び、どれか 1 つを直したときに他の 4 つが取り残される。
/// どの条件を送ったかはブラウザのアドレス欄に出ており、この注意書きが出るときは
/// 絞り込みパネルも開くので、選び直す導線はそちらで足りる
/// (送られてきた値そのものを画面へ echo しないのも既存の 2 つと同じ扱い)。</para>
///
/// <para><b>対象の名前は呼び出し側が <c>nameof</c> で渡す。</b> モデルバインドが使うキーは
/// アクションの引数名そのものなので、文字列を直書きせず <c>nameof</c> で渡せば
/// 引数を改名しても追随する(<c>ModelState.Remove</c> を <c>nameof</c> で書く既存の規約と同じ)。
/// <b>渡し忘れは構造的には塞げない</b>ので、
/// <c>Controllers.UnlistedFilterValuePolicyTests.IncidentsIndex_ReportsAFilterValueThatCannotBeRead</c>
/// が「<c>Index</c> が受ける <c>Nullable&lt;T&gt;</c> の引数」という<b>独立な手がかり</b>から
/// 一覧を導いて、1 つずつ実際に注意書きが出ることを確かめる ——6 つ目の型付き絞り込みを
/// 足した人がここへ渡し忘れると、その引数だけが黙って元の壊れ方に戻るため。</para>
///
/// <para><b>文字列の絞り込みは対象外。</b> <c>string?</c> はどんな入力でも束縛できるので
/// 「読めなかった」という状態が存在しない(空・空白のみの扱いは
/// <see cref="Models.Validation.SearchFilter"/> が答える別の問い)。</para>
/// </remarks>
internal static class MalformedFilterValueResolver
{
    /// <summary>
    /// 指定した絞り込み引数のうち、<b>値は届いたのに型として読めなかった</b>ものがあるかを判定する。
    /// </summary>
    /// <remarks>
    /// <para><b>判定は「その名前のエントリにエラーがあるか」。</b> このアクションの引数は
    /// 単純型だけで検証属性も付いていないため、<see cref="ModelStateDictionary"/> に
    /// エラーが積まれる経路は<b>型変換の失敗しか無い</b>。逆に <c>?severity=</c>(空文字)は
    /// null 許容型へ <c>null</c> として問題なく束縛されエラーにならないので、
    /// 「未指定」を誤って拾うこともない。</para>
    ///
    /// <para><b>エントリの有無だけでは足りない。</b> 束縛に成功した引数も
    /// <see cref="ModelStateDictionary"/> にはエントリを持つ(値が記録される)ので、
    /// キーの存在で判定すると<b>正しい値を送ったときに注意書きが出る</b>。
    /// 見るのはエラーの有無。</para>
    /// </remarks>
    /// <param name="modelState">アクションのモデルバインド結果(コントローラの <c>ModelState</c>)。</param>
    /// <param name="parameterNames">見張る絞り込み引数の名前(呼び出し側が <c>nameof</c> で渡す)。</param>
    /// <returns>読めなかった値が 1 つでもあれば <c>Ignored</c> が <c>true</c> の結果。</returns>
    public static MalformedFilterSelection Resolve(
        ModelStateDictionary modelState, params string[] parameterNames)
    {
        // 渡された引数名を順に見て、1 つでも「届いたが読めなかった」ものがあれば true にする
        foreach (var name in parameterNames)
        {
            // その名前のエントリが無いなら、値がそもそも届いていない(＝未指定)
            if (!modelState.TryGetValue(name, out var entry)) continue;
            // エントリはあるがエラーが無いなら、束縛に成功している(＝正しい値)
            if (entry.Errors.Count == 0) continue;
            // ここに来たら「値は届いたのに型として読めなかった」。これ以上見なくても結論は変わらない
            return new MalformedFilterSelection(Ignored: true);
        }

        // 読めなかった値は 1 つも無かった
        return new MalformedFilterSelection(Ignored: false);
    }

    /// <summary>
    /// <see cref="Resolve"/> の結果。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ真偽値だけを record struct で包むのか。</b> 素の <c>bool</c> を返すと
    /// 呼び出し側が <c>MalformedFilterIgnored = 何か</c> と書けてしまい、
    /// 「採用しなかったことは<b>解決処理が判断して返す</b>」という既存の 2 つ
    /// (<see cref="DepartmentFilterResolver.DepartmentFilterSelection"/> /
    /// <c>IncidentsController.CauseCategoryFilterSelection</c>)との書き方が揃わない。
    /// 揃えておくと、旗の一覧をコントローラのソースから
    /// (<c>… = ….Ignored</c> という代入の形で)導いている
    /// <c>UnlistedFilterValuePolicyTests.IgnoredFilterFlags_CoverEveryFlagTheControllerSets</c> が
    /// この旗も自動で拾う ——書き方を揃えること自体が検出網の一部になっている。</para>
    ///
    /// <para><b>採用した値(<c>Effective</c>)を持たない</b>のは、読めなかった値には
    /// 「採用しうる値」が存在しないため(引数は既に <c>null</c> になっている)。</para>
    /// </remarks>
    /// <param name="Ignored"><b>値を受け取ったのに型として読めず採用しなかった</b>とき <c>true</c>。</param>
    public readonly record struct MalformedFilterSelection(bool Ignored);
}
