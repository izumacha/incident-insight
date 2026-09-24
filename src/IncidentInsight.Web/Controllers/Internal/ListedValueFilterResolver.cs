// 絞り込み入力の「空かどうか」の判定を共有するために参照する
using IncidentInsight.Web.Models.Validation;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// <b>文字列の許可リストで閉じた絞り込み入力</b>について、<b>実際に絞り込みへ使う値</b>と
/// <b>受け取ったのに採用しなかったか</b>を同時に決める共有処理。
/// <c>/AuditLogs</c>(エンティティ名・操作種別)と <c>/</c>(ダッシュボードの集計期間)が使う。
/// </summary>
/// <remarks>
/// <para><b>なぜ 2 つを一緒に返すのか。</b> 採用した値と「採用しなかった」の判定は
/// <b>必ず整合していなければならない</b>。別々に書くと、片方だけ直したときに
/// 「絞り込みは効いていないのに旗が立たない(黙って落ちる)」か
/// 「効いているのに旗が立つ(嘘の注意書き)」のどちらかになる。
/// 既存の <see cref="DepartmentFilterResolver.DepartmentFilterSelection"/> や
/// <c>IncidentsController.CauseCategoryFilterSelection</c> と同じ形にしてあるのは、
/// 旗の一覧をコントローラのソースから(<c>… = ….Ignored</c> という代入の形で)導いている
/// <c>UnlistedFilterValuePolicyTests</c> がこの旗も自動で拾えるようにするため
/// ——書き方を揃えること自体が検出網の一部になっている。</para>
///
/// <para><b>ここが決めるのは「採用したか」までで、採用しなかったあとの扱いは画面が決める。</b>
/// <c>/AuditLogs</c> は<b>その条件を外して</b>一覧を出す(絞り込み無し)。
/// ダッシュボードは「期間なし」という状態を持てない(常に何らかの窓で集計する)ので、
/// <b>既定の期間へ補完</b>する。<see cref="ListedValueFilterSelection.Effective"/> が
/// <c>null</c> のときに何をするかを呼び出し側へ残してあるのはこのためで、
/// <b>方式(採用しない／補完する)が違っても旗は同じように立てる</b>
/// ——「採用しなかったなら必ず伝える」は方式とは別の軸の規則
/// (issue #220。規則の正本は <see cref="SearchFilter"/> の表)。</para>
///
/// <para><b>方式は「補完しない」(＝ここでは許可リスト外の値を採らない)。</b> 許可リストは
/// <c>AuditSaveChangesInterceptor.AuditedEntities</c> や
/// <c>DashboardViewModel.Periods</c> のような<b>コード側で閉じた語彙</b>なので、
/// 発生部署(自由記述＝実データにあれば選択肢へ補完する)のような逃げ道は採れない
/// ——選択肢に無い値を足すと、ドロップダウンや期間切替に実在しない対象が並ぶ。
/// 方式の選び方そのものは <see cref="SearchFilter"/> の表が正本。</para>
///
/// <para><b>なぜ共有ヘルパーなのか。</b> 以前これは <c>AuditLogsController</c> の private で、
/// 「いまの利用側がこの画面の 2 つだけだから(§6「将来を見越した過度な抽象化を避ける」)。
/// 2 画面目が同じ形を必要としたら <c>Controllers/Internal/</c> へ移す」と書いてあった。
/// ダッシュボードの <c>?period=</c> が 2 画面目になったので、その条件どおりここへ移した
/// ——private のまま写すと、判定を直したときに<b>片方だけが取り残される</b>
/// (この repo が <c>MalformedFilterValueResolver</c> ・ <c>UnlistedEnumFilterResolver</c> で
/// 既に共有している理由とまったく同じ)。</para>
///
/// <para><b>残る境界。</b> 「その引数が許可リストで閉じた絞り込みか」は署名から判定できない
/// (<c>string?</c> はどんな入力でも束縛できるので、<c>DateTime?</c> や enum のように
/// アプリ全体の署名から対象を導く検出網が書けない)。したがって
/// 「3 画面目が許可リストの絞り込みを足したのにここを通さない」形は機械では落ちない
/// ——規約とレビューで守る。ただし<b>旗を 1 つでも立てた時点から</b>は
/// <c>ViewModelFlagScreens_CoverEveryViewModelThatDeclaresAFlag</c> と
/// <c>IgnoredFilterNoticeScreens_CoverEveryViewThatRendersANotice</c> が
/// 登録漏れを落とすので、抜けるのは「そもそも伝えていない」形だけに限られる。</para>
/// </remarks>
public static class ListedValueFilterResolver
{
    /// <summary>
    /// 許可リストで閉じた絞り込み入力を解決する。
    /// </summary>
    /// <param name="value">クエリ文字列から届いた絞り込み値(未指定なら <c>null</c>)。</param>
    /// <param name="allowed">その入力が取りうる値の許可リスト。</param>
    /// <returns>採用した値(採用しないなら <c>null</c>)と、受け取ったのに採用しなかったかどうか。</returns>
    public static ListedValueFilterSelection Resolve(string? value, IReadOnlyList<string> allowed)
    {
        // 空・空白のみは「絞り込み無し」。判定は SearchFilter.HasValue に集約してある
        // ——受け取っていないものは「採用しなかった」ではないので、旗も立てない
        // (立てると、絞り込みを使っていない普通の一覧で警告が出続け、読まれなくなる)
        if (!SearchFilter.HasValue(value))
            return new ListedValueFilterSelection(null, Ignored: false);

        // 許可リストに載っていればそのまま採用する(比較は序数＝完全一致)
        if (allowed.Contains(value, StringComparer.Ordinal))
            return new ListedValueFilterSelection(value, Ignored: false);

        // 載っていない値は採用しない。絞り込みも掛けず、画面へも値を返さない
        // ——これで「絞り込み無し・バッジ非表示・select は全て」の三者が揃う
        return new ListedValueFilterSelection(null, Ignored: true);
    }

    /// <summary>
    /// <see cref="Resolve"/> の結果。
    /// </summary>
    /// <remarks>
    /// 入れ子にしてあるのは同じディレクトリの 3 つ(<see cref="DepartmentFilterResolver"/> /
    /// <see cref="MalformedFilterValueResolver"/> / <see cref="UnlistedEnumFilterResolver"/>)と
    /// 同じ置き方にするため ——「結果の型は解決処理の中にある」を崩すと、
    /// 読み手が置き場所を毎回探すことになり、名前衝突もしやすくなる(§6)。
    /// </remarks>
    /// <param name="Effective">絞り込みに使う値。採用しなかった場合は <c>null</c>。</param>
    /// <param name="Ignored"><b>値を受け取ったのに採用しなかった</b>とき <c>true</c>。</param>
    public readonly record struct ListedValueFilterSelection(string? Effective, bool Ignored);
}
