// コントローラの型を名指しして「自分たちのアセンブリ」を特定するために使う
using IncidentInsight.Web.Controllers;
// ControllerBase を使う
using Microsoft.AspNetCore.Mvc;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// 「アプリ全体のコントローラ」を導出する<b>唯一の入り口</b>。
/// </summary>
/// <remarks>
/// <para><b>なぜ 1 か所に寄せるのか。</b> コントローラを走査する検査は複数あり
/// (絞り込み値の方針・PHI のキャッシュ方針)、各検査が同じ絞り込みを書き写すと、
/// <b>片方の写しだけを狭めたときにもう片方は気付けない</b>。しかも狭める変異は
/// 「違反ゼロ＝緑」で現れるので痕跡が残らない(CLAUDE.md §6 DRY)。</para>
///
/// <para><b>導出が狭まっていないことを見張るのは
/// <c>UnlistedFilterValuePolicyTests.ControllerScan_ReachesEveryControllerFile</c>。</b>
/// この導出とは<b>独立な手がかり</b>(Web プロジェクト配下に実在するソースファイルと、
/// そのファイルが宣言している名前空間)と突き合わせる。同じ手がかりでガードを書くと、
/// 導出が狭まったときにガードも一緒に狭まって無力化されるため。
/// <b>利用側でこの絞り込みを書き写さない</b> ——写した瞬間に、その利用側だけが
/// このガードの射程から外れる。</para>
///
/// <para><b>名前空間ではなく所属アセンブリで絞る理由。</b> 名前空間の完全一致で切ると、
/// コントローラを Areas やサブフォルダへ移すだけで走査から外れる
/// (CLAUDE.md §3 が長さ管理の導出について同じ形の事故を記録している)。</para>
/// </remarks>
public static class AppControllerScan
{
    /// <summary>自分たちの Web アセンブリ(走査の基準)。</summary>
    public static System.Reflection.Assembly WebAssembly => typeof(IncidentsController).Assembly;

    /// <summary>
    /// アプリ全体の具象コントローラを返す。
    /// </summary>
    /// <remarks>抽象基底はルートを持たないので除く(URL として到達できない)。</remarks>
    /// <returns>自分たちのアセンブリにある具象コントローラ。</returns>
    public static IEnumerable<Type> Controllers() =>
        // 自分たちのアセンブリの、具象のコントローラすべて
        WebAssembly.GetTypes()
            .Where(t => typeof(ControllerBase).IsAssignableFrom(t) && !t.IsAbstract);

    /// <summary>
    /// キャッシュ指示の属性(<c>[ResponseCache]</c> / <c>[OutputCache]</c>)を宣言しうる型を、
    /// <b>基底型で絞らずに</b>すべて返す。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ <see cref="Controllers"/> を使い回さないのか。</b>
    /// <c>[ResponseCache]</c> は MVC のコントローラ専用ではない ——
    /// <c>PageModel</c>(Razor Pages)に付けても <c>IFilterFactory</c> として同じように効く。
    /// <c>ControllerBase</c> で絞ると、<c>Pages/Export.cshtml.cs</c> に
    /// <c>[ResponseCache(Duration = 300, Location = Any)]</c> を付けた PHI のページが
    /// <b>どの検査からも見えないまま</b>公開される。
    /// ソースを見る側の走査(<c>OnlyIntendedWriters_SetCacheControlDirectly</c>)は
    /// まさにこの <c>Pages/</c> の死角を理由に「パスの形で絞らない」形へ広げてあるのに、
    /// リフレクション側だけが基底型で狭いままだった ——
    /// <b>属性名にはヘッダー名の綴りが無い</b>ので、ソース側の走査でも拾えない。</para>
    ///
    /// <para><b>絞らないことの代償が無い。</b> 拾うのは「その属性が付いている宣言」だけなので、
    /// 端点でない型をいくら含めても誤検知は 1 件も増えない。逆に基底型で絞ると、
    /// 端点の形が増えるたびに<b>黙って</b>射程から外れる(この repo が長さ管理の導出と
    /// コントローラの走査で 2 度踏んだ形)。だから「絞らない」を既定にする。</para>
    /// </remarks>
    /// <returns>自分たちのアセンブリにある具象型すべて。</returns>
    public static IEnumerable<Type> CacheDirectiveHosts() =>
        // 抽象型は宣言を持てるが実体化されないので除く(基底へ引き上げた宣言は
        // ResponseCachePolicy 側が具象からたどるので、ここで拾わなくても取りこぼさない)
        WebAssembly.GetTypes().Where(t => !t.IsAbstract);
}
