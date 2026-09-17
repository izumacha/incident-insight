// ResponseCacheAttribute を使う
using Microsoft.AspNetCore.Mvc;
// 属性とアクションをリフレクションで走査するために使う
using System.Reflection;

// このヘルパーが属する名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// <c>[ResponseCache]</c> の宣言が「キャッシュ保存を禁じているか」を判定し、
/// アプリ全体からその宣言を集めるための共通処理。
/// </summary>
/// <remarks>
/// 判定と走査をヘルパーへ出すのは、<b>宣言として書かれた属性</b>を見る検査
/// (<c>ResponseCacheAttributePolicyTests</c>)と、<b>起動したアプリの設定</b>を見る検査
/// (<c>ResponseCacheHeaderIntegrationTests</c> の <c>MvcOptions</c> 側)の
/// 2 か所が同じ基準を使うため。基準を書き写すと、片方だけを緩めたときに
/// もう片方が黙って別の答えを出す(CLAUDE.md §6 DRY)。
/// </remarks>
public static class ResponseCachePolicy
{
    /// <summary>
    /// <c>[ResponseCache]</c> が名乗っている内容と、それが許されるかどうかの判定結果。
    /// </summary>
    /// <param name="IsSuppressing">キャッシュ保存を禁じている(＝このアプリで許される)なら true。</param>
    /// <param name="Reason">許されない場合に、失敗文言へ載せる理由。許される場合は空文字。</param>
    public readonly record struct CacheDirectiveVerdict(bool IsSuppressing, string Reason);

    /// <summary>
    /// 走査が見つけた 1 件の <c>[ResponseCache]</c> 宣言(どこに付いていたかを含む)。
    /// </summary>
    /// <param name="DeclaredOn">属性が付いていた場所の表示名(失敗文言で名指しするために持つ)。</param>
    /// <param name="Attribute">宣言された属性そのもの。</param>
    public readonly record struct ResponseCacheDeclaration(string DeclaredOn, ResponseCacheAttribute Attribute);

    /// <summary>
    /// <c>[ResponseCache]</c> の宣言内容が「保存を禁じている」かどうかを判定する純粋関数。
    /// </summary>
    /// <remarks>
    /// <para><b>基準を <c>NoStore</c> だけに置く理由。</b> ASP.NET Core が
    /// <c>Cache-Control: no-store</c> を書くのは <c>NoStore = true</c> のときだけで、
    /// それ以外の組み合わせ(<c>no-cache</c> / <c>private</c> / <c>public</c>)は
    /// いずれも「保存してよい」か「保存したうえで検証せよ」を意味する。
    /// 共用端末のディスクに PHI を残さないことが目的なので、基準は保存の可否 1 本にする。</para>
    ///
    /// <para><b>プロファイル名を落とす理由。</b> <c>CacheProfileName</c> を使うと実際の指示は
    /// <c>MvcOptions.CacheProfiles</c> 側にあり、属性のフィールドからは読めない。
    /// 読めないものを「たぶん安全」と扱うと無言の fail-open になるので、不明なら拒否する
    /// (§9 fail-closed)。プロファイル自体の中身は
    /// <c>ResponseCacheHeaderIntegrationTests</c> が起動したアプリの <c>MvcOptions</c> から
    /// 読んで、同じこの関数で判定する。</para>
    /// </remarks>
    /// <param name="attribute">判定する属性。</param>
    /// <returns>可否と、落とす場合の理由。</returns>
    public static CacheDirectiveVerdict Judge(ResponseCacheAttribute attribute)
    {
        // プロファイル名が指定されていると、実際の指示が属性の外にあって読めない
        if (!string.IsNullOrWhiteSpace(attribute.CacheProfileName))
        {
            // 読めない以上「安全だ」と言えないので落とす
            return new CacheDirectiveVerdict(
                false,
                $"CacheProfileName=\"{attribute.CacheProfileName}\" は実際の指示が MvcOptions 側にあり、"
                    + "属性からは読み取れません。プロファイルを使わず NoStore = true を直接宣言してください。");
        }

        // NoStore が宣言されていれば、応答は保存されない
        if (attribute.NoStore)
        {
            // 許可(理由は不要なので空文字)
            return new CacheDirectiveVerdict(true, string.Empty);
        }

        // ここへ来るのは「保存を許す」宣言なので、名乗っている内容を添えて落とす
        return new CacheDirectiveVerdict(
            false,
            $"NoStore が宣言されていません(Duration={attribute.Duration}, Location={attribute.Location})。"
                + "PHI を返しうる応答が保存されます。NoStore = true を付けるか、属性ごと外して"
                + "SecurityHeadersMiddleware の既定(no-store)に任せてください。");
    }

    /// <summary>
    /// <see cref="CacheProfile"/>(設定として持つキャッシュ指示)を同じ基準で判定する。
    /// </summary>
    /// <remarks>
    /// <see cref="CacheProfile"/> は <see cref="ResponseCacheAttribute"/> と同じ項目を持つ
    /// 別の型なので、属性へ写し取ってから 1 つの判定関数に通す
    /// (判定の規則を 2 つ書かない)。
    /// </remarks>
    /// <param name="profile">判定するキャッシュプロファイル。</param>
    /// <returns>可否と、落とす場合の理由。</returns>
    public static CacheDirectiveVerdict Judge(CacheProfile profile) =>
        // プロファイルの内容を属性の形へ写し取って、同じ判定へ渡す
        Judge(new ResponseCacheAttribute
        {
            // 保存を禁じるかどうか(未設定は「宣言していない」＝ false 扱い)
            NoStore = profile.NoStore ?? false,
            // キャッシュしてよい秒数(未設定は 0)
            Duration = profile.Duration ?? 0,
            // どの層でのキャッシュを許すか(未設定は既定の Any)
            Location = profile.Location ?? ResponseCacheLocation.Any,
        });

    /// <summary>
    /// 渡されたコントローラ型から <c>[ResponseCache]</c> の宣言を集める。
    /// </summary>
    /// <remarks>
    /// <para><b>アクションの絞り込みを「その型が宣言したメソッドか」で行わない。</b>
    /// 抽象基底コントローラへアクションを引き上げる形(<c>ReportExportControllerBase</c> に
    /// <c>Export()</c> を置き、具象が継承する)は、URL としては具象コントローラ経由で
    /// <b>実際に到達できる</b>のに、基底は抽象なので走査対象に入らず、具象の側では
    /// 宣言元が基底なので弾かれる ——つまり<b>どこからも見えなくなる</b>。
    /// 実測でも、この形で <c>[ResponseCache(Duration = 300, Location = Any)]</c> を足すと
    /// 全件緑のままテスト件数すら変わらずに通った。
    /// 代わりに<b>宣言元が自分たちのアセンブリか</b>で切る
    /// (<c>UnlistedFilterValuePolicyTests.MatchingActionParameters</c> と同じ判断)。</para>
    ///
    /// <para>走査対象を引数で受け取るのは、合成したコントローラに対して<b>走査そのもの</b>を
    /// 検証できるようにするため(アプリの実際の宣言が少ないあいだは、拾う経路を 1 つ消しても
    /// 本番の検査は緑のまま通るため)。</para>
    /// </remarks>
    /// <param name="controllers">走査するコントローラ型。</param>
    /// <param name="ownAssembly">「自分たちが宣言したアクション」と見なすアセンブリ。</param>
    /// <returns>見つかった宣言の一覧(同じ宣言が複数の具象から見えても 1 件に畳む)。</returns>
    public static IEnumerable<ResponseCacheDeclaration> DeclarationsOn(
        IEnumerable<Type> controllers,
        Assembly ownAssembly)
    {
        // 同じ宣言を二重に数えないための記録(基底の 1 つのアクションは派生の数だけ見える)
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // 渡されたコントローラを 1 つずつ見る
        foreach (var controller in controllers)
        {
            // クラス全体に付いた属性(付いていれば全アクションに効く)を読む。
            // inherit: true にするのは、基底コントローラで宣言して派生が継承する形を取りこぼさないため
            foreach (var attribute in controller.GetCustomAttributes<ResponseCacheAttribute>(inherit: true))
            {
                // どのコントローラに付いていたかが分かる表示名を作る
                var declaredOn = controller.FullName ?? controller.Name;
                // 同じ表示名で既に返していなければ返す
                if (seen.Add($"type:{declaredOn}"))
                {
                    // クラス側の宣言として返す
                    yield return new ResponseCacheDeclaration(declaredOn, attribute);
                }
            }

            // 各アクション(公開されたインスタンスメソッド)に付いた属性を読む
            foreach (var method in controller.GetMethods(BindingFlags.Public | BindingFlags.Instance))
            {
                // フレームワークの基底(ControllerBase 等)が持つメソッドは自分たちの宣言ではないので飛ばす。
                // 「この型が宣言したか」で切らないのは、基底へ引き上げたアクションを取りこぼさないため
                if (method.DeclaringType?.Assembly != ownAssembly)
                {
                    // 次のメソッドへ
                    continue;
                }

                // そのメソッドに付いた属性を読む
                foreach (var attribute in method.GetCustomAttributes<ResponseCacheAttribute>(inherit: true))
                {
                    // 宣言元の型で名指しする(基底へ引き上げた場合に「どこを直すか」が分かる)
                    var declaringType = method.DeclaringType!;
                    // どのアクションに付いていたかが分かる表示名を作る
                    var declaredOn = $"{declaringType.FullName ?? declaringType.Name}.{method.Name}";
                    // 同じ宣言を派生の数だけ返さないよう、シグネチャまで含めて記録する
                    if (seen.Add($"method:{declaredOn}({method.ToString()})"))
                    {
                        // アクション側の宣言として返す
                        yield return new ResponseCacheDeclaration(declaredOn, attribute);
                    }
                }
            }
        }
    }
}
