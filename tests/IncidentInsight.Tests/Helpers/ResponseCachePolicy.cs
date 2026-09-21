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
    /// 走査が見つけた 1 件の属性の宣言(属性の種類を問わない形)。
    /// </summary>
    /// <param name="DeclaredOn">属性が付いていた場所の表示名。</param>
    /// <param name="Attribute">宣言された属性そのもの。</param>
    public readonly record struct AttributeDeclaration(string DeclaredOn, object Attribute);

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
        Assembly ownAssembly) =>
        // 種類を問わない走査へ「ResponseCacheAttribute であること」を渡し、結果を型付きにする
        AttributeDeclarationsOn(controllers, ownAssembly, a => a is ResponseCacheAttribute)
            .Select(d => new ResponseCacheDeclaration(d.DeclaredOn, (ResponseCacheAttribute)d.Attribute));

    /// <summary>
    /// 渡されたコントローラから、条件に合う属性の宣言を集める(属性の種類を問わない走査)。
    /// </summary>
    /// <remarks>
    /// <para><b>走査を 1 つにしておく理由。</b> 「クラス側とアクション側の両方を読む」
    /// 「宣言元の型で名指しする」「基底の 1 つの宣言を派生の数だけ並べない」は、
    /// どの属性を探すときも同じように要る。属性ごとに走査を書き写すと、
    /// <b>片方だけにこれらの手当てが入っている</b>状態が生まれる ——実際、出力キャッシュの
    /// 検査を別に書いた時点で、基底に付けた属性が派生の数だけ並び、名指しされた
    /// ファイルには属性が無い、という既に直したはずの形が復活していた。</para>
    /// </remarks>
    /// <param name="controllers">走査するコントローラ型。</param>
    /// <param name="ownAssembly">「自分たちが宣言したアクション」と見なすアセンブリ。</param>
    /// <param name="matches">拾う属性かどうかを判定する条件。</param>
    /// <returns>見つかった宣言の一覧(同じ宣言が複数の具象から見えても 1 件に畳む)。</returns>
    public static IEnumerable<AttributeDeclaration> AttributeDeclarationsOn(
        IEnumerable<Type> controllers,
        Assembly ownAssembly,
        Func<object, bool> matches)
    {
        // <b>走査全体</b>で同じ宣言を二重に返さないための記録(基底の 1 つの宣言は派生の数だけ見える)。
        // 観測場所ごとの記録（seenOnThisType / seenOnThisMethod）と対で使う ——
        // 2 つ持つ理由は EnsureNothingWasLost の説明が正本
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // 渡されたコントローラを 1 つずつ見る
        foreach (var controller in controllers)
        {
            // <b>この観測場所（この型のクラス側）から見えた分だけ</b>を数える記録。
            // <b>走査の外へ括り出して使い回さない（レビュー指摘）。</b> 括り出して Clear() で
            // 使い回すと、観測場所ごとに空であることが<b>スコープではなく手で置いた Clear() の
            // 位置</b>に依存する ——観測場所を 1 つ足したり途中に early-exit を挟んだりした瞬間に
            // 前の場所のキーが残り、次の<b>ただ 1 つの宣言</b>が門番に当たって走査ごと落ちる
            // （しかも失敗文言は当てはまらない直し方を案内する）。
            // <b>実体は最初に要ったときに作る</b>(レビュー指摘) ——走査はアセンブリ中の
            // 全コントローラ・全アクションを回るが、キャッシュ指示を宣言しているものはごく一部。
            // スコープはこのままなので、観測場所ごとに空であることは変わらない
            HashSet<string>? seenOnThisType = null;

            // クラス全体に付いた属性(付いていれば全アクションに効く)を読む。
            // inherit: true にするのは、基底コントローラで宣言して派生が継承する形を取りこぼさないため
            foreach (var attribute in controller.GetCustomAttributes(inherit: true).Where(matches))
            {
                // <b>名指しは「継承して見えた型」ではなく「実際に宣言している型」で行う。</b>
                // 基底に付けた属性は派生の数だけ見えるので、具象の名前で報告すると
                // (a) 同じ 1 つの宣言が複数件に見え、(b) 名指しされたファイルを開いても
                // 属性が無く、直すべき 1 か所(基底)がどこにも出てこない
                // たどる条件はこの属性の型まで絞る(理由は SameKindAs の説明が正本)
                var declaringType = DeclarationSite(DeclaringTypeOf(controller, SameKindAs(attribute, matches)));
                // どこに付いていたかが分かる表示名を作る
                var declaredOn = declaringType.FullName ?? declaringType.Name;
                // キーの作り方と、そこに何を含めない選択をしたかは DeclarationKey の説明が正本
                var key = DeclarationKey($"type:{declaredOn}", attribute);

                // この観測場所の記録を、最初に要ったここで作る
                seenOnThisType ??= new HashSet<string>(StringComparer.Ordinal);

                // まだ返していない宣言なら返す(判定はクラス側・アクション側で共通)
                if (IsNewDeclaration(seenOnThisType, seen, key, attribute))
                {
                    // クラス側の宣言として返す
                    yield return new AttributeDeclaration(declaredOn, attribute);
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

                // クラス側と同じ理由で、このアクションの観測場所ぶんを持つ(実体は最初に要ったとき)
                HashSet<string>? seenOnThisMethod = null;

                // そのメソッドに付いた属性を読む
                foreach (var attribute in method.GetCustomAttributes(inherit: true).Where(matches))
                {
                    // 宣言元の型で名指しする(基底へ引き上げた場合に「どこを直すか」が分かる)。
                    // override の場合は method.DeclaringType が派生になるので、
                    // 属性を実際に宣言しているメソッドまでさかのぼる
                    // クラス側と同じく、たどる条件をこの属性の型まで絞る
                    var declaringMethod = DeclaringMethodOf(method, SameKindAs(attribute, matches));
                    // その宣言が置かれている型を、名指しに使う形へそろえる
                    var declaringType = DeclarationSite(declaringMethod.DeclaringType!);
                    // どのアクションに付いていたかが分かる表示名を作る
                    var declaredOn = $"{declaringType.FullName ?? declaringType.Name}.{declaringMethod.Name}";
                    // クラス側と同じキーの作り方（オーバーロードを分けるため宣言の同一性まで含める）
                    var key = DeclarationKey(
                        $"method:{declaredOn}(#{declaringMethod.MetadataToken})", attribute);

                    // この観測場所の記録を、最初に要ったここで作る
                    seenOnThisMethod ??= new HashSet<string>(StringComparer.Ordinal);

                    // クラス側とまったく同じ判定を通す(書き写すと片方だけ戻す変異が書ける)
                    if (IsNewDeclaration(seenOnThisMethod, seen, key, attribute))
                    {
                        // アクション側の宣言として返す
                        yield return new AttributeDeclaration(declaredOn, attribute);
                    }
                }
            }
        }
    }

    /// <summary>
    /// その宣言を<b>まだ返していない</b>かを判定し、返してよければ <c>true</c> を返す。
    /// </summary>
    /// <remarks>
    /// <para>判定は 2 段。<b>同じ観測場所で</b>キーが重なったら、それは本当に 2 つの宣言なので
    /// <see cref="EnsureNothingWasLost"/> に判断させる（1 つの型・1 つのアクションから見える属性は、
    /// 継承して見えたものも含めて 1 度ずつしか現れない）。重ならなければ、あとは
    /// <b>別の派生型から同じ 1 つの宣言を見ている</b>だけかどうかで、既に返していれば黙って畳む
    /// （issue #255 / #269）。</para>
    ///
    /// <para><b>クラス側とアクション側で書き写さない（レビュー指摘）。</b> この走査は
    /// <c>SameKindAs</c>・門番・重複判定と、まったく同じクラス側／アクション側の非対称を
    /// <b>3 度</b>踏んでいる。書き写すと「片方の枝だけを戻す」変異が書けてしまい、
    /// そのたびに対の検査を足すことになる（§6 DRY）。</para>
    /// </remarks>
    /// <param name="seenHere">いま見ている観測場所で既に見たキー。</param>
    /// <param name="seen">走査全体で既に返したキー。</param>
    /// <param name="key">この宣言のキー。</param>
    /// <param name="attribute">この宣言の属性（門番に渡す）。</param>
    /// <returns>宣言として返してよいなら <c>true</c>。</returns>
    private static bool IsNewDeclaration(
        HashSet<string> seenHere,
        HashSet<string> seen,
        string key,
        object attribute)
    {
        // 同じ観測場所で 2 度目なら、畳むと 2 個目が違反の一覧へ到達しない
        if (!seenHere.Add(key))
        {
            // 失って良い重複かどうかを門番に判断させる(複数付けられる属性なら落ちる)
            EnsureNothingWasLost(attribute);

            // 複数付けられない属性なら畳んでよい重複なので、返さない
            return false;
        }

        // 走査全体でまだ返していなければ返してよい(既に返していれば同じ宣言なので畳む)
        return seen.Add(key);
    }

    /// <summary>
    /// 宣言元の型を、<b>名指しとキーに使う形</b>へそろえる。
    /// </summary>
    /// <remarks>
    /// <b>総称型は開いた定義へ戻す（レビュー指摘）。</b> 総称の抽象基底に 1 つだけ付けた宣言は、
    /// <c>ExportBase&lt;Pdf&gt;</c> と <c>ExportBase&lt;Csv&gt;</c> のように<b>閉じた型ごとに
    /// 別の <c>FullName</c></b> を持つため、そのままキーに使うと走査全体の記録で畳まれず
    /// <b>1 つの宣言が具象の数だけ違反として並ぶ</b>。しかも名指しは
    /// <c>ExportBase`1[[…, Version=1.0.0.0, …]]</c> のようなアセンブリ修飾名になり、
    /// <b>開けるファイルを指さない</b> ——この関数と走査全体の記録が防ぐために存在する形そのもの。
    /// 開いた定義へ戻せば、宣言が 1 つであることも、直すべき 1 か所も正しく出る。
    /// </remarks>
    /// <param name="declaringType">属性を宣言している型。</param>
    /// <returns>名指しとキーに使う型。</returns>
    private static Type DeclarationSite(Type declaringType) =>
        // 閉じた総称型なら開いた定義へ、それ以外はそのまま
        declaringType.IsGenericType ? declaringType.GetGenericTypeDefinition() : declaringType;

    /// <summary>
    /// 「宣言元 × 属性の種類」という、重複除去のキーを作る。
    /// </summary>
    /// <remarks>
    /// <para><b>種類まで含める理由。</b> 宣言元だけをキーにすると、2 種類以上に一致する述語
    /// （3 つ目のキャッシュ指示 <c>[OutputCache]</c> を見るようになるときの最も自然な足し方）
    /// を渡した瞬間に、同じ型へ両方が付いていても先に返った 1 件しか <c>yield</c> されず、
    /// もう 1 件は違反の一覧へ到達しない ——<b>検査は緑のまま、PHI を含みうる応答に
    /// 共有キャッシュ可能な指示が残る</b>。</para>
    ///
    /// <para><b>「同じ宣言元に同じ種類が何個目か」は含めない。</b> それが要るのは
    /// <c>AttributeUsage(AllowMultiple = true)</c> の属性を同じ宣言元へ 2 つ付けたときだが、
    /// <b>実在のキャッシュ指示属性はすべて <c>AllowMultiple = false</c></b> なので、
    /// この形は今のところ作れない。通し番号を先回りで入れると
    /// <list type="bullet">
    ///   <item><c>GetCustomAttributes</c> の<b>規定されていない並び順</b>に答えが依存する、</item>
    ///   <item>基底の宣言が派生の名前でも報告されて<b>1 つの宣言が 2 件に見える</b>境界を新たに作る、</item>
    /// </list>
    /// という代償を、実在しない事情のために払うことになる
    /// （CLAUDE.md §6「将来を見越した過度な抽象化を避ける」。この repo は空の除外表が
    /// 「登録するだけで黙らせられる口」になった実例を記録している）。</para>
    ///
    /// <para><b>代わりに fail-closed にしてある。</b> 黙って落とすと静かな fail-open になるので、
    /// <see cref="EnsureNothingWasLost"/> が<b>実際に畳んで 1 件失った時点で落とす</b>。実際にそういう属性を足す人は、そこで必ず一度手を止めることになる
    /// （§9 fail-closed: 不明なら拒否）。</para>
    /// </remarks>
    /// <param name="site">宣言元を表すキーの前半（クラス側 / アクション側で綴りが違う）。</param>
    /// <param name="attribute">キーを作りたい属性。</param>
    /// <returns>重複除去に使うキー。</returns>
    private static string DeclarationKey(string site, object attribute)
    {
        // 宣言元と属性の種類でキーを作る
        return $"{site}:{attribute.GetType().FullName}";
    }

    /// <summary>
    /// 畳んだ 1 件が「失って良い重複」だったことを確かめ、そうでなければ<b>落とす</b>。
    /// </summary>
    /// <remarks>
    /// <b>黙って畳まないための門番。</b> <see cref="DeclarationKey"/> は (宣言元, 種類) で
    /// 畳むので、<c>AllowMultiple = true</c> の属性が同じ宣言元に 2 つ付いていると
    /// 2 個目以降が消える。許す側の宣言がたまたま 2 個目だと<b>検査は緑のまま出荷される</b>ので、
    /// 消す代わりにここで止める。
    ///
    /// <para><b>「その属性を見かけたら」ではなく「実際に畳んだら」で鳴らす。</b>
    /// 前者だと、複数付けられる属性が<b>1 つしか付いていなくても</b>走査全体が落ち、
    /// アセンブリ中の本物の違反が 1 件も報告されなくなる（しかも失敗文言は違反ではなく
    /// キーの話をする）。畳んだ瞬間＝実際に 1 件失った瞬間に鳴らせば、
    /// fail-closed のまま「正しくできる仕事」を止めずに済む。</para>
    ///
    /// <para><b>だから呼び出し側は「観測場所ごと」の記録で判断する（issue #255 / #269）。</b>
    /// 走査全体の記録だけでキーの重なりを見ると、<b>同じ 1 つの宣言を 2 つの派生型から
    /// 見ただけ</b>でも重なる ——<c>AllowMultiple = true</c> かつ継承される指示属性を
    /// 抽象基底へ<b>1 回だけ</b>付けて 2 つ派生させると、2 つ目の派生を見た時点でここが投げ、
    /// キャッシュ関連の検出網が<b>まとめて例外で止まる</b>。しかも失敗文言は
    /// 「キーへ位置を含めろ」と案内するが、<b>宣言は 1 つしか無い</b>のでその助言は当てはまらない
    /// （正しいコードで赤くなる検出網は、いずれ検査ごと緩められる）。
    /// 1 つの型・1 つのアクションから見える属性は、継承して見えたものも含めて
    /// <b>1 度ずつしか現れない</b>ので、同じ観測場所で 2 度重なったときだけが本当の損失になる。</para>
    ///
    /// <para><b>直し方は「キーを位置まで含む形にする」だが、
    /// それだけでは足りない</b> ——宣言元をたどる
    /// <see cref="DeclaringMethodOf(MethodInfo, Func{object, bool})"/> も「その種類を宣言している
    /// 最初の段」で止まるので、同じ種類が複数あると名指しが 1 つに寄る。
    /// <b>2 つをセットで見直すこと。</b></para>
    /// </remarks>
    /// <param name="attribute">確かめる属性。</param>
    /// <exception cref="NotSupportedException">複数付けられる属性だった場合。</exception>
    private static void EnsureNothingWasLost(object attribute)
    {
        // その属性の型が「同じ対象へ複数付けてよい」と名乗っているかを読む
        var allowsMultiple = attribute
            .GetType()
            .GetCustomAttribute<AttributeUsageAttribute>(inherit: true)?
            .AllowMultiple ?? false;

        // 複数付けられない属性が同じキーで重なるのは、基底の 1 つの宣言を
        // 派生の数だけ見ているだけ ——畳むのが正しいので、何も失われていない
        if (!allowsMultiple) return;

        // 複数付けられる属性が畳まれた＝2 個目以降が違反の一覧へ到達しないので落とす(§9 fail-closed)
        throw new NotSupportedException(
            $"{attribute.GetType().FullName} は AllowMultiple = true です。"
                + "この走査は (宣言元, 属性の種類) で重複を畳むため、同じキーへ 2 つ落ちると "
                + "2 個目以降が違反の一覧へ到達しません(許す側が 2 個目だと検査は緑のまま出荷されます)。"
                // <b>「同じ型に 2 つ付いている」と断定しない（レビュー指摘）。</b>
                // 基底と派生に 1 つずつという形でも、DeclaringTypeOf は
                // 「その種類を宣言している最初の段」で止まるので<b>どちらも派生</b>を返し、
                // 同じキーへ落ちてここへ来る ——断定すると、名指しした状況について
                // 事実と違うことを言うことになる
                + "2 つが同じ型にあるとは限りません(基底と派生に 1 つずつでも、"
                + $"{nameof(DeclaringTypeOf)} が「その種類を宣言している最初の段」で止まるため "
                + "同じキーになります)。"
                + "キーへ位置を含める形へ変え、あわせて宣言元をたどる "
                + $"{nameof(DeclaringTypeOf)} / {nameof(DeclaringMethodOf)} "
                + "の名指し(最初の段で止めてよいか)と、"
                // <b>ここも同じ変更セットで見直す（レビュー指摘）。</b> キーへ位置を入れると、
                // 走査全体の畳み込みは「同じ宣言がどの派生から見ても同じ位置に現れる」ことに
                // 依存する ——GetCustomAttributes の並び順は規定されていないので、
                // 派生ごとに順が違えば 1 つの宣言が具象の数だけ並ぶ形が戻る
                + $"{nameof(IsNewDeclaration)} の走査全体の畳み込み"
                + "(位置を入れると、派生ごとに並び順が違ったときに同じ宣言が複数件に見えます)"
                + "も見直してください。");
    }

    /// <summary>
    /// 「拾う条件を満たし、かつ<b>この属性と同じ型</b>」という条件を作る。
    /// </summary>
    /// <remarks>
    /// <b>宣言元をたどるときは、種類まで絞らないと別の属性で止まる。</b>
    /// <c>matches</c> が 2 種類以上に一致する述語（3 つ目のキャッシュ指示を見るように
    /// なるときの自然な形）だと、基底が A・派生が B を宣言している場合に
    /// <c>DeclaringTypeOf</c> は A についても「派生が宣言している」と答える ——
    /// 名指しされたファイルを開いても A が無く、直すべき 1 か所が出てこない。
    /// これは基底へ引き上げた宣言で一度直した形そのものなので、同じ轍を踏まない。
    /// </remarks>
    /// <param name="attribute">宣言元をたどりたい属性。</param>
    /// <param name="matches">呼び出し側が渡した、拾う属性かどうかの条件。</param>
    /// <returns>同じ型の属性だけを通す条件。</returns>
    private static Func<object, bool> SameKindAs(object attribute, Func<object, bool> matches) =>
        // 元の条件を満たし、かつ型が同じものだけを「同じ宣言」と見なす
        candidate => matches(candidate) && candidate.GetType() == attribute.GetType();

    /// <summary>
    /// アクション側の <c>[ResponseCache]</c> を<b>実際に宣言している</b>メソッドをたどる。
    /// </summary>
    /// <remarks>
    /// <c>override</c> したメソッドでは <c>GetCustomAttributes(inherit: true)</c> が基底の属性を
    /// 見つける一方、<c>DeclaringType</c> は<b>派生</b>を指す。そのまま名指しすると、
    /// 1 つの宣言が派生の数だけ違反として並び、しかも名指しされたファイルを開いても
    /// 属性が無く、直すべき 1 か所(基底)がどこにも出てこない
    /// (クラス側の同名のオーバーロードも、同じ理由から同じ手当てをしている)。
    ///
    /// <para><b>さかのぼり方は「根へ跳ぶ」ではなく「1 段ずつ」。</b>
    /// <c>GetBaseDefinition()</c> が返すのは<b>最初に virtual として宣言された定義</b>なので、
    /// 属性が<b>途中の型</b>の <c>override</c> に付いている場合は根にも自分自身にも無く、
    /// どちらの検査も外れて具象が名指しされる。連なりを 1 段ずつ見れば、
    /// 途中の宣言も「自分自身が宣言しているか」で正しく捕まる。</para>
    ///
    /// <para><b>型ではなくメソッドを返す（レビュー指摘）。</b> 重複除去のキーには
    /// オーバーロードを分けるための署名が要るが、そこへ<b>観測した</b>メソッドを使うと、
    /// 総称の基底が <c>Export(TModel model)</c> のように型引数を受けている場合に
    /// <c>Export(Int32)</c> と <c>Export(String)</c> で<b>キーが割れ</b>、
    /// 1 つの宣言が閉じ方の数だけ違反として並ぶ（宣言元の型だけをそろえても閉じない）。
    /// 宣言しているメソッドを返せば、その <c>MetadataToken</c>（同じメタデータ行なら同じ 1 つの宣言）
    /// を署名の代わりに使えて、閉じた総称でも <c>override</c> でも同じ 1 件に畳める。</para>
    /// </remarks>
    /// <param name="method">属性が見えているアクションメソッド。</param>
    /// <param name="matches">宣言としてたどる対象かどうかを判定する条件。</param>
    /// <returns>属性を宣言しているメソッド。</returns>
    private static MethodInfo DeclaringMethodOf(MethodInfo method, Func<object, bool> matches)
    {
        // そのメソッド自身が宣言しているなら、そこが直すべき場所
        if (method.GetCustomAttributes(inherit: false).Any(matches))
        {
            // 宣言しているメソッドそのものを返す
            return method;
        }

        // override の連なりを識別するための目印(同じ仮想メソッドはどこから見ても同じ根を持つ)
        var rootDefinition = method.GetBaseDefinition();

        // <b>根へ一足飛びに跳ばず、override の連なりを 1 段ずつさかのぼる。</b>
        // 跳ぶと、途中の型が宣言した属性を素通りして具象を名指しすることになる ——
        // Root(virtual) → Mid([ResponseCache] override) → Leaf1 / Leaf2(素の override)で、
        // Leaf の inherit: false は空・根は Root.Export なので<b>どちらの検査も外れ</b>、
        // 1 つの宣言が Leaf の数だけ違反として並び、しかも名指しされたファイルを開いても
        // 属性が無い ——この関数が防ぐために存在する形そのものになる(実測で 2 件並んだ)
        for (var type = method.DeclaringType?.BaseType; type is not null; type = type.BaseType)
        {
            // その型<b>自身が宣言している</b>メソッドの中から、同じ仮想メソッドの定義を探す
            var declared = type
                .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .FirstOrDefault(candidate => candidate.GetBaseDefinition().Equals(rootDefinition));

            // その段が同じメソッドを宣言していなければ、さらに基底へ
            if (declared is null) continue;

            // その定義が属性を宣言しているなら、そこが直すべき場所
            if (declared.GetCustomAttributes(inherit: false).Any(matches)) return declared;
        }

        // どこにも見つからなければ、少なくとも見えているメソッドを名指しする(黙って情報を失わない)
        return method;
    }

    /// <summary>
    /// クラス側の <c>[ResponseCache]</c> を<b>実際に宣言している</b>型をたどる。
    /// </summary>
    /// <remarks>
    /// 継承した属性は派生型からも見えるので、<c>inherit: false</c> で「自分自身が
    /// 宣言しているか」を確かめながら基底へさかのぼる。どこにも見つからない場合
    /// (継承の形が想定と違う場合)は、渡された型をそのまま返して名指しを失わせない。
    /// </remarks>
    /// <param name="controller">属性が見えているコントローラ型。</param>
    /// <param name="matches">宣言としてたどる対象かどうかを判定する条件。</param>
    /// <returns>属性を宣言している型。</returns>
    private static Type DeclaringTypeOf(Type controller, Func<object, bool> matches)
    {
        // 自分自身から基底へ順にたどる
        for (var type = controller; type is not null; type = type.BaseType)
        {
            // その型自身が宣言しているなら、そこが直すべき場所
            if (type.GetCustomAttributes(inherit: false).Any(matches)) return type;
        }

        // 見つからなければ、少なくとも見えている型を名指しする(黙って情報を失わない)
        return controller;
    }
}
