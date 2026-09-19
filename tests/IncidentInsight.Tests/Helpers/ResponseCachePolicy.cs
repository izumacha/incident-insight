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
        // 同じ宣言を二重に数えないための記録(基底の 1 つのアクションは派生の数だけ見える)
        var seen = new HashSet<string>(StringComparer.Ordinal);

        // 渡されたコントローラを 1 つずつ見る
        foreach (var controller in controllers)
        {
            // 「同じ宣言元に、同じ種類の属性が何個目か」を数える。
            // <b>キーを (宣言元, 種類) だけにすると、1 つの宣言元に同じ属性を複数付けられる型
            // (AttributeUsage の AllowMultiple = true)で 2 個目以降が黙って落ちる</b> ——
            // 種類をキーへ足して直したのとまったく同じ形の fail-open が、種類の中に残る。
            // 通し番号なら AllowMultiple = false の属性では必ず 0 になる(そういう属性は
            // 継承の規則上 1 つしか見えない)ので、既存の畳み方は 1 ビットも変わらない。
            // <b>コントローラごとに数え直すのが要点</b> ——走査全体で 1 つ持つと、
            // 基底の同じ宣言を見る 2 つ目の具象で番号が 1 つ進み、キーが変わって
            // 「派生の数だけ並べない」という本来の目的がその場で壊れる(実測で 2 件落ちた)
            var ordinals = new Dictionary<string, int>(StringComparer.Ordinal);

            // クラス全体に付いた属性(付いていれば全アクションに効く)を読む。
            // inherit: true にするのは、基底コントローラで宣言して派生が継承する形を取りこぼさないため
            foreach (var attribute in controller.GetCustomAttributes(inherit: true).Where(matches))
            {
                // <b>名指しは「継承して見えた型」ではなく「実際に宣言している型」で行う。</b>
                // 基底に付けた属性は派生の数だけ見えるので、具象の名前で報告すると
                // (a) 同じ 1 つの宣言が複数件に見え、(b) 名指しされたファイルを開いても
                // 属性が無く、直すべき 1 か所(基底)がどこにも出てこない
                // たどる条件を<b>この属性の型</b>まで絞る。matches をそのまま渡すと、
                // 2 種類以上に一致する述語のとき「別の種類を宣言している型」で止まり、
                // 名指しされたファイルを開いてもその属性が無い、という既に直したはずの形に戻る
                var declaringType = DeclaringTypeOf(controller, SameKindAs(attribute, matches));
                // どこに付いていたかが分かる表示名を作る
                var declaredOn = declaringType.FullName ?? declaringType.Name;
                // 同じ宣言元の<b>同じ属性</b>を既に返していなければ返す(派生の数だけ並べない)。
                // <b>キーに属性の型と通し番号を含める。</b> 型を含めないと、2 種類以上に一致する
                // 述語を渡した瞬間（3 つ目のキャッシュ指示 [OutputCache] を見るようになるときの
                // 最も自然な足し方）に、同じ型へ両方が付いていても先に返った 1 件しか
                // yield されず、もう 1 件は違反の一覧へ到達しない＝静かな fail-open になる。
                // 通し番号はその中で同じ事故が「同じ種類を複数付けられる属性」で再発するのを防ぐ
                if (seen.Add(NextDeclarationKey(ordinals, $"type:{declaredOn}", attribute)))
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

                // そのメソッドに付いた属性を読む
                foreach (var attribute in method.GetCustomAttributes(inherit: true).Where(matches))
                {
                    // 宣言元の型で名指しする(基底へ引き上げた場合に「どこを直すか」が分かる)。
                    // override の場合は method.DeclaringType が派生になるので、
                    // 属性を実際に宣言しているメソッドまでさかのぼる
                    // クラス側と同じ理由で、たどる条件をこの属性の型まで絞る
                    var declaringType = DeclaringTypeOf(method, SameKindAs(attribute, matches));
                    // どのアクションに付いていたかが分かる表示名を作る
                    var declaredOn = $"{declaringType.FullName ?? declaringType.Name}.{method.Name}";
                    // 同じ宣言を派生の数だけ返さないよう、シグネチャと<b>属性の型・通し番号</b>まで
                    // 含めて記録する（どちらを落としてもクラス側とまったく同じ fail-open になる）
                    if (seen.Add(NextDeclarationKey(ordinals, $"method:{declaredOn}({method})", attribute)))
                    {
                        // アクション側の宣言として返す
                        yield return new AttributeDeclaration(declaredOn, attribute);
                    }
                }
            }
        }
    }

    /// <summary>
    /// 「宣言元 × 属性の種類 × その中での通し番号」という、重複除去のキーを作る。
    /// </summary>
    /// <remarks>
    /// <para><b>通し番号まで入れる理由。</b> キーを (宣言元, 種類) で止めると、
    /// <c>AttributeUsage(AllowMultiple = true)</c> の属性を同じ宣言元へ 2 つ付けたとき、
    /// 2 個目以降が <c>seen</c> に飲まれて違反の一覧へ到達しない。
    /// 許す側の宣言が 2 個目だと<b>検査は緑のまま出荷される</b> ——
    /// 種類をキーへ足して直したのと、まったく同じ形の fail-open が種類の中に残る。</para>
    ///
    /// <para><b>既存の畳み方は変わらない。</b> <c>AllowMultiple = false</c> の属性
    /// （<c>[ResponseCache]</c> がこれ）は、継承の規則上 1 つの宣言元から 1 つしか見えないので
    /// 通し番号は必ず 0 になる。基底の 1 つの宣言を派生の数だけ並べない、という本来の
    /// 目的はそのまま保たれる。</para>
    ///
    /// <para><b>残っている境界。</b> <c>AllowMultiple = true</c> の属性を基底と派生の両方が
    /// 宣言している場合、<see cref="DeclaringTypeOf(Type, Func{object, bool})"/> は
    /// どちらの属性についても「派生が宣言している」と答えるため、基底の分が派生の名前で
    /// 報告されうる（その基底を継承する別の具象からは基底の名前でも報告されるので、
    /// <b>1 つの宣言が 2 件に見える</b>）。<b>取りこぼすのではなく多く報告する側</b>なので、
    /// そのまま残してある ——静かに落ちるより、名指しが重複して人の目に触れるほうが安全。
    /// 実際にそういう属性を足す人が、宣言元のたどり方ごと見直すこと。</para>
    /// </remarks>
    /// <param name="ordinals">宣言元と種類ごとの出現回数（この走査 1 回分の作業用）。</param>
    /// <param name="site">宣言元を表すキーの前半（クラス側 / アクション側で綴りが違う）。</param>
    /// <param name="attribute">キーを作りたい属性。</param>
    /// <returns>重複除去に使うキー。</returns>
    private static string NextDeclarationKey(
        Dictionary<string, int> ordinals,
        string site,
        object attribute)
    {
        // 宣言元と属性の種類までをキーの前半にする
        var kind = $"{site}:{attribute.GetType().FullName}";
        // その組み合わせが今回の走査で何個目かを取り出す(初出なら 0)
        var ordinal = ordinals.TryGetValue(kind, out var count) ? count : 0;
        // 次に同じ組み合わせが来たときのために 1 つ進めておく
        ordinals[kind] = ordinal + 1;
        // 通し番号まで含めたキーを返す
        return $"{kind}#{ordinal}";
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
    /// アクション側の <c>[ResponseCache]</c> を<b>実際に宣言している</b>型をたどる。
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
    /// </remarks>
    /// <param name="method">属性が見えているアクションメソッド。</param>
    /// <param name="matches">宣言としてたどる対象かどうかを判定する条件。</param>
    /// <returns>属性を宣言している型。</returns>
    private static Type DeclaringTypeOf(MethodInfo method, Func<object, bool> matches)
    {
        // そのメソッド自身が宣言しているなら、そこが直すべき場所
        if (method.GetCustomAttributes(inherit: false).Any(matches))
        {
            // 宣言しているメソッドの型を返す
            return method.DeclaringType!;
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
            if (declared.GetCustomAttributes(inherit: false).Any(matches)) return type;
        }

        // どこにも見つからなければ、少なくとも見えている型を名指しする(黙って情報を失わない)
        return method.DeclaringType!;
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
