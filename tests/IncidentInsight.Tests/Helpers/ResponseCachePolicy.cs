// ResponseCacheAttribute を使う
using Microsoft.AspNetCore.Mvc;
// 属性とアクションをリフレクションで走査するために使う
using System.Reflection;
using System.Text.RegularExpressions;

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
public static partial class ResponseCachePolicy
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
    ///
    /// <para><b>継承は「後から打ち消す」のではなく、最初から宣言元を歩く(issue #275)。</b>
    /// 以前は具象ごとに <c>GetCustomAttributes(inherit: true)</c> で読み(＝<b>継承した 1 つの
    /// 宣言が派生の数だけ現れる</b>)、宣言元をたどる仕組みでその継承を打ち消し、さらに
    /// 観測場所ごとの記録と走査全体の記録で重複した観測を打ち消していた。つまり
    /// 「継承して見えた」という性質を 2 段階で後から取り消しており、重複判定のパッチが
    /// 3 周目に入ったうえ、<b>2 つの記録へ入れる順序に正しさが依存</b>していた
    /// (順序への依存は差分では見えにくく、次の人が踏みやすい)。</para>
    ///
    /// <para><b>いまは継承の連なりを 1 段ずつたどり、各段を <c>inherit: false</c> で読む。</b>
    /// こうすると (a) 宣言元は<b>歩いている段そのもの</b>なので後追いが要らず、
    /// (b) 「同じ宣言を 2 つの派生から見る」形は<b>構造的に起こりえない</b>ので
    /// 畳むための内容キーも要らず(段を 1 度だけ訪ねるための型の集合で足りる)、
    /// (c) 同じ場所へ複数付いた宣言は<b>そのまま件数として返る</b> ——
    /// 以前はここで 2 個目が消えるため fail-closed の門番を置いていたが、
    /// <b>失われる経路そのものが無くなった</b>ので門番ごと不要になった。</para>
    ///
    /// <para><b>報告するのは「ソースに書かれた宣言」すべてで、実行時に効くものだけではない。</b>
    /// 派生が同じ種類を宣言し直していても、基底の宣言は<b>別の派生からは効く</b>し、
    /// 将来 <c>override</c> しない派生が足された時点で効き始める。狭めると
    /// 「いま宣言し直している派生があるという理由で、危険な基底の宣言が報告されない」
    /// という無言の fail-open になるので、宣言そのものを漏れなく返す側へ倒す。</para>
    /// </remarks>
    /// <param name="controllers">走査するコントローラ型。</param>
    /// <param name="ownAssembly">「自分たちが宣言したアクション」と見なすアセンブリ。</param>
    /// <param name="matches">拾う属性かどうかを判定する条件。</param>
    /// <returns>見つかった宣言の一覧(同じ段を複数の具象から辿っても 1 度しか読まない)。</returns>
    public static IEnumerable<AttributeDeclaration> AttributeDeclarationsOn(
        IEnumerable<Type> controllers,
        Assembly ownAssembly,
        Func<object, bool> matches)
    {
        // 既に読み終えた<b>宣言の置き場所</b>(＝継承の連なりの 1 段)を覚えておく集合。
        // 内容ではなく<b>段そのもの</b>を覚えるのが要点で、基底を共有する連なりを 1 度に畳むためだけに要る
        // (以前のように「宣言の内容」をキーにすると、同じ内容の別々の宣言まで畳んでしまう)
        var visitedSites = new HashSet<Type>();

        // 渡されたコントローラを 1 つずつ見る
        foreach (var controller in controllers)
        {
            // その具象から基底へ、継承の連なりを 1 段ずつさかのぼる
            for (var type = controller; type is not null; type = type.BaseType)
            {
                // 閉じた総称型は開いた定義へそろえてから読む。そろえないと
                // ExportBase&lt;Pdf&gt; と ExportBase&lt;Csv&gt; が別の段として 2 度読まれ、
                // <b>1 つの宣言が閉じ方の数だけ並ぶ</b>(理由の正本は DeclarationSite の説明)
                var site = DeclarationSite(type);

                // この段を既に読んでいれば、<b>その基底もすべて読み終えている</b>ので連なりごと打ち切る。
                // 開いた定義の基底の連なりは閉じ方によらず同じなので、閉じ方が違っても取りこぼさない
                if (!visitedSites.Add(site)) break;

                // 名指しに使う綴りを 1 度だけ組み立てる(素の FullName を使わない理由は TypeDisplayName が正本)
                var siteName = TypeDisplayName(site);

                // クラス全体に付いた属性(付いていれば全アクションに効く)を、<b>その段自身の宣言だけ</b>読む。
                // inherit: false にできるのは、継承した分は基底の段を訪ねたときに読むため
                foreach (var attribute in site.GetCustomAttributes(inherit: false).Where(matches))
                {
                    // クラス側の宣言として、宣言している型の名前で返す
                    yield return new AttributeDeclaration(siteName, attribute);
                }

                // フレームワークの基底(ControllerBase 等)が宣言したアクションは自分たちの宣言ではないので、
                // アクション側の走査だけ飛ばして基底へ進む。
                // <b>クラス側は飛ばさない</b> ——以前の inherit: true の読み方でも、フレームワーク側の型が
                // 宣言したクラス属性は継承されて見えていた(ここで飛ばすと走査範囲が黙って狭まる)。
                // <b>残っている境界(issue #275 以前から同じ)。</b> この 1 行を<b>外す</b>変異には
                // 検出網が無い ——外すとフレームワーク側のメソッドまで読むが、そこに拾う属性が
                // 1 つも無いので違反は 1 件も増えず、全件緑のまま通る(実測。旧実装でも同じだった)。
                // 倒れる向きが「過剰に報告する」側なので許容している。逆に<b>狭める</b>変異
                // (自分たちのアセンブリを別のものに取り違える等)は、アクション側の検査が
                // すべて落ちるので捕まる。
                if (site.Assembly != ownAssembly) continue;

                // その段が<b>自分で宣言している</b>アクション(公開されたインスタンスメソッド)を読む。
                // DeclaredOnly にできるのは、基底の分は基底の段を訪ねたときに読むため
                foreach (var method in site.GetMethods(
                    BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {
                    // そのメソッド自身に付いた属性だけを読む(override の連なりをさかのぼる必要が無い)
                    foreach (var attribute in method.GetCustomAttributes(inherit: false).Where(matches))
                    {
                        // 表示名は<b>返す分だけ</b>組み立てる。
                        // <b>引数の型まで載せる</b>のは、載せないと同じ名前のオーバーロードが
                        // 2 つとも違反したとき<b>まったく同じ行が 2 本</b>並び、片方だけが違反なら
                        // 名指しされたファイルを開いても<b>どちらを直すのか分からない</b>ため。
                        // 引数の綴りが閉じ方で揺れないのは、段そのものを開いた定義へそろえてあるため
                        // (以前は観測した閉じた総称のメソッドから宣言を引き直していた)
                        var declaredOn = $"{siteName}.{method.Name}({ParameterTypeList(method)})";

                        // アクション側の宣言として返す
                        yield return new AttributeDeclaration(declaredOn, attribute);
                    }
                }
            }
        }
    }

    /// <summary>
    /// 宣言の置き場所(継承の連なりの 1 段)を、<b>名指しと同一性の判定に使う形</b>へそろえる。
    /// </summary>
    /// <remarks>
    /// <b>総称型は開いた定義へ戻す（レビュー指摘）。</b> 総称の抽象基底に 1 つだけ付けた宣言は、
    /// <c>ExportBase&lt;Pdf&gt;</c> と <c>ExportBase&lt;Csv&gt;</c> のように<b>閉じた型ごとに
    /// 別の <c>Type</c></b> になるため、そろえずに訪ねると<b>同じ段を閉じ方の数だけ読み</b>、
    /// 1 つの宣言が具象の数だけ違反として並ぶ。しかも名指しは
    /// <c>ExportBase`1[[…, Version=1.0.0.0, …]]</c> のようなアセンブリ修飾名になり、
    /// <b>開けるファイルを指さない</b> ——この関数と「訪ねた段の記録」が防ぐために存在する形そのもの。
    /// 開いた定義へ戻せば、宣言が 1 つであることも、直すべき 1 か所も正しく出る
    /// (アクションの引数の綴りが閉じ方で揺れないのも、段をここでそろえているため)。
    /// </remarks>
    /// <param name="declaringType">属性を宣言している型。</param>
    /// <returns>名指しと同一性の判定に使う型。</returns>
    private static Type DeclarationSite(Type declaringType) =>
        // 閉じた総称型なら開いた定義へ、それ以外はそのまま
        declaringType.IsGenericType ? declaringType.GetGenericTypeDefinition() : declaringType;

    /// <summary>メソッドの引数の型を、表示名へ載せる 1 語にする。</summary>
    /// <remarks>
    /// <b>単純名で並べない（レビュー指摘・実測）。</b> 名前空間だけが違う同名の型
    /// （MVC では <c>Models.Incident</c> と <c>ViewModels.Incident</c> のような対が普通に起きる）を
    /// 受けるオーバーロードは、単純名だと <c>Export(Incident)</c> で<b>一字一句同じ</b>になり、
    /// 引数を載せた理由（どちらを直すのか分かるようにする）がその形でだけ失われる。
    /// <b>どちらが衝突するかは兄弟のオーバーロードを見ないと決められない</b>ので、
    /// 条件で出し分けず一律に完全修飾名で並べる（宣言元の型も完全修飾名で名乗っており、そろう）。
    /// 型引数（<c>TModel</c>）は完全修飾名を持たないので、そのときだけ単純名になる。
    /// </remarks>
    /// <param name="method">引数を並べるメソッド。</param>
    /// <returns>引数の型名をカンマで区切った 1 語（引数が無ければ空文字）。</returns>
    private static string ParameterTypeList(MethodBase method) =>
        // 型ごとの綴りは TypeDisplayName が決める(素の FullName を使わない理由はそちらの説明が正本)
        string.Join(
            ", ",
            method.GetParameters().Select(parameter => TypeDisplayName(parameter.ParameterType)));

    /// <summary>型を、表示名へ載せる読める 1 語にする。</summary>
    /// <remarks>
    /// <para><b>素の <c>FullName</c> を使わない（レビュー指摘・実測）。</b> 構築済みの総称型の
    /// <c>FullName</c> は<b>アセンブリ修飾名</b>を含むので、<c>DateTime?</c> を受けるアクションは
    /// <c>System.Nullable`1[[System.DateTime, System.Private.CoreLib, Version=8.0.0.0, …]]</c>
    /// と名乗る ——<see cref="DeclarationSite"/> の説明が「<b>開けるファイルを指さない</b>」として
    /// 退けた綴りそのもので、しかもこの repo は期間・enum の絞り込みを
    /// <c>Nullable&lt;T&gt;</c> で受けることを規約で求めている（いちばん出やすい形）。</para>
    ///
    /// <para><b><c>FullName ?? Name</c> でも足りない（レビュー指摘・実測）。</b> 開いた総称
    /// （<c>List&lt;T1&gt;</c>）は <c>FullName</c> を持たないので <c>Name</c> へ落ち、
    /// <c>List`1</c> だけが残る ——総称の基底で <c>Export(List&lt;T1&gt;)</c> と
    /// <c>Export(List&lt;T2&gt;)</c> を分けているオーバーロードが<b>同じ名前</b>になり、
    /// 引数を載せた理由がその形でだけ失われる。</para>
    ///
    /// <para>そこで型引数まで自分で組み立てる。名前空間は残し（単純名だけだと
    /// 名前空間違いの同名の型が衝突する）、アセンブリ修飾名は載せない。</para>
    /// </remarks>
    /// <param name="type">綴りにする型。</param>
    /// <returns>表示名へ載せる 1 語。</returns>
    private static string TypeDisplayName(Type type)
    {
        // 型引数(TModel / T1)はそれ自身が名前なので、そのまま使う
        if (type.IsGenericParameter) return type.Name;

        // <b>参照渡し(ref / out / in)とポインタは、包んでいる殻を剥いてから綴る（レビュー指摘・実測）。</b>
        // 剥かないと総称でも配列でもない扱いになり、素の FullName へ落ちて
        // `System.Nullable`1[[System.DateTime, …, Version=8.0.0.0, …]]&` という
        // <b>開けるファイルを指さない</b>綴りがそのまま出る(走査はアクション以外の公開メソッドも見る)
        if (type.IsByRef) return TypeDisplayName(type.GetElementType()!) + "&";

        // ポインタも同じ理由で剥く
        if (type.IsPointer) return TypeDisplayName(type.GetElementType()!) + "*";

        // 配列は要素の綴りに角括弧を付ける(要素が型引数でも読める形になる)
        if (type.IsArray)
        {
            // <b>次元を落とさない（レビュー指摘・実測）。</b> 落とすと int[,] が int[] と
            // 同じ綴りになり、2 つのオーバーロードが同じ 1 行として並ぶ
            var rank = type.GetArrayRank();

            // 次元の数だけカンマを入れた角括弧を作る(1 次元なら [] のまま)
            var brackets = "[" + new string(',', rank - 1) + "]";

            // 要素の綴りに角括弧を足して返す
            return TypeDisplayName(type.GetElementType()!) + brackets;
        }

        // 総称でなければ、名前空間付きの名前をそのまま使う(持たなければ単純名)
        if (!type.IsGenericType) return type.FullName ?? type.Name;

        // 総称は、開いた定義の名前から `1 のような個数の印を落とす
        var definition = type.GetGenericTypeDefinition();

        // 名前空間付きの名前を取り出す(開いた定義は FullName を持つ)
        var rawName = definition.FullName ?? definition.Name;

        // <b>最初の印で切らない（レビュー指摘・実測）。</b> 総称型の中に入れ子にした型は
        // `Ns+Outer`1+Inner` の形で、最初の印までで切ると入れ子の段(+Inner)ごと落ちて
        // Outer&lt;int&gt;.Inner と Outer&lt;int&gt;.Other が<b>同じ綴り</b>になる
        // ——引数の型を載せた理由がその形でだけ失われる。印だけを取り除く
        var name = ArityTicks().Replace(rawName, string.Empty);

        // 型引数も同じ規則で綴る(入れ子の総称でも読める形になる)
        var arguments = string.Join(", ", type.GetGenericArguments().Select(TypeDisplayName));

        // 名前と型引数を組み立てて返す
        return $"{name}<{arguments}>";
    }

    /// <summary>総称の個数の印（<c>`1</c>）を見つける正規表現。</summary>
    /// <returns>個数の印に一致する正規表現。</returns>
    [GeneratedRegex("`[0-9]+")]
    private static partial Regex ArityTicks();
}
