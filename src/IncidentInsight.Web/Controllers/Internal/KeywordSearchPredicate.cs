// 式ツリー(Expression / ExpressionVisitor)を組み立てるために使う
using System.Linq.Expressions;

// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// 一覧画面のフリーワード検索(部分一致・大文字小文字を区別しない)の述語を組み立てる。
///
/// <para><b>なぜ述語ごと共有するのか。</b> この検索は<b>2 つの辺の大文字化がペアで揃って
/// はじめて正しい</b>(下記)。以前はキーワード側だけを共有ヘルパへ集約し、列側の
/// <c>.ToUpper()</c> は呼び出し側の手書きに任せていたが、その形では
/// <b>列側を書き忘れても CI は全件緑のまま通り、PostgreSQL 配備でだけ検索が 0 件になる</b>。
/// 実測(issue #188 の対応時。当時の全体は 752 件): 3 経路すべての列側 <c>.ToUpper()</c> を
/// 落とすと <b>751 passed / 1 failed</b> で、落ちた 1 件は <c>/AuditLogs</c> の
/// <c>Index_FilterByChangedBy_PartialMatch</c>(検索とは別の目的のテストが偶然拾っていた)。
/// <c>/Incidents</c> と <c>/PreventiveMeasures</c> の 2 経路だけを落とすと
/// <b>752 件すべて緑</b>だった。ペアの片方を書ける構造が残っている限り、規約とレビューでしか
/// 守れない。そこで<b>述語そのものをここから出し、呼び出し側が列側の大文字化を書く場所を無くす</b>
/// (前例: <c>PreventiveMeasure.OverdueOn</c> も判定を <c>Expression</c> として出している)。</para>
///
/// <para><b>なぜ両辺を大文字化するのか。</b> 一覧の部分一致検索はいずれも
/// 「列を大文字化した結果に、大文字化したキーワードが含まれるか」で判定する。
/// <c>string.Contains</c> をそのまま使うと、SQLite / SQL Server では大文字小文字を区別しない
/// LIKE に翻訳されるのに Npgsql(PostgreSQL) は区別する比較に翻訳され、同じ検索語でも配備先で
/// 結果が変わってしまうため(DB プロバイダ非依存の原則)。</para>
///
/// <para><b>なぜキーワード側だけ <c>ToUpperInvariant</c> なのか。</b> 突き合わせる 2 つの辺は、
/// 大文字化する主体が違う。
/// <list type="bullet">
///   <item>列の側 … 式ツリー内の <c>col.ToUpper()</c> は EF Core が SQL の <c>UPPER(col)</c> へ
///     翻訳するので、大文字化するのは <b>DB</b>(その照合順序)であってアプリではない。
///     ここで <c>ToUpperInvariant()</c> を書くと EF Core が SQL へ翻訳できず実行時に落ちる。</item>
///   <item>キーワードの側 … C# で評価してパラメータとして渡すので、大文字化するのは <b>アプリ</b>。</item>
/// </list>
/// キーワード側で引数なしの <c>ToUpper()</c> を使うと、アプリ側だけが
/// <see cref="System.Globalization.CultureInfo.CurrentCulture"/>(＝サーバ OS のロケール)に
/// 従ってしまう。トルコ語系ロケール(tr-TR / az-*)では <c>"incident".ToUpper()</c> が
/// <c>"İNCİDENT"</c>(U+0130 を含む)になる一方、標準的な照合順序の DB が返す
/// <c>UPPER('incident')</c> は <c>"INCIDENT"</c> なので、<b>正規の検索語が 1 件も
/// ヒットしなくなる</b>(実測で確認済み)。「配備先によらず同じ結果」を狙って入れた正規化が、
/// 逆にサーバのロケールという別の環境差を持ち込んでいたことになる
/// (CLAUDE.md §10 プラットフォーム差異ゼロ設計)。</para>
///
/// <para><b>残る境界 1: DB 側の照合順序は「ロケール中立」であることを前提にしている。</b>
/// 「どの照合順序でも <c>UPPER('incident')</c> は <c>"INCIDENT"</c>」とは言えない。とくに
/// PostgreSQL の <c>upper()</c> は引数の照合順序(データベースの <c>lc_ctype</c>、または
/// 列・式に付けた ICU 照合順序)に従うため、<c>lc_ctype=tr_TR.UTF-8</c> で初期化した
/// クラスタでは <c>UPPER('incident')</c> が <c>'İNCİDENT'</c> を返す。その場合はアプリ側を
/// 不変規則にしても両辺は一致しない。<b>ここで取り除けるのは「アプリ側がサーバ OS の
/// ロケールで揺れる」ことだけ</b>で、DB 側までロケール中立にすることはできない
/// (それは配備時の照合順序の選択の問題であり、コードからは決められない)。
/// PostgreSQL / Supabase は CLAUDE.md §1 が挙げる一次配備先なので、トルコ語系の
/// <c>lc_ctype</c> でクラスタを作る場合はこの前提が崩れる点に注意する。</para>
///
/// <para><b>残る境界 2: テストの InMemory プロバイダでは列の側もカルチャ依存になる。</b>
/// 本番では列の側を大文字化するのは DB だが、InMemory プロバイダには SQL が無く、
/// 式ツリーの <c>col.ToUpper()</c> は<b>アプリ内で</b>現在のカルチャに従って評価される。
/// つまり InMemory 上では列の側だけがカルチャ依存のまま残る。これはテスト実行環境に限った
/// 性質で、本番の経路(SQL への翻訳)には影響しない。そのためロケールを差し替える
/// テストは、列の側が影響を受けないよう<b>あらかじめ大文字の ASCII</b> を保存したうえで
/// 小文字のキーワードで引く形にしてある
/// (各 <c>*ControllerTests</c> の <c>...SearchUsesInvariantUpperCasing</c>)。
/// <b>その形は裏を返すと「列側の大文字化が無くても通る」</b>ので、列側を見張る役目は
/// 小文字を保存して引く <c>...SearchMatchesLowercaseColumnValues</c> の側が持つ。</para>
///
/// <para><b>残る境界 3: SQLite の <c>upper()</c> は ASCII しか畳まない。</b>
/// 既定プロバイダの SQLite は組み込みの <c>upper()</c> が <c>a-z</c> だけを大文字化する
/// (ICU 拡張を組み込まない限り)。一方アプリ側は <see cref="string.ToUpperInvariant"/> で
/// Unicode 全体を畳むため、<b>非 ASCII の小文字を含む検索語は既定プロバイダでだけ一致しない</b>:
/// 「café」を保存して「café」で検索すると、アプリ側は <c>"CAFÉ"</c>、SQLite 側は
/// <c>upper('café') = 'CAFé'</c> となり 0 件になる(全角の <c>ｉｃｕ</c> なども同様)。
/// SQL Server / PostgreSQL は正しく畳むので一致する。
/// ドメイン語彙が日本語であるこのアプリでは、仮名・漢字に大文字小文字の区別が無いため
/// 実害は限定的だが、<b>「配備先によらず同じ結果」を完全に達成できているわけではない</b>点は
/// 明記しておく。塞ぐならプロバイダ非依存の別手段(照合順序の指定、正規化済み列の保持など)が要り、
/// ここの差し替えでは足りない。</para>
///
/// <para><b>残る境界 4: 「この関数を通したか」を見るソース走査の検出網は無い。</b>
/// 以前ここに書いていた「列側の <c>.ToUpper()</c> を手で付ける」という約束は、
/// 述語をここから出したことで<b>守る対象が無くなった</b>(付ける場所がこの中にしかない)。
/// 残っているのは「新しい一覧検索がこの関数を経由するか」だが、これは
/// <c>ModelStateKeyPrefixMatchTests</c> のようなソース走査では捕まえられない。
/// <b>理由は「必要な書き方まで咎めるから」ではない</b>(<c>col.ToUpper()</c> が現れる場所は
/// もうこの 1 ファイルだけなので、そこを除いた走査なら誤検出は出ない)。
/// そうではなく、<b>捕まえたい形にそもそも目印が無い</b>から:
/// 実際に壊れるのは <c>query.Where(x =&gt; x.Col.Contains(keyword))</c> のように
/// <b>大文字化を 1 つも書かない</b>形で、そこには <c>ToUpper</c> が現れない。
/// <c>Contains</c> はコレクション判定・許可リスト照合などアプリ中に無数にあるので、
/// それを手掛かりにすると正しいコードを大量に咎めることになる
/// (式ツリーの内側かどうかはテキスト走査では判別できず、構文解析が要る)。
/// <c>ToUpper</c> を禁じる走査は<b>「惜しい」書き方しか捕まえられず、本当に壊れる書き方は
/// 素通りする</b>ため、置いても守りたい性質の保証にならない。
/// <b>したがって新しい一覧検索を足すときは、この関数を経由することだけを守ればよい。</b>
/// 既存の 3 経路については、経路ごとのコントローラ級テスト
/// (<c>...SearchUsesInvariantUpperCasing</c> / <c>...SearchMatchesLowercaseColumnValues</c>)が
/// 「この関数が実際に経路上にあること」まで固定している
/// ——どのテストも<b>一致しない行を併せて置く</b>ので、絞り込みが経路から消えると落ちる。</para>
///
/// <para><b>対になる規則。</b> 「そもそも絞り込むかどうか」(空・空白のみの入力を
/// 絞り込み無しとして扱う)は <see cref="Models.Validation.SearchFilter.HasValue"/> が持つ。
/// 呼び出し側は必ずその判定を通してからここを呼ぶ。置き場所が分かれているのは、
/// 空判定を絞り込みの適用側(コントローラ)と「絞り込み中」の表示側(ビュー)の両方が使うのに対し、
/// この大文字化は EF Core のクエリを組み立てる経路にしか現れないため(issue #187)。</para>
/// </summary>
internal static class KeywordSearchPredicate
{
    /// <summary>
    /// 「指定した列のいずれかが、大文字小文字を区別せずキーワードを含む」という述語を返す。
    /// </summary>
    /// <remarks>
    /// <para><b>キーワードがパラメータとして SQL へ渡ることを保つ書き方にしてある。</b>
    /// 大文字化した値を <see cref="Expression.Constant(object)"/> で埋め込むと、EF Core は
    /// それを SQL の<b>リテラル</b>として展開する(検索語ごとに別のクエリ文字列になり、
    /// DB 側の実行計画キャッシュが検索語の数だけ汚れる。ログにも利用者の入力がそのまま乗る)。
    /// そこで判定の本体は <c>matchesKeyword</c> という<b>ふつうの C# のラムダ</b>として書き、
    /// キーワードを C# のクロージャに捕まえさせている。EF Core はクロージャ経由の値を
    /// パラメータとして扱うため、集約前(呼び出し側がローカル変数を捕まえていた頃)と
    /// 同じ SQL になる。<b>この性質は理由を書くだけでは守られない</b>
    /// (組み立て直すと SQL は変わるのに、件数だけを見るテストは全件緑のまま通る。実測)ので、
    /// <c>KeywordSearchSqlTranslationTests.KeywordSearch_PassesTheKeywordAsAParameter_NotAsALiteral</c>
    /// が発行された SQL 本文を読んで固定している。</para>
    ///
    /// <para><b>ラムダで書くもう 1 つの理由</b>は、守りたいペア
    /// (<c>列.ToUpper()</c> と 大文字化済みキーワード)が<b>1 行の中で隣り合う</b>こと。
    /// 式ツリーを部品から手で組み立てると、ペアが再び 2 箇所に分かれてしまう。</para>
    /// </remarks>
    /// <typeparam name="TEntity">検索対象のエンティティ型。</typeparam>
    /// <param name="keyword">
    /// 利用者が入力した検索キーワード。
    /// <b>空でないことは呼び出し側が <see cref="Models.Validation.SearchFilter.HasValue"/> で確認済み</b>
    /// (上の「対になる規則」を参照)。
    /// </param>
    /// <param name="columns">
    /// 突き合わせる列のセレクタ(1 つ以上)。複数渡すと OR で束ねる。
    /// </param>
    /// <returns><c>query.Where(...)</c> へそのまま渡せる述語。</returns>
    /// <exception cref="ArgumentException">列のセレクタが 1 つも渡されなかった場合。</exception>
    public static Expression<Func<TEntity, bool>> Matching<TEntity>(
        string keyword,
        params Expression<Func<TEntity, string>>[] columns)
    {
        // 列が 1 つも無ければ述語を決められない。ここで落とすのは、どちらへ倒しても
        // 黙って壊れるため(常に true にすれば絞り込みが消え、常に false にすれば 0 件になる。
        // どちらも画面上は「そういう結果」に見えて気づけない) ——不明なら拒否する(§9 fail-closed)。
        //
        // 【この門番には検出網が無い】現在の 3 つの呼び出し側はいずれも列を
        // リテラルで書いているので、この分岐は実行経路から到達しない。加えてこの型は
        // internal でテストプロジェクトから直接は呼べない(IncidentControllerHelpers の
        // 2 つの門番と同じ事情)ため、寛容なフォールバック(例: body ?? Expression.Constant(true))
        // へ差し替えても全件緑のまま通る。守っているのは「配列を組み立てて渡す
        // 呼び出し側を後から足したとき、空でも黙って全件返らない」ことなので、
        // **そういう呼び出し側を足す人が、同じ変更セットでこの分岐を通るテストも足すこと**
        if (columns.Length == 0)
            throw new ArgumentException("検索する列を 1 つ以上指定してください。", nameof(columns));

        // キーワード側だけを、実行環境のロケールに左右されない不変(invariant)規則で大文字化する
        var normalized = keyword.ToUpperInvariant();
        // 守りたいペアを 1 行の C# として書く。col.ToUpper() は EF Core が SQL の UPPER(col) へ
        // 翻訳し、normalized はクロージャ経由なのでパラメータとして渡る(上の remarks を参照)
        Expression<Func<string, bool>> matchesKeyword = value => value.ToUpper().Contains(normalized);

        // 束ねた述語が受け取るエンティティ(全セレクタの引数をこれ 1 つへ寄せる)
        var entity = Expression.Parameter(typeof(TEntity), "entity");
        // OR で積み上げていく本体(最初の 1 件が入るまでは null)
        Expression? body = null;
        // 渡された列を順に述語へ変換して OR で束ねる
        foreach (var column in columns)
        {
            // セレクタの本体(例: i.Description)の引数を、共通のエンティティ引数へ差し替える
            var columnValue = SubstituteParameter(column.Body, column.Parameters[0], entity);
            // 判定ラムダの引数(value)を、その列の値へ差し替える(= 列.ToUpper().Contains(キーワード))
            var clause = SubstituteParameter(matchesKeyword.Body, matchesKeyword.Parameters[0], columnValue);
            // 1 件目はそのまま、2 件目以降は || で連結する(C# の || と同じ OrElse を使う)
            body = body is null ? clause : Expression.OrElse(body, clause);
        }

        // 束ねた本体を、共通のエンティティ引数を取るラムダに包んで返す
        // (body は上のループで必ず 1 回は代入される ——列が 0 件の場合は入口で弾いてある)
        return Expression.Lambda<Func<TEntity, bool>>(body!, entity);
    }

    /// <summary>
    /// 式の中に現れる特定の引数を、別の式へ置き換えた新しい式を返す。
    /// </summary>
    /// <remarks>
    /// 別々のラムダから取り出した式は<b>それぞれ自分の引数を参照している</b>ため、
    /// そのまま繋ぐと「どのラムダの引数か」が食い違って
    /// <c>InvalidOperationException</c> になる。差し替えを 1 か所に置いて、
    /// 列セレクタの結合と判定ラムダの埋め込みの両方で使い回す(§6 DRY)。
    /// </remarks>
    /// <param name="body">書き換える対象の式。</param>
    /// <param name="parameter">置き換えたい引数。</param>
    /// <param name="replacement">代わりに埋め込む式。</param>
    /// <returns>引数を置き換えた新しい式(元の式は書き換えない)。</returns>
    private static Expression SubstituteParameter(
        Expression body,
        ParameterExpression parameter,
        Expression replacement)
        // 走査は ExpressionVisitor に任せる(式の種類ごとの再帰を自前で書かない)
        => new ParameterSubstitution(parameter, replacement).Visit(body);

    /// <summary>
    /// 式ツリーを辿って、指定した引数の出現を別の式へ差し替える <see cref="ExpressionVisitor"/>。
    /// </summary>
    private sealed class ParameterSubstitution : ExpressionVisitor
    {
        // 置き換えたい引数(この参照と同一のものだけを対象にする)
        private readonly ParameterExpression _parameter;
        // 代わりに埋め込む式
        private readonly Expression _replacement;

        /// <param name="parameter">置き換えたい引数。</param>
        /// <param name="replacement">代わりに埋め込む式。</param>
        public ParameterSubstitution(ParameterExpression parameter, Expression replacement)
        {
            // 対象の引数を覚えておく
            _parameter = parameter;
            // 埋め込む式を覚えておく
            _replacement = replacement;
        }

        /// <summary>引数に行き当たったときの処理。</summary>
        /// <param name="node">走査中に現れた引数。</param>
        /// <returns>対象の引数なら差し替え後の式、それ以外はそのまま。</returns>
        protected override Expression VisitParameter(ParameterExpression node)
            // 名前ではなく参照で比べる(同名の別ラムダの引数を巻き込まないため)
            => node == _parameter ? _replacement : base.VisitParameter(node);
    }
}
