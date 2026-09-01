// 共通ヘルパ用の名前空間(Controllers/Internal に隔離して内部利用扱いにする)
namespace IncidentInsight.Web.Controllers.Internal;

/// <summary>
/// 一覧画面のフリーワード検索で、ユーザーが入力したキーワードを
/// 「DB 側の大文字化と突き合わせられる形」へ正規化する。
///
/// <para><b>なぜ必要か。</b> 一覧の部分一致検索は 3 コントローラ
/// (<c>IncidentsController</c> / <c>PreventiveMeasuresController</c> / <c>AuditLogsController</c>)
/// にあり、いずれも「列を大文字化した結果に、大文字化したキーワードが含まれるか」で判定する。
/// <c>string.Contains</c> をそのまま使うと、SQLite / SQL Server では大文字小文字を区別しない
/// LIKE に翻訳されるのに Npgsql(PostgreSQL) は区別する比較に翻訳され、同じ検索語でも配備先で
/// 結果が変わってしまうため(DB プロバイダ非依存の原則)。</para>
///
/// <para><b>なぜ <c>ToUpperInvariant</c> なのか(ここが本ヘルパの要点)。</b>
/// 突き合わせる 2 つの辺は、大文字化する主体が違う。
/// <list type="bullet">
///   <item>列の側 … 式ツリー内の <c>col.ToUpper()</c> は EF Core が SQL の <c>UPPER(col)</c> へ
///     翻訳するので、大文字化するのは <b>DB</b>(その照合順序)であってアプリではない。</item>
///   <item>キーワードの側 … C# で評価してパラメータとして渡すので、大文字化するのは <b>アプリ</b>。</item>
/// </list>
/// ここで引数なしの <c>ToUpper()</c> を使うと、アプリ側だけが
/// <see cref="System.Globalization.CultureInfo.CurrentCulture"/>(＝サーバ OS のロケール)に
/// 従ってしまう。トルコ語系ロケール(tr-TR / az-*)では <c>"incident".ToUpper()</c> が
/// <c>"İNCİDENT"</c>(U+0130 を含む)になる一方、標準的な照合順序の DB が返す
/// <c>UPPER('incident')</c> は <c>"INCIDENT"</c> なので、<b>正規の検索語が 1 件も
/// ヒットしなくなる</b>(実測で確認済み)。「配備先によらず同じ結果」を狙って入れた正規化が、
/// 逆にサーバのロケールという別の環境差を持ち込んでいたことになる
/// (CLAUDE.md §10 プラットフォーム差異ゼロ設計)。ロケールに依存しない
/// <see cref="string.ToUpperInvariant"/> なら、アプリ側の結果が実行環境で揺れなくなる。</para>
///
/// <para><b>残る境界 1: DB 側の照合順序は「ロケール中立」であることを前提にしている。</b>
/// 「どの照合順序でも <c>UPPER('incident')</c> は <c>"INCIDENT"</c>」とは言えない。とくに
/// PostgreSQL の <c>upper()</c> は引数の照合順序(データベースの <c>lc_ctype</c>、または
/// 列・式に付けた ICU 照合順序)に従うため、<c>lc_ctype=tr_TR.UTF-8</c> で初期化した
/// クラスタでは <c>UPPER('incident')</c> が <c>'İNCİDENT'</c> を返す。その場合はアプリ側を
/// 不変規則にしても両辺は一致しない。<b>本ヘルパが取り除くのは「アプリ側がサーバ OS の
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
/// コントローラのテストは、列の側が影響を受けないよう<b>あらかじめ大文字の ASCII</b> を
/// 保存したうえで小文字のキーワードで引く形にしてある(<c>SearchTextTests</c> および
/// 各 <c>*ControllerTests</c> の <c>...SearchUsesInvariantUpperCasing</c>)。</para>
///
/// <para>public にしているのは、この正規化規則をテストから直接固定するため
/// (テストプロジェクトへ internal を公開する設定は置いていない)。
/// 置き場所は、共有相手が上記 3 コントローラであることに合わせて Controllers/Internal に置く。</para>
/// </summary>
public static class SearchText
{
    /// <summary>
    /// 部分一致検索のキーワードを、DB 側の <c>UPPER()</c> と突き合わせられる形へ正規化する。
    /// </summary>
    /// <param name="keyword">利用者が入力した検索キーワード。</param>
    /// <returns>ロケールに依存しない規則で大文字化したキーワード。</returns>
    public static string NormalizeForContainsSearch(string keyword)
        // 実行環境のロケールに左右されない不変(invariant)規則で大文字化して返す
        => keyword.ToUpperInvariant();
}
