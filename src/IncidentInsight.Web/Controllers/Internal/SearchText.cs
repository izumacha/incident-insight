// 下の docstring が <see cref="CultureInfo.CurrentCulture"/> を参照するために要る
// (実行コードでは使わない。cref の解決に using が必要なため残している)
using System.Globalization;

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
/// <see cref="CultureInfo.CurrentCulture"/>(＝サーバ OS のロケール)に従ってしまう。
/// トルコ語系ロケール(tr-TR / az-*)では <c>"incident".ToUpper()</c> が <c>"İNCİDENT"</c>
/// (U+0130 を含む)になる一方、DB の <c>UPPER('incident')</c> はどの照合順序でも <c>"INCIDENT"</c>
/// を返すため、<b>正規の検索語が 1 件もヒットしなくなる</b>(実測で確認済み)。
/// 「配備先によらず同じ結果」を狙って入れた正規化が、逆にサーバのロケールという別の環境差を
/// 持ち込んでいたことになる(CLAUDE.md §10 プラットフォーム差異ゼロ設計)。
/// ロケールに依存しない <see cref="string.ToUpperInvariant"/> なら ASCII は DB の
/// <c>UPPER()</c> と同じ結果になり、この食い違いが消える。</para>
///
/// <para><b>残る境界(誤解を避けるため明記する)。</b> 本番では列の側を大文字化するのは DB だが、
/// テストが使う InMemory プロバイダには SQL が無く、式ツリーの <c>col.ToUpper()</c> は
/// <b>アプリ内で</b> 現在のカルチャに従って評価される。つまり InMemory 上では列の側だけが
/// カルチャ依存のまま残り、トルコ語系ロケールで走らせると検索は一致しない。
/// これはテスト実行環境に限った性質で、本番の経路(SQL への翻訳)には影響しない。
/// そのため本ヘルパの検証は「キーワード側の正規化が
/// カルチャに依存しないこと」を単体で固定する形にしてある(<c>SearchTextTests</c>)。</para>
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
