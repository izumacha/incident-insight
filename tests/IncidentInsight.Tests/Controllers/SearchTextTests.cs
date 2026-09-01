// テスト中だけカルチャ(ロケール)を差し替えるために使う
using System.Globalization;
// 検証対象の正規化ヘルパを使う
using IncidentInsight.Web.Controllers.Internal;

// テストの名前空間(対象と同じ Controllers 系に置く)
namespace IncidentInsight.Tests.Controllers;

/// <summary>
/// 一覧検索のキーワード正規化(<see cref="SearchText.NormalizeForContainsSearch"/>)が
/// サーバの OS ロケールに左右されないことを固定するテスト。
///
/// <para><b>なぜコントローラ経由ではなく単体で見るのか。</b> 検索の突き合わせは
/// 「列の側(本番では DB の <c>UPPER()</c>)」と「キーワードの側(アプリ)」の 2 辺から成るが、
/// テストが使う InMemory プロバイダには SQL が無く、式ツリーの <c>col.ToUpper()</c> も
/// アプリ内で現在のカルチャに従って評価されてしまう。つまりコントローラ経由で
/// トルコ語ロケールを再現しても、本番には存在しない「列の側もカルチャ依存」という条件が
/// 混ざり、何を確かめたのか分からなくなる。本番と同じ条件で意味を持つのは
/// キーワード側の規則だけなので、そこを単体で固定する
/// (この切り分けの根拠は SearchText の docstring にも書いてある)。</para>
/// </summary>
public class SearchTextTests
{
    /// <summary>
    /// トルコ語ロケールでも ASCII の小文字 i が U+0130(İ)ではなく ASCII の I になることを固定する。
    ///
    /// <para>引数なしの <c>ToUpper()</c> に戻すとこのテストが落ちる。トルコ語系ロケール
    /// (tr-TR / az-*)では <c>"incident".ToUpper()</c> が <c>"İNCİDENT"</c> になる一方、
    /// DB の <c>UPPER('incident')</c> はどの照合順序でも <c>"INCIDENT"</c> を返すため、
    /// 正規の検索語が 1 件もヒットしなくなる。</para>
    /// </summary>
    [Fact]
    public void NormalizeForContainsSearch_IsUnaffectedByTurkishLocale()
    {
        // 現在のスレッドのカルチャを退避しておく(他のテストへ影響を残さないため)
        var original = CultureInfo.CurrentCulture;
        try
        {
            // ドット無し I を持つトルコ語ロケールへ切り替える(この規則の差が出る代表的なロケール)
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");

            // 検索キーワードを正規化する
            var normalized = SearchText.NormalizeForContainsSearch("incident");

            // DB の UPPER() と同じ ASCII の I になっていること(İ を含んでいないこと)
            Assert.Equal("INCIDENT", normalized);
        }
        finally
        {
            // 退避しておいたカルチャへ必ず戻す(テスト間の実行順で結果が変わらないようにする)
            CultureInfo.CurrentCulture = original;
        }
    }

    /// <summary>
    /// ロケールを差し替えても正規化結果が変わらないことを、複数のロケール間の比較で固定する。
    ///
    /// <para>上のテストが「期待値そのもの」を固定するのに対し、こちらは
    /// <b>ロケール間で結果がぶれないこと</b>という別の切り口で見る。将来ヘルパの実装を
    /// 変えたときに、期待値だけを書き換えて通してしまう事故を防ぐ。</para>
    /// </summary>
    [Fact]
    public void NormalizeForContainsSearch_GivesSameResultAcrossLocales()
    {
        // 現在のスレッドのカルチャを退避しておく
        var original = CultureInfo.CurrentCulture;
        try
        {
            // 日本語ロケール(想定される主な配備先)での正規化結果を取る
            CultureInfo.CurrentCulture = new CultureInfo("ja-JP");
            var underJapanese = SearchText.NormalizeForContainsSearch("Incident-i");

            // トルコ語ロケール(大文字化規則が異なるロケール)での正規化結果を取る
            CultureInfo.CurrentCulture = new CultureInfo("tr-TR");
            var underTurkish = SearchText.NormalizeForContainsSearch("Incident-i");

            // ロケールが違っても同じ結果であること(＝サーバのロケールに依存しない)
            Assert.Equal(underJapanese, underTurkish);
        }
        finally
        {
            // 退避しておいたカルチャへ必ず戻す
            CultureInfo.CurrentCulture = original;
        }
    }
}
