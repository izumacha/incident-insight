// カルチャ(ロケール)を扱うために使う
using System.Globalization;

// テスト用ヘルパーの名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// ロケール依存の挙動を検証するテストが共有する前提チェックとカルチャの差し替え。
///
/// <para><b>なぜ要るか。</b> これらのテストは「サーバの OS ロケールによって大文字化や
/// 前方一致の規則が変わる」ことを再現して検証する。ところがホストが
/// globalization-invariant モード(<c>DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1</c>。
/// slim / distroless 系のコンテナでよくある)だと、その規則の差そのものが消える。
/// <b>差が消えた環境では、修正を戻してもテストが通ってしまう</b>——検出網が黙って死ぬ。</para>
///
/// <para><b>「組み立てられたか」ではなく「実際に差が出るか」を見る。</b> 初版は
/// <c>new CultureInfo("tr-TR")</c> が例外を投げないことだけを確かめていたが、
/// <c>DOTNET_SYSTEM_GLOBALIZATION_PREDEFINED_CULTURES_ONLY=0</c> を併用すると
/// 構築は成功する一方カルチャは invariant として振る舞うため、
/// <c>"incident".ToUpper()</c> が <c>"INCIDENT"</c> になり、素の <c>ToUpper()</c> へ
/// 戻しても 3 つのロケールテストが緑のまま通った(実測)。前提は<b>振る舞いで</b>確かめる。</para>
///
/// <para>前提が崩れているときは、原因を名指しして落とす(skip しない)。この環境では
/// ロケール依存の検査が成立しない以上、黙って緑にするより気づける方が安全なため
/// (fail-closed)。「製品の不具合ではない」ことまで文面に含め、原因の取り違えを防ぐ。</para>
/// </summary>
internal static class LocaleSensitiveTest
{
    // 大文字化の規則が ASCII と食い違う代表的なロケール(小文字 i が U+0130 になる)
    private const string TurkishCultureName = "tr-TR";

    // 前提が崩れているときの説明の共通部分(どのチェックでも同じ原因を指すため 1 箇所に置く)
    private const string EnvironmentHint =
        "(globalization-invariant モードの可能性: DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1)。"
        + "製品側の不具合ではありません。";

    /// <summary>
    /// 現在のスレッドのカルチャをトルコ語へ差し替え、破棄時に元へ戻すスコープを返す。
    ///
    /// <para>差し替え前に「そのカルチャで実際に大文字化の規則が変わること」を確かめる。
    /// 各テストが <c>try</c>/<c>finally</c> で退避・復元を書き写していたのをここへ集約した
    /// (CLAUDE.md §6 DRY。前提を厳しくするときに 1 箇所だけ直せば済むようにするため)。</para>
    /// </summary>
    public static IDisposable UseTurkishCulture()
    {
        // トルコ語ロケールの組み立てを試みる
        CultureInfo culture;
        try
        {
            // 組み立てられたら次の振る舞いチェックへ進む
            culture = new CultureInfo(TurkishCultureName);
        }
        catch (CultureNotFoundException e)
        {
            // 構築すらできない環境なので、理由を名指しして落とす
            throw new InvalidOperationException(
                $"前提が崩れています: この実行環境では {TurkishCultureName} を組み立てられないため、"
                + $"ロケール依存の検査を実施できません{EnvironmentHint}", e);
        }

        // 構築できても invariant として振る舞う環境があるので、実際に差が出るかを確かめる。
        // トルコ語では小文字 i の大文字が U+0130(İ)になり、ASCII の I とは一致しないはず
        if (string.Equals("i".ToUpper(culture), "I", StringComparison.Ordinal))
            // 差が出ない＝この環境ではロケール依存の検査が成立しないので落とす
            throw new InvalidOperationException(
                $"前提が崩れています: この実行環境では {TurkishCultureName} でも大文字化の規則が "
                + $"ASCII と同じになるため、ロケール依存の検査が成立しません{EnvironmentHint}");

        // 差し替えたカルチャを破棄時に元へ戻すスコープを返す
        return new CultureScope(culture);
    }

    /// <summary>
    /// 「カルチャ比較なら前方一致してしまう」という前提を、その場で確かめる。
    ///
    /// <para>序数比較かどうかを判別するテストは、ICU が特定の文字を無視できるとみなすことに
    /// 依存している。globalization-invariant モードでは <c>CompareInfo</c> が序数比較へ縮退し、
    /// 前提が崩れたまま「修正を戻しても通る」状態になる。前提を表明しておけば、素通りの
    /// 代わりにここで落ちて原因が分かる(fail-closed)。</para>
    /// </summary>
    /// <param name="key">誤一致させたい ModelState のキー(無視できる文字を含む)。</param>
    /// <param name="prefix">前方一致の対象となる前置詞。</param>
    public static void RequireCultureSensitivePrefixMatch(string key, string prefix)
    {
        // カルチャ比較で前方一致することを確かめる(しなければ判別材料が無い)
        if (!key.StartsWith(prefix, StringComparison.CurrentCulture))
            // 前提が崩れているので、原因を名指しして落とす
            throw new InvalidOperationException(
                "前提が崩れています: この実行環境ではカルチャ比較が誤一致しないため、"
                + $"序数比較かどうかを判別できません{EnvironmentHint}");
    }

    // 現在のスレッドのカルチャを差し替え、破棄時に元へ戻す使い捨てスコープ
    private sealed class CultureScope : IDisposable
    {
        // 差し替える前のカルチャ(復元用)
        private readonly CultureInfo _original;

        // 指定のカルチャへ差し替えつつ、元のカルチャを控える
        public CultureScope(CultureInfo culture)
        {
            // 復元できるよう現在のカルチャを控える
            _original = CultureInfo.CurrentCulture;
            // 検証したいカルチャへ差し替える
            CultureInfo.CurrentCulture = culture;
        }

        // スコープを抜けるときに元のカルチャへ戻す(テスト間の実行順で結果が変わらないようにする)
        public void Dispose() => CultureInfo.CurrentCulture = _original;
    }
}
