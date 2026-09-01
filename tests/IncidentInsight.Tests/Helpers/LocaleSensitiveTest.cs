// カルチャ(ロケール)を扱うために使う
using System.Globalization;

// テスト用ヘルパーの名前空間
namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// ロケール依存の挙動を検証するテストが共有する前提チェック。
///
/// <para><b>なぜ要るか。</b> これらのテストは「サーバの OS ロケールによって大文字化の
/// 規則が変わる」ことを再現するため、トルコ語ロケールを組み立てて検証する。ところが
/// ホストが globalization-invariant モード(<c>DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1</c>。
/// slim / distroless 系のコンテナでよくある)だと、<c>PredefinedCulturesOnly</c> の既定が
/// true のため <c>new CultureInfo("tr-TR")</c> は <c>CultureNotFoundException</c> を投げる。
/// そのまま投げさせると「製品の不具合」に見える不透明な例外でテストが落ち、実際は
/// <b>実行環境の前提が満たされていないだけ</b>だと読み取れない。</para>
///
/// <para>前提が崩れていることを名指しで報告する形にして、原因の取り違えを防ぐ。
/// 落とす(skip しない)のは意図的で、この環境ではロケール依存の検査が成立しない以上、
/// 黙って緑にするより気づける方が安全なため(fail-closed)。</para>
/// </summary>
internal static class LocaleSensitiveTest
{
    // 大文字化の規則が ASCII と食い違う代表的なロケール(小文字 i が U+0130 になる)
    private const string TurkishCultureName = "tr-TR";

    /// <summary>
    /// トルコ語ロケールを返す。組み立てられない実行環境では、理由が分かる形で落とす。
    /// </summary>
    public static CultureInfo RequireTurkishCulture()
    {
        // トルコ語ロケールの組み立てを試みる
        try
        {
            // 組み立てられたらそのまま返す
            return new CultureInfo(TurkishCultureName);
        }
        catch (CultureNotFoundException e)
        {
            // 組み立てられない＝この環境ではロケール依存の検査が成立しないことを名指しで報告する
            // (原因例外も添えて、環境側の設定であることを追えるようにする)
            throw new InvalidOperationException(
                $"前提が崩れています: この実行環境では {TurkishCultureName} を組み立てられないため、"
                + "ロケール依存の検査を実施できません(globalization-invariant モードの可能性: "
                + "DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1)。製品側の不具合ではありません。", e);
        }
    }
}
