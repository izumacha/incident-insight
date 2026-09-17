// フレームワークと同じホスト名の正規化を通すために使う
using Microsoft.AspNetCore.Http;

// この判定が属する名前空間(他の入力検証の規則と同じ場所)
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// <c>AllowedHosts</c> の設定値が「どのホスト名でも受け付ける」状態かを判定する。
/// </summary>
/// <remarks>
/// <para><b>なぜ純粋関数として切り出すのか。</b> 判定を <c>Program.cs</c> の
/// トップレベル文の中へ書くと、テストから呼べるのは「アプリを起動してログを覗く」形しか
/// 残らない。境界値（区切り方・空白・大文字小文字・複数指定）を固定したいので、
/// 判定だけを取り出してある。</para>
///
/// <para><b>判定は「1 つでもワイルドカードがあるか」。</b> ここが要点で、
/// <c>HostFiltering</c> は許可リストにワイルドカード（<see cref="Wildcards"/>）が<b>1 つでも</b>含まれていれば
/// 「空でない Host はすべて受け付ける」に切り替わる。つまり
/// <c>"*;incident.example.com"</c> は「実ホスト名も足した」ように見えて
/// <b>実際には全ホスト許可のまま</b>で、これは実ホスト名を「追加」しようとしたときに
/// 自然に書いてしまう形。以前の判定は値全体が <c>"*"</c> と一致するかだけを見ていたため、
/// この綴りでは警告が出ず、運用者は「ログが出ていない＝絞れている」と読んでしまった
/// （docs/security.md がその確認手順を案内しているぶん、なお悪い）。</para>
/// </remarks>
public static class AllowedHostsPolicy
{
    /// <summary>設定値の区切り文字（ASP.NET Core が <c>AllowedHosts</c> に使うもの）。</summary>
    private const char Separator = ';';

    /// <summary>どのホスト名でも受け付ける状態を表す綴り（3 つとも同じ意味）。</summary>
    /// <remarks>
    /// <para><b><c>*</c> だけではない。</b> <c>HostFilteringMiddleware.IsTopLevelWildcard</c> は
    /// <c>*</c>（HTTP.sys）・<c>[::]</c>（Kestrel の IPv6 Any）・<c>0.0.0.0</c>（IPv4 Any）の
    /// いずれかが<b>1 つでも</b>含まれていれば、許可リスト全体を無効にして
    /// 「空でない Host はすべて受け付ける」へ切り替える。</para>
    ///
    /// <para><b>ここを <c>*</c> だけにすると、直したはずのバグがそのまま残る。</b>
    /// <c>"incident.example.test;0.0.0.0"</c> は <c>"*;incident.example.com"</c> と
    /// <b>構造がまったく同じ</b>（実ホスト名の隣にワイルドカードがある）で、
    /// <c>ASPNETCORE_URLS=http://0.0.0.0:8080</c> を写して書くと自然に生まれる。
    /// 実測でも、この綴りは別ホストを 200 で受けるのに警告が出なかった。</para>
    /// </remarks>
    private static readonly string[] Wildcards = ["*", "[::]", "0.0.0.0"];

    /// <summary>
    /// 許可リストの 1 項目が、フレームワークから見てワイルドカードかを返す。
    /// </summary>
    /// <remarks>
    /// <para><b>生の文字列で比べてはいけない。</b> <c>HostFilteringMiddleware</c> は各項目を
    /// <c>new HostString(entry).ToUriComponent()</c>（IDNA / NFKC の正規化）に通して<b>から</b>
    /// 3 綴りと突き合わせる。そのため全角数字の <c>０.０.０.０</c> や、日本語 IME の読点で
    /// 書いた <c>0。0。0。0</c> は正規化で <c>0.0.0.0</c> になり、
    /// <b>許可リスト全体が無効になる</b>（実測: この 2 つと、1 文字だけ全角の <c>０.0.0.0</c> も同じ）。
    /// 生の <c>Ordinal</c> 比較のままだと、そこがそのまま「警告の出ない全許可」になる ——
    /// この判定が直したはずの穴が、1 段深いところに残る形。</para>
    ///
    /// <para><b>正規化できない綴りは警告する側へ倒す。</b> <c>ToUriComponent()</c> は
    /// <c>"0.0.0.0\t"</c> のような値で例外を投げる。判断できない以上「絞れている」とは
    /// 言えないので、<c>true</c>（＝警告を出す）を返す（§9 fail-closed）。
    /// 過剰に警告する側なので、見逃しにはならない。</para>
    /// </remarks>
    /// <param name="entry">許可リストの 1 項目（前後の空白は除去済み）。</param>
    /// <returns>フレームワークがワイルドカードとして扱うなら <c>true</c>。</returns>
    private static bool IsWildcardEntry(string entry)
    {
        // フレームワークと同じ正規化を通した綴りを入れる
        string normalized;

        // 正規化そのものが失敗しうるので捕まえる
        try
        {
            // HostFiltering と同じ手順でホスト名を正規化する
            normalized = new HostString(entry).ToUriComponent();
        }
        catch (ArgumentException)
        {
            // 判断できない綴りは「絞れている」と言えないので、警告する側へ倒す
            return true;
        }

        // 正規化後の綴りが 3 つのワイルドカードのいずれかかを見る
        return Wildcards.Contains(normalized, StringComparer.Ordinal);
    }

    /// <summary>
    /// その設定値が「実質すべてのホストを許可する」かを返す。
    /// </summary>
    /// <param name="allowedHosts"><c>AllowedHosts</c> の設定値（未設定なら <c>null</c>）。</param>
    /// <returns>未設定・空・ワイルドカードを 1 つでも含むなら <c>true</c>。</returns>
    public static bool IsPermissive(string? allowedHosts)
    {
        // 未設定・空・空白だけなら、絞り込みが効いていない
        if (string.IsNullOrWhiteSpace(allowedHosts)) return true;

        // <b>フレームワークとまったく同じ分割</b>で項目を取り出す(空の項目だけを落とし、
        // <b>トリムはしない</b>)。ここで trim すると、次の「1 件も残らないか」の判定が
        // フレームワークとずれる
        var entries = allowedHosts.Split(Separator, StringSplitOptions.RemoveEmptyEntries);

        // <b>1 件も残らないなら全許可。</b> 汎用ホストの既定設定は
        //   options.AllowedHosts = hosts?.Length > 0 ? hosts : new[] { "*" };
        // なので、";" や ";;" のような値は既定の ["*"] へ落ちて全ホスト許可になる。
        // つまり<b>「空の項目は無害」なのは、空でない項目が 1 つでも残る場合だけ</b>。
        // 実測: AllowedHosts=";" は別ホストを 200 で受ける。この形は手で書くより
        // テンプレート展開(AllowedHosts=${PRIMARY};${SECONDARY} の両方が未定義)で生まれる
        if (entries.Length == 0) return true;

        // 残った項目を 1 つずつ見る(前後の空白は照合の前に落とす)
        return entries
            .Select(entry => entry.Trim())
            // 1 つでもワイルドカードがあれば、その時点で全ホスト許可になる
            .Any(IsWildcardEntry);
    }
}
