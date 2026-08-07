// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策の「有効性評価」(1〜5 の 5 段階)に関する語彙・段階数・配色の
/// 唯一の真実の源(single source of truth)。
///
/// この尺度は enum ではなく <c>int?</c>(<see cref="Models.PreventiveMeasure.EffectivenessRating"/>)
/// で保持しているため <see cref="EnumLabels"/> の変換表に載せられず、結果として
/// 同じ語彙・同じ段階数が次の 5 箇所へ写経されていた:
///   - <c>Controllers/AnalyticsController.EffectivenessRating</c> … グラフのラベル配列を直書き
///   - <c>Views/PreventiveMeasures/Review.cshtml</c>              … 端点の補助ラベルを三項演算子で直書き
///   - <c>Views/Incidents/Details.cshtml</c>                      … 「1=効果なし / 3=普通 / 5=非常に効果あり」を直書き
///   - <c>Models/ViewModels/IncidentViewModels.cs</c>             … [Display]/[Range] に段階数と文言を直書き
///   - <c>Scripts/analytics.ts</c>                                … 段階ごとの配色(16進)を直書き
/// この状態では、たとえば段階を 5 → 7 に増やしたり「効果なし」の言い回しを変えたりしたときに
/// 一部の画面だけ古い表示のまま残る(CLAUDE.md §6 定数・ラベルの一元管理 / マジックナンバーを避ける)。
///
/// Bootstrap カラー名 → 16 進の解決は <see cref="EnumLabels.Hex"/> に委ねる。重症度グラフと同じく
/// 「配色の一元管理元は EnumLabels」という構造を崩さないため、ここでは色名までしか持たない。
/// </summary>
public static class EffectivenessScale
{
    /// <summary>評価の下限(最も効果が低い)。</summary>
    // 評価の最小値
    public const int Min = 1;

    /// <summary>評価の上限(最も効果が高い)。</summary>
    // 評価の最大値
    public const int Max = 5;

    /// <summary>
    /// 尺度の中央値。未評価の対策をレビュー画面で開いたときの初期選択にも使う
    /// (どちらにも寄っていない値から始めることで、評価者を高評価・低評価へ誘導しない)。
    /// </summary>
    // 5 段階の真ん中の値
    public const int Middle = 3;

    /// <summary>下限の段階に付ける補助説明。</summary>
    // 「効果がまったく無かった」ことを表す文言
    public const string LowestDescription = "効果なし";

    /// <summary>中間の段階に付ける補助説明。</summary>
    // 可もなく不可もない状態を表す文言
    public const string MiddleDescription = "普通";

    /// <summary>上限の段階に付ける補助説明。</summary>
    // 期待どおりの効果が出たことを表す文言
    public const string HighestDescription = "非常に効果あり";

    /// <summary>
    /// 入力用 ViewModel の <c>[Display(Name = ...)]</c> に使う表示名。
    /// 属性の引数はコンパイル時定数でなければならないためメソッドでは組み立てられないが、
    /// const 文字列同士の連結は定数式として許されるので、端点の文言だけはここから引く。
    /// </summary>
    // 例: 「有効性評価（1=効果なし〜5=非常に効果あり）」
    public const string DisplayName =
        "有効性評価（1=" + LowestDescription + "〜5=" + HighestDescription + "）";

    /// <summary>
    /// 入力用 ViewModel の <c>[Range]</c> に使う日本語エラーメッセージ。
    /// <see cref="Min"/> / <see cref="Max"/> を文中に埋め込めない(定数式に数値→文字列変換が無い)ため、
    /// 段階数を変えるときはこの文言も併せて直すこと。
    /// </summary>
    // 範囲外の値を送られたときに画面へ出す文言
    public const string RangeMessage = "1〜5で評価してください";

    /// <summary>未評価(<c>null</c>)の対策を一覧で示すときの表示文字列。</summary>
    // まだ評価が入力されていないことを表す文言
    public const string UnratedText = "未評価";

    /// <summary>
    /// 評価欄の下に添える短い凡例(例: 「1=効果なし / 3=普通 / 5=非常に効果あり」)。
    /// ラジオボタンだけでは各段階が何を意味するのか分からないため、端点と中央値の
    /// 意味づけを文字でも示す。組み立てをここに置くのは、Razor 側に
    /// 数値と文言の連結を書くと画面ごとに書式がずれるため。
    /// </summary>
    // 「値=説明」を ' / ' で連ねた 1 行の凡例
    public static string HintText =>
        string.Join(" / ", new[] { Min, Middle, Max }.Select(r => $"{r}={Description(r)}"));

    /// <summary>
    /// 全段階を昇順(<see cref="Min"/>〜<see cref="Max"/>)で列挙する。
    /// レビュー画面のラジオボタン生成と、分析グラフのバケット生成が共有する。
    /// </summary>
    // 1,2,3,4,5 を順に返す
    public static IEnumerable<int> All => Enumerable.Range(Min, Max - Min + 1);

    /// <summary>
    /// 段階に対応する補助説明を返す。中間の段階(2・4 など)には説明を付けないため空文字を返す。
    /// </summary>
    /// <param name="rating">1〜5 の評価値。</param>
    // 端点と中央値だけに説明文を割り当てる(それ以外は空文字)
    public static string Description(int rating) => rating switch
    {
        // 最低評価には「効果なし」を出す
        Min => LowestDescription,
        // 真ん中の段階には「普通」を出す
        Middle => MiddleDescription,
        // 最高評価には「非常に効果あり」を出す
        Max => HighestDescription,
        // それ以外(★2・★4)は星の数だけで十分なので説明を付けない
        _ => string.Empty
    };

    /// <summary>
    /// 分析グラフの横軸ラベル(例: 「★1 (効果なし)」「★2」)を返す。
    /// </summary>
    /// <param name="rating">1〜5 の評価値。</param>
    // 説明がある段階だけ括弧付きで補足する
    public static string ChartLabel(int rating)
    {
        // その段階の補助説明を引く(無ければ空文字)
        var description = Description(rating);
        // 説明が無い段階は「★2」のように星と数字だけにする
        return description.Length == 0 ? $"★{rating}" : $"★{rating} ({description})";
    }

    /// <summary>
    /// 段階に対応する Bootstrap カラー名を返す。★1=赤 → ★5=青で「悪い→良い」を色でも示す。
    /// 色だけに意味を持たせないよう、グラフのラベル(<see cref="ChartLabel"/>)にも
    /// 同じ情報を文字で載せている(CLAUDE.md §7)。
    /// </summary>
    /// <param name="rating">1〜5 の評価値。</param>
    // 想定外の値はグレー(secondary)に倒す(fail-safe)
    public static string ColorName(int rating) => rating switch
    {
        // ★1 は赤(効果が無かった)
        Min => "danger",
        // ★2 は橙(赤と黄の中間で、悪化方向であることを示す)
        2 => "orange",
        // ★3 は黄(可もなく不可もなく)
        Middle => "warning",
        // ★4 は緑(効果あり)
        4 => "success",
        // ★5 は青(十分な効果あり)
        Max => "primary",
        // 範囲外はグレーにして、配色から誤った意味を読み取らせない
        _ => "secondary"
    };

    /// <summary>
    /// 評価を ★★★☆☆ のような星記号の並びで返す。未評価(<c>null</c>)は
    /// <see cref="UnratedText"/> を返す。
    /// </summary>
    /// <param name="rating">1〜5 の評価値。未評価なら <c>null</c>。</param>
    // 塗りつぶし星と白抜き星を合わせて必ず Max 個の星を並べる
    public static string Stars(int? rating)
    {
        // 未評価ならその旨の文字列を返す
        if (rating is null)
        {
            return UnratedText;
        }
        // 想定外の値でも星の総数が Max 個から崩れないよう 0〜Max へ丸める(fail-safe)。
        // 下限を Min ではなく 0 にするのは、範囲外の値(0 や負数)を「★1 相当」と
        // 読ませないため。塗りつぶし星 0 個 = 評価に相当する星が無い、と正しく見える。
        // 丸めずに new string('★', rating) とすると、Max を超える値で
        // 白抜き星の個数が負になり ArgumentOutOfRangeException で画面全体が 500 になる
        var filled = Math.Clamp(rating.Value, 0, Max);
        // 評価の数だけ ★ を並べ、残りを ☆ で埋める
        return new string('★', filled) + new string('☆', Max - filled);
    }
}
