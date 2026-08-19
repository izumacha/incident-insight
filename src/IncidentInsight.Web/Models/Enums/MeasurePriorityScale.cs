// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Enums;

/// <summary>
/// 再発防止策の「優先度」(1=高 / 2=中 / 3=低 の 3 段階)に関する語彙・段階数・配色の
/// 唯一の真実の源(single source of truth)。
///
/// この尺度は enum ではなく <c>int</c>(<see cref="Models.PreventiveMeasure.Priority"/>)で
/// 保持しているため <see cref="EnumLabels"/> の変換表に載せられず、結果として
/// 同じ語彙・同じ段階数・同じ配色が次の 7 箇所へ写経されていた:
///   - <c>Models/PreventiveMeasure.cs</c>              … [Range] の 1〜3・既定値 2・PriorityLabel / PriorityColor の switch
///   - <c>Models/ViewModels/IncidentViewModels.cs</c>  … [Range] の 1〜3・既定値 2・エラーメッセージに段階の文言を直書き
///   - <c>Views/Incidents/Create.cshtml</c>            … &lt;option value="1"&gt;高&lt;/option&gt; を 3 行直書き
///   - <c>Views/Incidents/Details.cshtml</c>           … 同上
///   - <c>Views/PreventiveMeasures/Create.cshtml</c>   … 同上
///   - <c>Views/PreventiveMeasures/Edit.cshtml</c>     … 同上
///   - <c>Data/DbSeeder.cs</c>                         … デモデータの Priority に 1/2/3 を直書き
/// 加えて項目名「優先度」も、ラベル・テーブル見出しとして Incidents 側の 3 箇所へ直書きされていた。
/// この状態では、たとえば段階を 3 → 4 に増やしたり「中」の言い回しを変えたりしたときに、
/// ドロップダウンだけ古い 3 段階のまま残る(= 新しい段階を画面から選べない)一方で
/// [Range] だけが広がる、といった不整合が黙って発生する
/// (CLAUDE.md §6 定数・ラベルの一元管理 / マジックナンバーを避ける)。
/// 段階の番号付け自体(High=1 が最優先)を変えたときにデモデータだけが別の意味を持たないよう、
/// シードの値も High / Medium / Low を経由させている。
///
/// なお <c>tests/IncidentInsight.Tests/Models/PreventiveMeasureTests.cs</c> の
/// <c>PriorityLabel_And_Color_AreCorrect</c> は、意図的にラベルと配色を
/// リテラル(1=高/danger …)で固定したままにしている。ここを含めて全部を尺度参照にすると
/// 検査が「尺度は尺度と一致する」という同語反復になり、綴り間違いや配色の取り違えを
/// 誰も検出できなくなるため、具体値を釘付けする箇所を 1 つだけ残す方針
/// (<see cref="EffectivenessScale"/> と同じ)。ラベルを改名するときはこのテストも直す。
///
/// 構造は既存の <see cref="EffectivenessScale"/>(有効性評価 1〜5 の尺度)に合わせている。
/// Bootstrap カラー名 → 16 進の解決は <see cref="EnumLabels.Hex"/> に委ねるという分担も同じで、
/// ここでは色名までしか持たない。
/// </summary>
public static class MeasurePriorityScale
{
    /// <summary>最も高い優先度(数値が小さいほど優先度が高い)。</summary>
    // 優先度「高」を表す数値
    public const int High = 1;

    /// <summary>中位の優先度。</summary>
    // 優先度「中」を表す数値
    public const int Medium = 2;

    /// <summary>最も低い優先度。</summary>
    // 優先度「低」を表す数値
    public const int Low = 3;

    /// <summary>
    /// 許容範囲の下限。「小さいほど優先度が高い」尺度なので、数値としての最小値は
    /// <see cref="High"/> と同じ値になる([Range] の第 1 引数に使う)。
    ///
    /// <para><b>「High &lt; Medium &lt; Low」という数値の並びは前提条件(load-bearing)。</b>
    /// const は式で導出できない(<c>Math.Min</c> は定数式にならない)ため、ここは別名として
    /// 定義している。番号付けを逆向き(High=3 / Low=1)にすると <see cref="Min"/> が
    /// <see cref="Max"/> を上回り、<see cref="All"/> の <c>Enumerable.Range</c> が負の個数で
    /// <c>ArgumentOutOfRangeException</c> を投げ、[Range(3, 1)] は全ての値を弾く。
    /// 番号付けを反転させたい場合は Min / Max と <see cref="All"/> を並び順に依存しない形へ
    /// 書き換えること。取りこぼしは <c>MeasurePriorityScaleTests.All_EnumeratesEveryStepFromMinToMax</c>
    /// が CI で落として気付けるようにしてある。</para>
    /// </summary>
    // 数値としての最小値(= 高)。High が最小であることが前提
    public const int Min = High;

    /// <summary>
    /// 許容範囲の上限。数値としての最大値は <see cref="Low"/> と同じ値になる
    /// ([Range] の第 2 引数に使う)。並び順が前提である点は <see cref="Min"/> と同じ。
    /// </summary>
    // 数値としての最大値(= 低)。Low が最大であることが前提
    public const int Max = Low;

    /// <summary>
    /// 新規登録フォームの初期選択値。どちらにも寄っていない中位から始めることで、
    /// 起票者を「とりあえず高」「とりあえず低」へ誘導しない(EffectivenessScale.Middle と同じ考え方)。
    /// </summary>
    // 未指定時に採用する優先度(= 中)
    public const int Default = Medium;

    /// <summary>優先度「高」の日本語ラベル。</summary>
    // 画面のバッジ・ドロップダウンに出す文言
    public const string HighLabel = "高";

    /// <summary>優先度「中」の日本語ラベル。</summary>
    // 画面のバッジ・ドロップダウンに出す文言
    public const string MediumLabel = "中";

    /// <summary>優先度「低」の日本語ラベル。</summary>
    // 画面のバッジ・ドロップダウンに出す文言
    public const string LowLabel = "低";

    /// <summary>
    /// 範囲外の値を受け取ったときに表示するラベル。ここで「高」等に丸めてしまうと、
    /// 壊れたデータが正常な優先度に見えてしまうため、意図的に中立な記号を返す(fail-safe)。
    /// </summary>
    // どの段階にも当てはまらないことを示す記号
    public const string UnknownLabel = "-";

    /// <summary>
    /// 範囲外の値に割り当てる中立な Bootstrap カラー名。<see cref="UnknownLabel"/> の配色版で、
    /// フォールバック色を変えたいときの参照元をここ 1 箇所にまとめる。
    /// </summary>
    // 意味を読み取らせないためのグレー
    public const string UnknownColorName = "secondary";

    /// <summary>入力用 ViewModel / エンティティの <c>[Display(Name = ...)]</c> に使う表示名。</summary>
    // 画面上の項目名
    public const string DisplayName = "優先度";

    /// <summary>
    /// 入力用 ViewModel の <c>[Range]</c> に使う日本語エラーメッセージ。
    /// <see cref="Min"/> / <see cref="Max"/> を文中に埋め込めない(属性の引数はコンパイル時定数で
    /// なければならず、定数式に数値→文字列変換が無い)ため、段階数を変えるときはこの文言の
    /// 数字部分も併せて直すこと(<see cref="EffectivenessScale.RangeMessage"/> と同じ制約)。
    /// </summary>
    // 範囲外の値を送られたときに画面へ出す文言
    public const string RangeMessage =
        DisplayName + "は1(" + HighLabel + ")〜3(" + LowLabel + ")の範囲で指定してください";

    /// <summary>
    /// 全段階を優先度の高い順(<see cref="Min"/>〜<see cref="Max"/>)で列挙する。
    /// 4 つのドロップダウン(インシデント登録・詳細・対策登録・対策編集)が共有する。
    /// </summary>
    // 1,2,3 を順に返す
    public static IEnumerable<int> All => Enumerable.Range(Min, Max - Min + 1);

    /// <summary>
    /// 段階に対応する日本語ラベル(高 / 中 / 低)を返す。
    /// </summary>
    /// <param name="priority">1〜3 の優先度。</param>
    // 想定外の値は UnknownLabel に倒す(fail-safe)
    public static string Label(int priority) => priority switch
    {
        // 1 は「高」
        High => HighLabel,
        // 2 は「中」
        Medium => MediumLabel,
        // 3 は「低」
        Low => LowLabel,
        // 範囲外は中立な記号にして、壊れた値を正常な優先度に見せない
        _ => UnknownLabel
    };

    /// <summary>
    /// 段階に対応する Bootstrap カラー名を返す。高=赤 → 低=グレーで緊急度を色でも示す。
    /// 色だけに意味を持たせないよう、同じ情報を <see cref="Label"/> の文字でも併記している
    /// (CLAUDE.md §7)。
    /// </summary>
    /// <param name="priority">1〜3 の優先度。</param>
    // 想定外の値はグレー(secondary)に倒す(fail-safe)
    public static string ColorName(int priority) => priority switch
    {
        // 高は赤(すぐ着手すべき)
        High => "danger",
        // 中は黄(通常の温度感)
        Medium => "warning",
        // 低はグレー(急がない)
        Low => UnknownColorName,
        // 範囲外もグレーにして、配色から誤った意味を読み取らせない
        _ => UnknownColorName
    };
}
