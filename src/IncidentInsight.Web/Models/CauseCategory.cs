// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 文字数上限の唯一の真実の源(FieldLengths)を使う
using IncidentInsight.Web.Models.Validation;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

// 原因分類(ヒューマンエラー・設備起因など)を表すクラス。親子のツリー構造を持つ
public class CauseCategory
{
    // 主キー(自動採番)
    public int Id { get; set; }

    // 分類名は必ず入力が必要で、上限は FieldLengths.ShortText
    [Required]
    [MaxLength(FieldLengths.ShortText)]
    [Display(Name = "分類名")]
    public string Name { get; set; } = "";

    // 分類の説明文(省略可)。上限は FieldLengths.FreeText。
    // 上限が無いままだと nvarchar(max) / text 相当の無制限列になり、書き込み経路が
    // 増えたときに際限なく積める(§8 の資源枯渇防止と §9 の DoS 防止に反する)
    [MaxLength(FieldLengths.FreeText)]
    [Display(Name = "説明")]
    public string? Description { get; set; }

    // 親分類のID(親がない=大分類ならnull)
    [Display(Name = "親分類")]
    public int? ParentId { get; set; }

    // 画面で並べるときの順番(数字が小さい順に表示)
    [Display(Name = "表示順")]
    public int DisplayOrder { get; set; }

    // Navigation
    // 親分類への参照(nullなら自分がトップの大分類)
    public CauseCategory? Parent { get; set; }
    // 子分類のリスト(小分類をぶら下げる)
    public ICollection<CauseCategory> Children { get; set; } = new List<CauseCategory>();
    // この分類で作られた なぜなぜ分析のリスト
    public ICollection<CauseAnalysis> CauseAnalyses { get; set; } = new List<CauseAnalysis>();

    // 親かどうか(ParentIdがnullなら自分が親=大分類)
    public bool IsParent => ParentId == null;
    // 「親名 > 自分の名前」の形式の表示文字列(親がなければ自分の名前だけ)
    public string FullName => FormatFullName(Parent?.Name, Name);

    /// <summary>
    /// 「親名 &gt; 自分の名前」形式の表示名を組み立てる規則。親が無ければ自分の名前だけを返す。
    /// </summary>
    /// <remarks>
    /// エンティティを丸ごと読まずに「分類名」と「親の分類名」だけを投影して取得する場面
    /// （<see cref="Services.RecurrenceService"/> のアラート見出し用の名前引き）でも
    /// <see cref="FullName"/> と同じ表記を使えるように、組み立て規則をここに切り出している。
    /// 書き写すと片方だけ区切り文字を変えたときに画面ごとに表記が食い違う（§6 DRY）。
    /// </remarks>
    /// <param name="parentName">親分類の名前。親がなければ null。</param>
    /// <param name="name">自分の分類名。</param>
    /// <returns>表示用の分類名。</returns>
    public static string FormatFullName(string? parentName, string name) =>
        // 親名があれば「親 > 子」、無ければ子の名前だけを返す
        parentName != null ? $"{parentName} > {name}" : name;
}
