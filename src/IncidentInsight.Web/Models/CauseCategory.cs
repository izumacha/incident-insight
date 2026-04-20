// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models;

// 原因分類(ヒューマンエラー・設備起因など)を表すクラス。親子のツリー構造を持つ
public class CauseCategory
{
    // 主キー(自動採番)
    public int Id { get; set; }

    // 分類名は必ず入力が必要で、最大100文字まで
    [Required]
    [MaxLength(100)]
    [Display(Name = "分類名")]
    public string Name { get; set; } = "";

    // 分類の説明文(省略可)
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
    public string FullName => Parent != null ? $"{Parent.Name} > {Name}" : Name;
}
