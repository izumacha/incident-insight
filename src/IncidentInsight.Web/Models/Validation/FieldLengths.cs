// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// 業務データの文字数上限の唯一の真実の源(single source of truth)。
///
/// 以前はエンティティ(<c>Models/*.cs</c>)・入力用 ViewModel(<c>Models/ViewModels/*.cs</c>)・
/// 生文字列を受け取る POST アクション(<c>IncidentControllerHelpers.ValidateFreeTextLength</c>)の
/// 3 層すべてに <c>500</c> / <c>100</c> が裸の数値で約 40 箇所に散在していた。
/// この状態だと片方の層だけ上限を変更したときに、
///   - ViewModel だけ緩めた場合 → 検証は通るのに保存時に列長超過(SQL Server / PostgreSQL では
///     未捕捉の DbUpdateException = HTTP 500、SQLite では黙って保存される)、
///   - エンティティだけ緩めた場合 → 入力画面が新しい上限を受け付けない、
/// という「気づきにくい層またぎの不整合」が生まれる。定数を 1 箇所に集約して防ぐ
/// (CLAUDE.md §6 定数の一元管理 / マジックナンバーを避ける)。
///
/// 値を変更するときは、エンティティ側の <c>[MaxLength]</c> は DB の列長にも反映されるため、
/// 同一変更セットで EF Core マイグレーションを追加すること(CLAUDE.md §3 の不変条件)。
/// なお <see cref="AuditLog"/> の列長(256 / 64 / 16)は業務入力ではなく監査証跡スキーマ固有の
/// 値のため、ここには含めない。
/// </summary>
public static class FieldLengths
{
    /// <summary>
    /// 自由記述欄の文字数上限。状況・経緯 / 応急対応 / なぜ1〜5 / 根本原因まとめ / 補足メモ /
    /// 対策内容 / 立案根拠メモ / 完了報告 / 有効性評価コメントが共有する。
    /// </summary>
    // 自由記述欄(長文)の上限文字数
    public const int FreeText = 500;

    /// <summary>
    /// 氏名・部署名・分類名といった短い識別用テキストの文字数上限。
    /// </summary>
    // 氏名・部署名など短いテキストの上限文字数
    public const int ShortText = 100;

    /// <summary>
    /// <c>[MaxLength]</c> 用の日本語エラーメッセージ書式。
    /// <c>{0}</c> に <c>[Display(Name = ...)]</c> の表示名、<c>{1}</c> に上限文字数が入る
    /// (<c>MaxLengthAttribute.FormatErrorMessage</c> がこの 2 つを渡す)。
    ///
    /// 書式に上限値を直書きせずプレースホルダに任せるのは、
    ///   (a) 上限を変えたときに文言側の数字だけ古いまま残る事故を防ぐため、
    ///   (b) 既定のエラーメッセージが英語("The field ... maximum length of '500'.")で、
    ///       日本語 UI(CLAUDE.md §1)に英文が混ざるのを防ぐため。
    /// 入力用 ViewModel の <c>[MaxLength]</c> にはこの書式を必ず指定する。
    /// </summary>
    // 文字数超過時に画面へ表示する日本語メッセージの書式
    public const string MaxLengthMessage = "{0}は{1}文字以内で入力してください。";
}
