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
/// なお <see cref="AuditLog"/> の列長は業務入力ではなく監査証跡スキーマ固有の値のため、
/// ここには含めない(具体的な値は <c>AuditLog</c> の各プロパティが持つ。ここへ書き写すと
/// 列を増やしたときにこの説明だけが古くなる —— 実際、以前は 1 列ぶん欠けた列挙になっていた)。
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
    /// <c>HasConversion&lt;string&gt;()</c> で文字列として保存する enum 列の上限。
    /// 保存されるのは enum の名前(<c>Level0</c> / <c>Planned</c> / <c>ShortTerm</c> など)で、
    /// 利用者の入力ではなく閉じた語彙なので <see cref="ShortText"/> とは別の値にしている。
    /// </summary>
    // 文字列として保存する enum 列(重症度 / ステータス / 対策種別)の上限文字数
    public const int EnumCode = 20;

    /// <summary>
    /// 文字列として保存する enum 列のうち、日本語の値を保存するものの上限。
    /// <c>Incident.IncidentType</c> は <c>IncidentTypeMapping</c> が日本語の DB 文字列
    /// (「与薬・投薬」など)へ変換して保存するため、<see cref="EnumCode"/> では足りない。
    /// </summary>
    // 日本語の値を文字列として保存する enum 列(インシデント種別)の上限文字数
    public const int EnumCodeJapanese = 50;

    /// <summary>
    /// バイト長（<c>byte[]</c> の添付など）の上限に使う日本語エラーメッセージ書式。
    /// <c>{0}</c> に <c>[Display(Name = ...)]</c> の表示名、<c>{1}</c> に上限バイト数が入る。
    ///
    /// 文字数用の <see cref="MaxLengthMessage"/> を流用してはいけない。
    /// <c>byte[]</c> の上限に文字数の書式を付けると、画面には
    /// 「添付は100文字以内で入力してください。」という<b>誤った文言</b>が出る
    /// （実際に制限しているのはバイト数）。
    ///
    /// なお<b>上限の「値」も文字数用の定数を流用しない</b>。
    /// <see cref="FreeText"/> / <see cref="ShortText"/> は文字数の上限として定義してあるので、
    /// それでバイト数を表すと単位またぎのずれになる。バイト長の上限を最初に足すときは、
    /// 用途を表す専用の定数（例: 添付ファイルの上限バイト数）をこのクラスへ追加すること
    /// （<c>EveryMaxLength_UsesAFieldLengthsConstant</c> がそう案内する）。<see cref="ItemCountMessage"/> と同じ理由で、
    /// 本番の利用箇所がまだ無くてもここに置く（最初にバイト長の上限を足す人が参照できないと、
    /// 一元管理すべき値がその時点で必ず二重化する）。
    /// </summary>
    // バイト長の上限を伝える日本語メッセージの書式
    public const string ByteLengthMessage = "{0}は{1}バイト以内で入力してください。";

    /// <summary>
    /// コレクション（要素数）の上限に使う日本語エラーメッセージ書式。
    /// <c>{0}</c> に <c>[Display(Name = ...)]</c> の表示名、<c>{1}</c> に上限件数が入る。
    ///
    /// 文字数用の <see cref="MaxLengthMessage"/> を流用してはいけない。
    /// <c>[MaxLength(3)] List&lt;string&gt; Tags</c> に文字数の書式を付けると、
    /// 画面には「タグは3文字以内で入力してください。」という<b>誤った文言</b>が出る
    /// （実際に制限しているのはタグの「件数」）。
    ///
    /// <b>現時点で本番の利用箇所は無い</b>（コレクションに上限を付けた入力欄がまだ無いため）。
    /// それでもテスト側に置かず本番の定数として持つのは、この書式が
    /// <c>NonEntityMaxLength_UsesJapaneseSharedErrorMessage</c> が<b>要求する値</b>だから。
    /// テストの中に隠すと、最初にコレクションの上限を足す人はこの文言を参照できず、
    /// 自分で別の文字列を書くしかなくなる（＝ <see cref="MaxLengthMessage"/> と同じ理由で
    /// 一元管理すべき値が、最初の利用時点で必ず二重化する）。
    /// </summary>
    // 要素数の上限を伝える日本語メッセージの書式
    public const string ItemCountMessage = "{0}は{1}件以内で入力してください。";

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
