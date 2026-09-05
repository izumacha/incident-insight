// 属性(Required / MaxLength など)を使うためのライブラリを取り込む
using System.ComponentModel.DataAnnotations;
// 文字数上限とエラーメッセージ書式の唯一の真実の源(FieldLengths)を使う
using IncidentInsight.Web.Models.Validation;
// enum(重症度・種別など)を使えるようにする
using IncidentInsight.Web.Models.Enums;
// ドロップダウン用の SelectListItem を使えるようにする
using Microsoft.AspNetCore.Mvc.Rendering;
// [BindNever](モデルバインドの対象から外す)を使うために取り込む
using Microsoft.AspNetCore.Mvc.ModelBinding;
// [ValidateNever](入力検証の対象から外す)を使うために取り込む
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

// ViewModel 群の名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.ViewModels;

// インシデント一覧画面のモデル(絞り込み条件とページング情報を持つ)
public class IncidentListViewModel
{
    // 表示対象のインシデント行リスト
    public List<Incident> Incidents { get; set; } = new();
    // 絞り込み後の総件数(ページングの計算に使う)
    public int TotalCount { get; set; }
    // 現在表示中のページ番号(1始まり)
    public int Page { get; set; } = 1;
    // 1ページに表示する件数
    public int PageSize { get; set; } = 20;
    // 総ページ数(総件数÷ページサイズを切り上げ)
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);

    // Filter state
    // フリーワード検索キーワード
    public string? Search { get; set; }
    // 部署フィルタ
    public string? Department { get; set; }
    // インシデント種別フィルタ
    public IncidentTypeKind? IncidentType { get; set; }
    // 重症度フィルタ
    public IncidentSeverity? Severity { get; set; }
    // 発生日 絞り込み(開始日)
    public DateTime? DateFrom { get; set; }
    // 発生日 絞り込み(終了日)
    public DateTime? DateTo { get; set; }
    // 原因分類フィルタ(原因分類IDで絞り込み)
    public int? CauseCategoryId { get; set; }
    // 並び順のうち「利用者が実際に選んだ値」。受け付けない値・未指定は null になる
    // (判定は Models/Validation/IncidentSortOrder.Adopted)。ページャの URL へ引き継ぐのは
    // こちら —— 採用しなかった値を載せると、並びは既定なのにリンクだけが
    // ?sortBy=<受け付けない値> を運び続ける食い違いになる(issue #209)
    public string? SortBy { get; set; }

    // 並び順のうち「実際に適用した値」。未指定・受け付けない値なら既定(最新順)が入る
    // (判定は Models/Validation/IncidentSortOrder.Effective)。ドロップダウンの現在値は
    // こちらで示す。
    //
    // 上の SortBy と必ず対で設定する。2 つに分けているのは答える問いが違うため ——
    // SortBy は「URL に残すか」(選んでいなければ残さない)、こちらは「どう並べたか」
    // (必ず 1 つに決まる)。表示側でこの判定をやり直さないこと: 並び替えを決めたのは
    // コントローラなので、ビューが別の判定を書くと「メニューは A を指しているのに
    // 並びは B」という食い違いが生まれる(選択肢を ViewModel から取る他の
    // ドロップダウンと同じ考え方)
    public string EffectiveSortOrder { get; set; } = IncidentSortOrder.Latest;

    // 原因分類ドロップダウンの選択肢。
    // 中身を決めるのは IncidentsController.ResolveCauseCategoryFilterAsync で、
    // 上の CauseCategoryId と必ず対で設定する(片方だけ差し替えると食い違いが戻る)。
    // 選択肢は親カテゴリのみだが、子カテゴリの id で絞り込んでいるときはその 1 件が
    // 「親名 > 子名」の見出しで先頭に補完されている
    // (なぜ補完が要るのかは Models/Validation/SearchFilter の解説が正本。issue #195)。
    //
    // required にして既定値を持たせない理由は下の DepartmentOptions とまったく同じ
    // (そちらの説明が正本)。2 つは対の解決処理(Controllers/Internal の
    // DepartmentFilterResolver / IncidentsController.ResolveCauseCategoryFilterAsync)が
    // 作るので壊れ方も同じで、片方だけコンパイラに
    // 強制させると、新しい構築箇所が DepartmentOptions だけ書いてこちらを忘れたときに
    // 「コンパイルも通りテストも緑のまま、原因分類のドロップダウンが
    // 『原因分類（全て）』だけになって絞り込みが画面から消える」(issue #204 課題 3)
    public required List<SelectListItem> CauseCategoryOptions { get; set; }

    // 原因分類の絞り込み値を受け取ったのに採用しなかったかどうか(true なら画面で知らせる)。
    // 黙って落とさない理由も、値そのものではなく真偽値にしている理由も、
    // 下の DepartmentFilterIgnored と同じ(そちらの説明が正本)
    public bool CauseCategoryFilterIgnored { get; set; }

    // 発生部署ドロップダウンの選択肢。
    // ビューが Incident.Departments を直接回さずこちらを使うのは、許可リストから外れた
    // 過去の部署名で絞り込んでいるときに、その値を選択肢へ補完して渡す必要があるため
    // (なぜ補完が要るのかは Models/Validation/SearchFilter の解説が正本。issue #192)。
    // 中身を決めるのは Controllers/Internal/DepartmentFilterResolver で、
    // 上の Department と必ず対で設定する(片方だけ差し替えると食い違いが戻る)。
    //
    // required にして既定値を持たせないのは、設定し忘れを実行時ではなくコンパイル時に
    // 落とすため。空リストを既定にすると、この ViewModel を組み立てる経路が増えたときに
    // 部署の絞り込みが「部署（全て）」だけの空のドロップダウンになり、例外もテストの
    // 失敗も出ないまま画面から機能が消える。以前はビュー側が Incident.Departments を
    // 直接回していたので設定漏れという状態が存在しなかったが、出所を呼び出し側へ
    // 移した以上その穴は新しく作ったものなので、同じ変更でふさいでおく
    public required List<string> DepartmentOptions { get; set; }

    // 部署の絞り込み値を受け取ったのに採用しなかったかどうか(true なら画面で知らせる)。
    //
    // なぜ黙って落とさないのか(採用しない条件がデータ側の状態に依存すること、黙ると
    // どう取り違えられるか)は Models/Validation/SearchFilter の解説が正本。
    //
    // 値そのものではなく真偽値なのは、送った値を画面へ出し戻すのをやめたため。
    // 一度は出していたが、外部由来の文字列をアプリ自身の文章へ埋め込むと、長さ・
    // 結合文字・不可視文字・双方向の上書きの手当てが次々に要り、しかも整形するほど
    // 「表示した文字列」と「実際に照会した文字列」が食い違って事実と逆の案内になる
    // (「ICU は 1 件も無い」等)。送った値はブラウザのアドレス欄に出ており、
    // この注意書きが出るときは絞り込みパネルも開くので、選び直す導線はそちらで足りる。
    public bool DepartmentFilterIgnored { get; set; }

    // 型として読み取れない絞り込み値を受け取ったので採用しなかったかどうか
    // (true なら画面で知らせる。issue #198)。
    //
    // 上の 2 つと違い入力ごとに分かれていないのは、採用しなかった理由が
    // 対象の 5 つ(incidentType / severity / dateFrom / dateTo / causeCategoryId)で
    // 同一だから ——「その型の値として読めない」。分ければ同じ文章が 5 つ並び、
    // どれか 1 つを直したときに他の 4 つが取り残される。
    // 判定と理由の正本は Controllers/Internal/MalformedFilterValueResolver の解説。
    //
    // 値そのものではなく真偽値なのも、黙って落とさない理由も、上の 2 つと同じ
    public bool MalformedFilterIgnored { get; set; }
}

/// <summary>
/// 「絞り込み値を受け取ったのに採用しなかった」注意書き 1 件分の文面。
/// 一覧ビューの共有パーシャル <c>Views/Incidents/_FilterIgnoredNotice.cshtml</c> のモデル。
/// </summary>
/// <remarks>
/// <para><b>なぜ型を作るのか。</b> 注意書きは旗ごとに出る(発生部署・原因分類・読めない値)が、
/// 見た目(警告の枠・アイコン・<c>role="alert"</c>・アイコンを支援技術から隠す指定)は
/// どれも完全に同じで<b>文面だけが違う</b>。マークアップを呼び出し側へ書き写すと、
/// a11y の指定を直すときに 1 つが取り残される(§6 DRY / §7)。
/// 件数をここに書かないのは、旗を足すたびにこの数字だけが古くなるため。
/// 文面だけをこの型で渡し、枠はパーシャル 1 か所が持つ。</para>
///
/// <para><b>受け取った値そのものは入れない。</b> 外部由来の文字列をアプリ自身の文章へ
/// 埋め込まない方針は既存の注意書きと同じ(理由の正本は
/// <see cref="IncidentListViewModel.DepartmentFilterIgnored"/> の解説)。
/// この型に載るのは<b>コード側で決めた定型文</b>だけ。</para>
/// </remarks>
/// <param name="Heading">太字で出す見出し(「〜の絞り込みは適用していません。」)。</param>
/// <param name="Detail">見出しに続けて出す説明文(採用しなかった理由と、選び直す導線の案内)。</param>
public record FilterIgnoredNotice(string Heading, string Detail);

// インシデント詳細画面のモデル
public class IncidentDetailViewModel
{
    // 表示対象のインシデント本体
    public Incident Incident { get; set; } = null!;
    // 再発検知で見つかった類似インシデントのリスト
    public List<Incident> SimilarIncidents { get; set; } = new();
    // 再発警告を表示すべきか(類似が1件以上あれば true)
    public bool HasRecurrenceWarning => SimilarIncidents.Any();

    // For inline cause analysis form
    // 詳細画面から直接追加する「なぜなぜ分析」のフォーム用モデル
    public CauseAnalysisFormViewModel NewCauseAnalysis { get; set; } = new();
    // なぜなぜ分析フォーム用の原因分類ドロップダウン選択肢。
    // required にして既定値を持たせない理由は IncidentListViewModel.DepartmentOptions と同じ
    // (そちらの説明が正本)。空リストを既定にすると、この ViewModel を組み立てる経路が
    // 増えたときに設定漏れがコンパイルもテストも緑のまま素通りし、詳細画面の
    // 「なぜなぜ分析を追加」フォームから原因分類が選べなくなる(＝分析を登録できない)。
    // この型はモデルバインドされない(詳細アクションは id を受けるだけ)ので、
    // 入力用 ViewModel が必要とする [BindNever] / [ValidateNever] は要らない
    public required List<SelectListItem> CauseCategoryOptions { get; set; }

    // For inline measure form
    // 詳細画面から直接追加する「再発防止策」のフォーム用モデル
    public MeasureFormViewModel NewMeasure { get; set; } = new();
}

// インシデント登録/編集ウィザード用のモデル
public class IncidentCreateEditViewModel
{
    // ID(新規=0、編集時=既存ID)
    public int Id { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    // hidden field でクライアントに渡して POST 時に戻ってきたものを OriginalValue に設定する。
    public Guid ConcurrencyToken { get; set; }

    // 発生日時。必須。初期値は Get アクションで IClock.Now を代入する(ここでは null)。
    // ViewModel の既定値に DateTime.Now を使うと IClock 規約違反になり、
    // テストで時刻制御ができなくなるため、コントローラ側で設定する方式に統一する。
    // 型を nullable(DateTime?)にしているのは [Required] を実際に機能させるため:
    // 非 nullable の DateTime だと未送信時に 0001-01-01 が黙って束縛され
    // [Required] は「null かどうか」しか見ないため検証をすり抜けてしまう。
    [Required(ErrorMessage = "発生日時は必須です")]
    [Display(Name = "発生日時")]
    public DateTime? OccurredAt { get; set; }

    // 発生部署。必須で上限は FieldLengths.ShortText
    [Required(ErrorMessage = "部署は必須です")]
    [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "発生部署")]
    public string Department { get; set; } = "";

    // 発生部署ドロップダウンに並べる選択肢。
    // ビューが Incident.Departments を直接回さずこちらを使うのは、許可リストから外された
    // 部署名を持つ既存インシデントを編集するとき、その 1 件だけを選択肢へ足す必要があるため
    // (規則と理由は IncidentsController.ResolveDepartmentSaveSelection の解説が正本。issue #196)。
    // 中身を決めるのは同メソッドで、保存を通す例外(Grandfathered)と必ず対で決まる
    // ——片方だけ差し替えると「画面では選べるのに保存で弾かれる」食い違いが戻る。
    //
    // required にして既定値を持たせない理由は IncidentListViewModel.DepartmentOptions と同じ
    // (設定し忘れを実行時ではなくコンパイル時に落とす)。ただし守備範囲はあちらより狭い:
    // この ViewModel は POST のモデルバインド経由でも作られ、その経路は Activator による
    // 生成なので required の検査が掛からず、DepartmentOptions は null のまま届く。
    // つまりコンパイラが守るのは GET 側の組み立てだけで、POST の再描画で設定し忘れると
    // ビューの foreach が NullReferenceException(HTTP 500)になる。空リストを既定にすると
    // 同じ設定漏れが「例外もテストの失敗も出ないまま部署の選択肢が消える」という
    // 気付けない壊れ方になるので、あえて既定値を置かず大きな音で落ちる側を選んでいる
    // (再描画の 2 経路は UnlistedDepartmentSavePolicyTests が固定する)。
    //
    // [BindNever] / [ValidateNever] が必須(実測)。この 2 つが無いと Create / Edit の
    // POST がすべて失敗する ——プロジェクトは <Nullable>enable</Nullable> なので、MVC は
    // 非 null 許容の参照型プロパティに [Required] を自動で足す
    // (MvcOptions.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes は既定の false)。
    // フォームは選択肢を送らないため、モデルバインド後この値は null のまま
    // ——初期値を持つ CauseCategoryOptions と違い required は初期値を置かないので、
    // 自動で足された [Required] が必ず落ちる。実測では ModelState に
    // 「The DepartmentOptions field is required.」(日本語 UI に英語の既定メッセージ)が積まれ、
    // ModelState.IsValid が常に false になって<b>インシデントを 1 件も登録・編集できなくなる</b>。
    // しかも対応する入力欄が画面に無いので、利用者には直しようがない。
    // コントローラ級のテストは ModelState を手で組み立てるためこの経路を通らず、全件緑のまま通る
    // (FormViewModelBindingMetadataTests が実際のモデルメタデータを見て固定する)。
    // [BindNever] は併せて overposting も塞ぐ(利用者が選択肢を送り込めないようにする)。
    [BindNever]
    [ValidateNever]
    public required List<string> DepartmentOptions { get; set; }

    // インシデント種別。必須で初期値「その他」
    // EnumDataType: モデルバインドは未定義の整数(例:99以外の未使用値)もそのまま
    // (IncidentTypeKind)値 として束縛してしまうため、Enum.IsDefined 相当の検証を追加し、
    // フォーム改ざんで未定義値が保存されるのを防ぐ(UpdateStatus の fail-closed 方針と同じ考え方)
    // 型を nullable にしているのは OccurredAt / DueDate と同じ理由で [Required] を
    // 実際に機能させるため: 非 nullable の enum だと未送信時に既定値(Other)が
    // 黙って束縛され、種別を選ばないままの登録が検証をすり抜けてしまう。
    // 画面の初期選択値は Create GET アクション側で設定する
    [Required(ErrorMessage = "インシデント種別は必須です")]
    [EnumDataType(typeof(IncidentTypeKind), ErrorMessage = "インシデント種別の値が不正です")]
    [Display(Name = "インシデント種別")]
    public IncidentTypeKind? IncidentType { get; set; }

    // 重症度。必須(初期選択値は Create GET アクション側で「レベル0」を設定)
    // EnumDataType: IncidentType と同じ理由で未定義値の束縛を拒否する。
    // nullable なのも同じ理由: 非 nullable だと未送信時に Level0(影響なし)が
    // 黙って束縛され、医療インシデントの重症度が誰も選んでいない値で保存されてしまう
    [Required(ErrorMessage = "重症度は必須です")]
    [EnumDataType(typeof(IncidentSeverity), ErrorMessage = "重症度の値が不正です")]
    [Display(Name = "重症度")]
    public IncidentSeverity? Severity { get; set; }

    // 状況・経緯の記述(必須)。他の自由記述欄(Why1-5/AnalysisNote等)と同じ自由記述上限(FieldLengths.FreeText)を
    // 明示検証する。EF Core は保存時に DataAnnotations を自動検証しないため、MaxLength を
    // 付けないと ModelState.IsValid が無制限の自由記述を素通りさせてしまう(§9 入力は信用しない)。
    [Required(ErrorMessage = "状況・経緯を入力してください")]
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "状況・経緯")]
    public string Description { get; set; } = "";

    // 発生直後の応急対応(省略可)。他の自由記述欄と同じ自由記述上限(FieldLengths.FreeText)を明示検証する(理由は上記 Description と同じ)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "発生直後の対応")]
    public string? ImmediateActions { get; set; }

    // 報告者の名前。必須で上限は FieldLengths.ShortText
    [Required(ErrorMessage = "報告者名は必須です")]
    [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "報告者")]
    public string ReporterName { get; set; } = "";

    // Tab 2: Cause Analysis
    // ウィザードのなぜなぜ分析タブ用モデル
    public CauseAnalysisFormViewModel CauseAnalysis { get; set; } = new();
    // 原因分類のドロップダウン選択肢。
    // 上の DepartmentOptions と同じ理由で、モデルバインドと入力検証の両方から外す
    // ——こちらは初期値(= new())があるおかげで自動で足された [Required] を今は通せているが、
    // 初期値を外した瞬間に同じ「全 POST が失敗する」状態になる。役割が同じプロパティの
    // 片方だけ守ると、その差が次の人には読み取れない(検出網も分類ごとに穴が空く)
    [BindNever]
    [ValidateNever]
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    // Tab 3: Preventive Measures (at least one required)
    // 再発防止策リスト(最低1件は必須)。初期値として空の対策フォームを1件入れておく
    public List<MeasureFormViewModel> Measures { get; set; } = new() { new MeasureFormViewModel() };
}

// なぜなぜ分析フォーム用のモデル
public class CauseAnalysisFormViewModel
{
    // 分析ID(新規=0)
    public int Id { get; set; }
    // 対応するインシデントID
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    // 原因分類。必須で画面から選択する。
    // 注: 非 null 型の int に [Required] を付けても検証は常に成功する(int は null になり得ない)ため、
    //     未選択(=0)を弾く目的では機能しない。[Range] で 1 以上を要求することで、
    //     CauseCategoryId=0 のまま INSERT され FK 違反(未捕捉 DbUpdateException = HTTP 500)になる事故を防ぐ。
    [Range(1, int.MaxValue, ErrorMessage = "原因分類を選択してください")]
    [Display(Name = "原因分類")]
    public int CauseCategoryId { get; set; }

    // なぜ1。必須入力で上限は FieldLengths.FreeText
    [Required(ErrorMessage = "なぜ1を入力してください")]
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "なぜ1（何が起きたか・直接原因）")]
    public string Why1 { get; set; } = "";

    // なぜ2(任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "なぜ2")]
    public string? Why2 { get; set; }

    // なぜ3(任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "なぜ3")]
    public string? Why3 { get; set; }

    // なぜ4(任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "なぜ4")]
    public string? Why4 { get; set; }

    // なぜ5(根本原因、任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "なぜ5（根本原因）")]
    public string? Why5 { get; set; }

    // 根本原因まとめ(任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "根本原因まとめ")]
    public string? RootCauseSummary { get; set; }

    // 分析者の名前(任意)
    [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "分析者")]
    public string? AnalystName { get; set; }

    // 補足メモ(任意)。他の自由記述欄(Why1-5/RootCauseSummary等)と同じ自由記述上限(FieldLengths.FreeText)を明示検証する。
    // EF Core は保存時に DataAnnotations を自動検証しないため、MaxLength を付けないと
    // ModelState.IsValid が無制限の自由記述を素通りさせてしまう(§9 入力は信用しない)。
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "補足メモ")]
    public string? AdditionalNotes { get; set; }

    // 原因分類ドロップダウンの選択肢。
    // この ViewModel も POST でモデルバインドされる(登録ウィザードの入れ子と
    // CauseAnalysesController の単独 POST の両方)ので、DepartmentOptions と同じ理由で
    // モデルバインドと入力検証の対象から外す
    [BindNever]
    [ValidateNever]
    public List<SelectListItem> CauseCategoryOptions { get; set; } = new();

    /// <summary>
    /// 保存に必要な最小の組(原因分類の選択 + なぜ1 の入力)が揃っているか。
    /// IncidentsController.Create は分析タブを任意入力として扱うため、この条件を
    /// 満たすときだけ CauseAnalysis を保存する。判定をコントローラに直書きすると
    /// 複数箇所で定義がずれていくため、ViewModel 側に一元化する(§6 DRY)。
    /// </summary>
    // 原因分類が選択され、かつ なぜ1 が入力されていれば保存可能
    public bool IsSavable =>
        CauseCategoryId > 0 && !string.IsNullOrWhiteSpace(Why1);

    /// <summary>
    /// 分析タブのいずれかの欄に入力があるか(すべて空なら「分析なし」の正常系)。
    /// IsSavable が false なのに true の場合は「部分入力」であり、黙って破棄すると
    /// 利用者が気づかないデータ消失になるため、Create はこの組み合わせを入力不備として扱う。
    /// フィールドを追加したら必ずここにも足すこと(足し忘れると新フィールドの入力が
    /// 「入力なし」扱いになり、無言破棄バグが再発する)。
    /// </summary>
    // いずれかの入力欄に値があるかを判定する
    public bool HasAnyInput =>
        CauseCategoryId > 0
        || !string.IsNullOrWhiteSpace(Why1)
        || !string.IsNullOrWhiteSpace(Why2)
        || !string.IsNullOrWhiteSpace(Why3)
        || !string.IsNullOrWhiteSpace(Why4)
        || !string.IsNullOrWhiteSpace(Why5)
        || !string.IsNullOrWhiteSpace(RootCauseSummary)
        || !string.IsNullOrWhiteSpace(AnalystName)
        || !string.IsNullOrWhiteSpace(AdditionalNotes);
}

// 再発防止策フォーム用のモデル
public class MeasureFormViewModel
{
    // 対策ID(新規=0)
    public int Id { get; set; }
    // 対応するインシデントID
    public int IncidentId { get; set; }

    // 楽観的同時実行制御トークン(Edit 時のみ意味を持つ)。
    public Guid ConcurrencyToken { get; set; }

    // 対策内容(必須で上限は FieldLengths.FreeText)
    [Required(ErrorMessage = "対策内容を入力してください")]
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "対策内容")]
    public string Description { get; set; } = "";

    // 対策種別(短期/長期、必須)
    // EnumDataType: フォーム改ざんで未定義の整数値が束縛されるのを拒否する
    // (IncidentCreateEditViewModel.IncidentType/Severity と同じ理由)。
    // nullable なのは [Required] を機能させるため(非 nullable だと未送信時に
    // ShortTerm が黙って束縛される)。初期選択値はフォームを組み立てる側で設定する
    [Required(ErrorMessage = "対策種別を選択してください")]
    [EnumDataType(typeof(MeasureTypeKind), ErrorMessage = "対策種別の値が不正です")]
    [Display(Name = "対策種別")]
    public MeasureTypeKind? MeasureType { get; set; }

    // 担当者(必須で上限は FieldLengths.ShortText)
    [Required(ErrorMessage = "担当者を入力してください")]
    [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "担当者")]
    public string ResponsiblePerson { get; set; } = "";

    // 担当部署(必須で上限は FieldLengths.ShortText)
    [Required(ErrorMessage = "担当部署を入力してください")]
    [MaxLength(FieldLengths.ShortText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "担当部署")]
    public string ResponsibleDepartment { get; set; } = "";

    // 実施期限(必須)。初期値はコントローラ側で IClock を使って設定する。
    // DateTime.Now.AddDays(30) をここに書くと IClock 規約違反になるため削除した。
    // 型を nullable(DateTime?)にしているのは [Required] を実際に機能させるため:
    // 非 nullable の DateTime だと未送信時に 0001-01-01 が黙って束縛され
    // [Required] は「null かどうか」しか見ないため検証をすり抜け、
    // 「期限超過 約74万日」の不正データが保存できてしまう。
    [Required(ErrorMessage = "実施期限を入力してください")]
    [Display(Name = "実施期限")]
    public DateTime? DueDate { get; set; }

    // 優先度(1=高/2=中/3=低、初期値は中)
    // EF Core は保存時に DataAnnotations を自動検証しないため、AddMeasure /
    // PreventiveMeasuresController.Create / Edit の3経路をすり抜けないよう、
    // ドメインモデル PreventiveMeasure.Priority と同じ範囲をここでも明示検証する。
    // 範囲・既定値・文言はいずれも MeasurePriorityScale(尺度の唯一の源)から引くため、
    // 段階を増やしてもこの ViewModel とドメインモデルの検証が食い違わない(§6)
    [Range(MeasurePriorityScale.Min, MeasurePriorityScale.Max,
        ErrorMessage = MeasurePriorityScale.RangeMessage)]
    [Display(Name = MeasurePriorityScale.DisplayName)]
    public int Priority { get; set; } = MeasurePriorityScale.Default;

    // 立案根拠・背景メモ(任意)
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "立案根拠・背景メモ")]
    public string? AnalysisNote { get; set; }
}

// 対策の有効性レビュー画面のモデル
public class ReviewViewModel
{
    // 対象対策のID
    public int Id { get; set; }

    // 楽観的同時実行制御トークン。
    public Guid ConcurrencyToken { get; set; }

    // 有効性評価(1〜5、必須)。段階数・表示名・エラーメッセージは
    // EffectivenessScale(尺度の唯一の源)から引き、画面ごとの食い違いを防ぐ(§6)
    [Required]
    [Range(EffectivenessScale.Min, EffectivenessScale.Max, ErrorMessage = EffectivenessScale.RangeMessage)]
    [Display(Name = EffectivenessScale.DisplayName)]
    public int EffectivenessRating { get; set; }

    // 有効性評価のコメント(任意)。他の自由記述欄(Description/AnalysisNote 等)と同じ
    // 自由記述上限(FieldLengths.FreeText)を明示検証する。EF Core は保存時に DataAnnotations を自動検証しないため、
    // ここが唯一の防波堤になる(未検証だと無制限の自由記述が保存されうる)。
    [MaxLength(FieldLengths.FreeText, ErrorMessage = FieldLengths.MaxLengthMessage)]
    [Display(Name = "有効性評価コメント")]
    public string? EffectivenessNote { get; set; }

    // 対策後の再発有無(必須)。非nullable boolだと既定値falseが常に入り [Required] が
    // 何も検証しない死んだ属性になる(未選択でも「再発なし」を暗黙に確定してしまう)ため、
    // 未選択状態を表現できる bool? にして [Required] を実効化する。
    [Required(ErrorMessage = "再発の有無を選択してください")]
    [Display(Name = "対策実施後に再発を確認したか")]
    public bool? RecurrenceObserved { get; set; }
}
