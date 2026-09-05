// [NotNullWhen] 属性(戻り値が true のとき引数が非 null であることをコンパイラへ伝える)を使う
using System.Diagnostics.CodeAnalysis;

// この型が属する名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Models.Validation;

/// <summary>
/// 一覧・集計画面の絞り込み入力について「値が入っているか」を判定する唯一の真実の源
/// (single source of truth)。<c>?search=</c> のようなクエリ文字列から届く
/// <see cref="string"/> の絞り込み条件は、一覧でも集計(グラフ用 JSON)でも、
/// すべてこの判定を通してから使う。利用側はここに書き並べない
/// (参照を辿れば分かるので、写しを持つと一覧の方が先に古くなる)。
///
/// <para><b>規則。</b> <c>null</c> / 空文字 / <b>空白のみ</b>の入力は「絞り込み無し」として扱う
/// (＝<see cref="HasValue"/> は <c>false</c> を返す)。空白のみを「入力あり」と数えないのは、
/// 利用者にとって空欄と見分けが付かないため。末尾スペースごとの貼り付け・IME の誤入力・
/// ブラウザのオートフィルで容易に発生する。</para>
///
/// <para><b>なぜ 1 か所に集めるのか(issue #187)。</b> 以前はこの判定が画面ごとに書かれ、
/// フリーワード検索を持つ 3 画面のうち <c>/PreventiveMeasures</c>(カンバン)だけが
/// <c>string.IsNullOrEmpty</c> を使っていた。そのため空白のみの入力に対して
/// <c>/Incidents</c> と <c>/AuditLogs</c> は「絞り込み無し」として全件を返すのに、
/// カンバンだけは絞り込みが<b>実際に走り</b>、
/// <c>ResponsiblePerson.ToUpper().Contains(&quot; &quot;)</c> がこのアプリの日本語の氏名・部署名に
/// まず一致しないため<b>盤面が空になっていた</b>。利用者からは原因が分からないまま
/// データが消えたように見える(CLAUDE.md §6 定数・規則の一元管理)。</para>
///
/// <para><b>絞り込みの適用側と「絞り込み中」の表示側で必ず同じ判定を使う。</b>
/// 一覧画面には、絞り込みが効いているかどうかで表示を変える箇所がある
/// (カンバンの <c>ViewBag.HasActiveFilter</c>＝0 件時の文言の出し分け、
/// <c>/Incidents</c> と <c>/AuditLogs</c> の絞り込みパネルを開いた状態にするかどうか)。
/// 片方だけ判定を変えると、<b>空白のみの入力で「絞り込み中」と表示しながら全件を返す</b>
/// (またはその逆の)食い違いが生まれる。両方をこの関数に通しておけば、規則を変えるときも
/// ここ 1 か所で揃う。</para>
///
/// <para><b>入力値そのものは加工しない。</b> この型が答えるのは「絞り込むかどうか」だけで、
/// 前後の空白を取り除いたりはしない。<c>&quot;田中 &quot;</c>(末尾スペース付き)のような
/// 入力は今までどおりそのまま検索語として使われる。トリミングは検索の一致範囲を変える
/// 別の判断なので、必要になったときに独立した変更として決めること。
/// 検索語の大文字化(ロケール非依存の正規化)は
/// <c>Controllers.Internal.IncidentControllerHelpers.NormalizeSearchKeyword</c> が担当する
/// ——こちらは EF Core のクエリを組み立てる経路でしか使わないためコントローラ側に置いてある。</para>
///
/// <para><b>ドロップダウンが表せない適用値をどう扱うか(issue #192)。</b>
/// <see cref="HasValue"/> は「入力があるか」しか答えない。その先に
/// 「<b>適用中の値が選択肢のどれにも一致しない</b>とき、絞り込みを維持するか捨てるか」
/// という別の判断があり、これを画面ごとに決め打ちすると三者三様になる(実際そうなっていた)。
/// 一致する <c>&lt;option&gt;</c> が無いと、ブラウザは <c>&lt;select&gt;</c> を先頭の
/// 「(全て)」の位置に置く。絞り込みは効いたままなので<b>画面と実状態が食い違い</b>、
/// 利用者がそのフォームを再送信した時点で<b>意図せず絞り込みが解除される</b>。
/// 逃げ道は 2 つしかなく、どちらを採るかは<b>値の集合の性質</b>で決まる:</para>
///
/// <list type="bullet">
///   <item><description><b>補完する</b>(適用値を選択肢の先頭へ足す)…
///     選択肢が<b>実データから作られる</b>、または<b>過去の行が現在の許可リストに無い値を持ちうる</b>場合。
///     捨てると「実在するデータへ絞り込めない」損失が出るため、到達性を優先する。</description></item>
///   <item><description><b>採用しない</b>(絞り込みを掛けず、画面へも値を返さない)…
///     値の集合が<b>コード側で閉じていて過去の行も必ずその中に収まる</b>場合。
///     リスト外は不正入力・古いブックマークなので、絞り込み無しの状態で揃える。</description></item>
/// </list>
///
/// <para><b>現在の割り当てと理由。</b></para>
/// <list type="table">
///   <item><description><c>/PreventiveMeasures</c> の担当部署 … <b>補完</b>。
///     <c>ResponsibleDepartment</c> は<b>自由記述</b>で許可リストが存在せず、選択肢は実データから
///     件数上限付きで作るため、上限超過で切り捨てられた値も表せない。補完しか採れない。</description></item>
///   <item><description><c>/AuditLogs</c> のエンティティ名・操作種別 … <b>採用しない</b>。
///     どちらも <c>AuditSaveChangesInterceptor.AuditedEntities</c> / 操作種別という
///     <b>コード側で閉じた集合</b>で、過去行が持つ値も必ずその中にある。</description></item>
///   <item><description><c>/Incidents</c> の発生部署 … <b>実データにあれば補完、無ければ採用しない</b>。
///     <c>Incident.Departments</c> は閉じた語彙だが CLAUDE.md が「値追加は static 配列を更新」と
///     明記する<b>可変の真実の源</b>で、部署名を入れ替えても<b>過去の行は古い部署名を保持し続ける</b>。
///     一律に捨てると実在の部署で業務データを絞り込めなくなり、一律に補完すると
///     打ち間違い・改ざんで<b>存在しない部署が選択肢に現れる</b>。そこで
///     <c>Controllers.Internal.DepartmentFilterResolver</c>(<c>/Analytics</c> と共有)が
///     <b>部署スコープ内の実データに存在するか</b>で 2 つの方式を振り分ける
///     (スコープを掛けるのは、Staff が他部署の部署名の有無を推測できないようにするため)。</description></item>
///   <item><description><c>/Analytics</c> の発生部署 … <b>実データにあれば採用、無ければ採用しない</b>。
///     判定は <c>/Incidents</c> の発生部署と<b>同じ共有処理</b>
///     (<c>Controllers.Internal.DepartmentFilterResolver</c>)を通す ——
///     同じ <c>?department=</c> で画面ごとに答えが違うと、実在しない部署名を指す URL が
///     一覧では「適用していません」と言い、集計では<b>全 0 のグラフ</b>を返す。
///     0 件と「そんな部署は無い」を区別できないのは医療インシデントの集計では誤読が重い
///     (issue #204 課題 4)。この画面は部署のドロップダウンを持たないので補完した選択肢の
///     使い道は無いが、それでも同じ処理を通すのは 2 つの判定が分かれないようにするため。</description></item>
///   <item><description><c>/Incidents</c> のインシデント種別・重症度 … <b>採用しない</b>。
///     どちらも <c>IncidentTypeKind</c> / <c>IncidentSeverity</c> という<b>コード側で閉じた集合</b>で、
///     過去行が持つ値も(保存側が <c>[EnumDataType]</c> で未定義値を弾いているため)必ずその中にある。
///     <c>/AuditLogs</c> の 2 つと同じ形。判定の正本は
///     <c>Controllers.Internal.UnlistedEnumFilterResolver</c>(下の enum の段落を参照。issue #208)。</description></item>
///   <item><description><c>/Incidents</c> の原因分類 … <b>マスタにあれば補完、無ければ採用しない</b>。
///     選択肢は<b>実データ(原因分類マスタ)から</b>作るうえ、絞り込みが受け付ける値は
///     その表示用の部分集合より広い —— ドロップダウンは<b>親カテゴリだけ</b>で作るのに、
///     「親を選ぶと子も拾う」仕様の裏返しで<b>子カテゴリの id も効く</b>ため。
///     一律に捨てると「子カテゴリで絞り込む」経路そのものが失われ、一律に補完すると
///     打ち間違い・URL 改ざんの id が選択肢に現れる。そこで
///     <c>IncidentsController.ResolveCauseCategoryFilterAsync</c>(private)が
///     <b>原因分類マスタに実在するか</b>で振り分け、子カテゴリは
///     「親名 &gt; 子名」の見出しで先頭へ補完する(裸の子名だと親と対等の分類に見えるため)。
///     <b>ここだけ実在確認にスコープを掛けない</b>のは、照会先が業務データではなく
///     <b>マスタ</b>で、<c>BuildCauseCategoryOptionsAsync</c> が登録・詳細画面で全ロールへ
///     子カテゴリまで並べている＝隠せていない情報だから。掛けても防御にならず、
///     自部署にまだ 1 件も無い分類で絞り込めなくなる実害だけが残る。</description></item>
/// </list>
///
/// <para><b>「採用しない」ときは黙って落とさない(<c>/Incidents</c> と <c>/Analytics</c>)。</b>
/// 入力を受け取ったのに絞り込まなかった場合、<c>/Incidents</c> は画面に注意書きを出す
/// (<see cref="ViewModels.IncidentListViewModel.DepartmentFilterIgnored"/> /
/// <see cref="ViewModels.IncidentListViewModel.CauseCategoryFilterIgnored"/>)。黙って落とすと、絞り込んだ
/// つもりの利用者に<b>全件</b>が返り、しかも「絞り込み中」バッジも出ないので取り違えに
/// 気付けない(0 件になるならまだ分かる)。<c>/AuditLogs</c> に同じ手当てが要らないのは
/// <b>判定の元が違う</b>から —— あちらの許可リストはコード側で決まっていて、利用者の
/// 操作やデータの増減では変わらない(外れる値は古いブックマークか改ざんだけ)。
/// <c>/Incidents</c> の 2 つの条件はどちらも<b>実データの有無</b>なので、正しく
/// ブックマークした URL でも<b>勝手に切り替わる</b>——部署は該当インシデントが
/// 削除・修正された時点で、原因分類はその分類がマスタから消えた時点で。
/// 利用者が何もしていないのに結果が変わる側だけ、変わったことを伝える。
/// <c>/Analytics</c> も同じ理由で伝えるが、伝え方は画面ではなく<b>JSON の
/// <c>departmentFilterIgnored</c></b>(この画面にはまだ部署の絞り込み UI が無く、
/// 読み手は JSON の利用側になるため。詳細は <c>AnalyticsController</c> の解説)。</para>
///
/// <para><b>自由記述のテキスト絞り込みには「補完 / 採用しない」の 2 択が要らない。</b>
/// 上の表が答えるのは「<b>ドロップダウンが表せない</b>値をどうするか」なので、
/// 選択肢を持たない入力欄(<c>/Incidents</c> のフリーワード、<c>/AuditLogs</c> の
/// 変更者・対象キー、<c>/PreventiveMeasures</c> の担当者)は対象外。
/// ただし<b>「採用しなかった値を画面へ返さない」だけは同じく守る</b> ——
/// 空白のみの入力を画面へ echo すると、絞り込みは効いていないのに
/// <c>&lt;input&gt;</c> に見えない値が残り、ページャのリンクがすべてその値を運ぶ。
/// 判定は <see cref="Adopted"/> の 1 か所に集約してある(issue #204 課題 2)。</para>
///
/// <para>この表は文章なので放っておけば実装から離れる。各画面の実際の挙動は
/// <c>Controllers.UnlistedFilterValuePolicyTests</c> が 1 ファイルにまとめて固定しており、
/// どれかの画面が表と違う振る舞いに変われば落ちる。<b>方式を変えるときは表とそのテストを
/// 同じ変更セットで直す。</b>(画面数をここに書かないのは、足すたびにこの数字だけが
/// 古くなるため —— 実際 <c>/Analytics</c> は「3 画面」と書いてあった頃に表から漏れていた。)</para>
///
/// <para><b>表に載せ忘れること自体も機械で落とす。</b> 表が「絞り込み入力の唯一の真実の源」を
/// 名乗る以上、<b>表に載っていない画面が同じ入力を受けている</b>ことが穴になる
/// ——その画面は表からも、表を守る検出網からも同時に外れる(issue #204 課題 4 がその状態だった)。
/// <c>?department=</c> については <c>UnlistedFilterValuePolicyTests</c> の
/// <c>PolicyTable_CoversEveryActionThatAcceptsADepartmentFilter</c> が、
/// 表に載せた一覧と<b>実際にその引数を受けるアクション全体</b>を突き合わせる。</para>
///
/// <para><b>文字列以外の絞り込み入力もこの表に載せる(issue #195)。</b>
/// <c>causeCategoryId</c> は <c>int?</c> なので <see cref="HasValue"/>(<c>string</c> 用)を
/// 通せず、「値が入っているか」は <c>int?</c> 自身の <c>HasValue</c> で判定する。
/// <b>判定の道具が違うだけで、この表が答える問いは同じ</b>——
/// 「入っている値をドロップダウンが表せないとき、絞り込みを維持するか捨てるか」。
/// 型で表を分けないこと(分けると、同じ壊れ方が 2 つの表に散る)。
/// 空白のみを弾く必要があるのは文字列だけなので、<see cref="HasValue"/> を
/// <c>int?</c> まで受けるように広げてもいない。</para>
///
/// <para><b>型として解釈できない入力も「受け取った」と数える(issue #198)。</b>
/// <c>causeCategoryId</c> のような<b>文字列以外</b>の絞り込みは、値がその型として読めなければ
/// MVC のモデルバインドが失敗して <c>null</c> になり、失敗した事実は <c>ModelState</c> にしか残らない。
/// 見なければ <c>?causeCategoryId=abc</c> は「そもそも指定が無かった」と同じ扱いになり、
/// <c>?causeCategoryId=0</c>(実在しない id)なら注意書きが出るのに綴りが数値でないと消える、
/// という一貫性の欠如になる ——<b>利用者から見た結果は同じ</b>(絞り込んだつもりで全件が返る)
/// なので、伝えないままにしてよい理由が無い。そこで <c>/Incidents</c> は
/// <c>Controllers.Internal.MalformedFilterValueResolver</c> で <c>ModelState</c> を見て、
/// 対象の 5 つ(<c>incidentType</c> / <c>severity</c> / <c>dateFrom</c> / <c>dateTo</c> /
/// <c>causeCategoryId</c>)のどれかが読めなかったときも注意書きを出す。</para>
///
/// <para><b>この経路だけ入力ごとに旗を分けない。</b> 上の表が文面を分けているのは
/// <b>採用しなかった理由が入力ごとに違う</b>から(部署は「その部署の行が見える範囲に無い」、
/// 原因分類は「その分類がマスタに無い」)。読めなかった場合の理由は<b>5 つとも同一</b>
/// (「その型の値として読めない」)なので、分ける根拠が無い —— 分ければ同じ文章が 5 つ並び、
/// どれか 1 つを直したときに他の 4 つが取り残される。
/// したがって旗は <see cref="ViewModels.IncidentListViewModel.MalformedFilterIgnored"/> の 1 つ。
/// <b>「どの綴り違いなら知らせるか」が入力ごとにばらけない</b>ことがこの選択の要点で、
/// それはこの表がまさに無くそうとしている三者三様の状態そのものだった
/// (5 つまとめて決める変更として切り出したのもそのため)。</para>
///
/// <para><b>渡し忘れは検出網で塞ぐ。</b> 見張る引数名は呼び出し側が <c>nameof</c> で渡すので、
/// 6 つ目の型付き絞り込みを足した人が渡し忘れると<b>その引数だけが黙って元の壊れ方に戻る</b>。
/// <c>Controllers.UnlistedFilterValuePolicyTests.IncidentsIndex_ReportsAFilterValueThatCannotBeRead</c>
/// が「<c>IncidentsController.Index</c> が受ける <c>Nullable&lt;T&gt;</c> の引数」という
/// <b>独立な手がかり</b>から一覧を導き、1 つずつ実際に注意書きが出ることを確かめる
/// (文字列の引数は対象外 —— <c>string?</c> はどんな入力でも束縛でき、
/// 「読めなかった」という状態が存在しない)。</para>
///
/// <para><b>残っている境界: この手当てが入っているのは <c>/Incidents</c> だけ(issue #207)。</b>
/// 同じ壊れ方は他の画面にもある —— <c>/AuditLogs?dateFrom=abc</c> は監査ログ全件を、
/// <c>/PreventiveMeasures?status=abc</c> はカンバン全件を、
/// <c>/Analytics/MonthlyTrend?dateFrom=abc</c> は<b>期間を絞ったかのような全期間のグラフ</b>を、
/// いずれも注意書きもバッジも無しで返す。上の理屈
/// (「利用者から見た結果は同じなので伝えないままにしてよい理由が無い」)はそのまま当てはまり、
/// <b>いま <c>?dateFrom=</c> は画面ごとに答えが違う</b> ——この表が <c>?department=</c> について
/// 「同じパラメータで画面ごとに答えが違うと誤読が重い」と書いているのと同じ状態。
/// <b>それでも同じ変更で広げていない</b>のは、画面ごとに伝え先が違う(一覧は画面、
/// <c>/Analytics</c> は JSON のキー、カンバンは <c>ViewBag</c>)ため、
/// 旗の持たせ方と検出網の掛け方をまとめて決め直す必要があり、
/// 「1 コミット = 1 論理変更」(CLAUDE.md §12)に収まらないから。
/// <b>解決処理側</b>(<c>MalformedFilterValueResolver.Resolve</c>)は画面に依存しない形
/// (<c>ModelState</c> と名前だけを受ける)にしてあるので、そちらは配線だけで済む
/// ——ただし<b>注意書きの見せ方は別で、そのままでは持ち出せない</b>:
/// パーシャル <c>_FilterIgnoredNotice</c> は <c>Views/Incidents/</c> に置いてあり、
/// Razor のパーシャル解決は <c>/Views/{コントローラ名}/</c> と <c>/Views/Shared/</c> しか
/// 見ないので、他の画面から名前で呼ぶと実行時に見つからない。広げるときは
/// このパーシャル(と <c>FilterIgnoredNotice</c>)を <c>Views/Shared/</c> へ移すこと
/// (<c>_Pager</c> / <c>_ConcurrencyTokenFields</c> がその置き方)。
/// <b>先回りで移していない</b>のは、今の利用者が 1 画面しか無いため
/// ——複数画面で使う前に共有の場所へ置くのは§6 が避けろと書いている
/// 「将来を見越した過度な抽象化」で、しかも <c>/Analytics</c> の伝え先は JSON、
/// カンバンは <c>ViewBag</c> なので、実際に何を共有できるかは広げる時点で決まる。
/// <b>この段落を消すときは、実際に全画面へ広げたときにすること</b>
/// ——消しただけでは、残った画面が表からも検出網からも同時に外れる。</para>
///
/// <para><b>enum の絞り込みは「読めるが定義に無い」値も採用しない(issue #208)。</b>
/// 上の手当てが拾うのは<b>束縛に失敗した</b>値だけだが、enum には
/// <b>束縛に成功するのに定義に無い</b>値がある —— <c>?severity=99</c> は
/// MVC の <c>SimpleTypeModelBinder</c> が <c>EnumConverter</c> 経由で
/// <c>(IncidentSeverity)99</c> へ変換し、<b>エラーを積まない</b>(実測。
/// 変換は通り <c>Enum.IsDefined</c> だけが <c>false</c>)。素通しにすると絞り込みは
/// <b>実際に掛かって 0 件</b>になり、<c>&lt;select&gt;</c> には一致する
/// <c>&lt;option&gt;</c> が無いので「重症度（全て）」の位置に戻る ——
/// <b>この表が守ろうとしている不変条件(「絞り込みに使った値は必ず選択肢にある」)が
/// そのまま破れている</b>状態で、利用者がそのフォームを再送信した時点で
/// 絞り込みが黙って解除される(issue #192 の症状そのもの)。
/// インシデント種別も同じで、そちらの未定義の例は <c>?incidentType=0</c>
/// (<b><c>?incidentType=99</c> ではない</b> —— <c>IncidentTypeKind.Other</c> が
/// <b>99 として定義済み</b>なので、その URL は「その他」で正しく絞り込まれる。
/// issue #208 の本文はここを取り違えているので、再現手順として写さないこと)。</para>
///
/// <para><b>この判定が正しいための前提: 選択肢の出所と定義が一致していること。</b>
/// <c>Enum.IsDefined</c> で採用を決める一方、<c>&lt;select&gt;</c> の選択肢は
/// <c>EnumLabels.AllSeverities</c> / <c>IncidentTypeMapping.AllInDisplayOrder</c> という
/// <b>別の宣言箇所</b>から作る。片方にしかない値が生まれると
/// 「採用されるのに一致する <c>&lt;option&gt;</c> が無い」——つまり上とまったく同じ壊れ方に戻る。
/// とくにインシデント種別の一覧は<b>手で保守する辞書</b>のキーなので、
/// enum へ値を足して辞書を直し忘れるだけで成立する(実測で全件緑のまま通った)。
/// <c>Models.EnumFilterOptionSourceTests</c> がこの一致を固定する。</para>
///
/// <para><b>方式は表の 2 択のうち「採用しない」。</b> enum の値の集合は
/// <b>コード側で閉じていて</b>、DB の過去行も(保存側が <c>[EnumDataType]</c> で
/// 未定義値を弾いているため)必ずその中に収まる ——
/// <c>/AuditLogs</c> のエンティティ名・操作種別とまったく同じ形なので、
/// <b>絞り込みを掛けず、画面へも値を返さない</b>。判定(<c>Enum.IsDefined</c>)と
/// 理由の正本は <c>Controllers.Internal.UnlistedEnumFilterResolver</c> の解説で、
/// <c>/Incidents</c> の種別・重症度の 2 つが通る。
/// これは「読めなかったので採用しない」(上の <c>MalformedFilterValueResolver</c>)とは
/// <b>答えが違う</b>ので、旗も文面も分けてある
/// (<see cref="ViewModels.IncidentListViewModel.UnlistedEnumFilterIgnored"/>。
/// 「値として読み取れない」vs「選べる値ではない」)。逆に<b>種別と重症度で旗を分けない</b>のは
/// その 2 つでは理由が同一だから —— 旗を分ける / まとめるの基準は
/// <b>採用しなかった理由が同じかどうか</b>で、既存の 3 つの旗と共通。</para>
///
/// <para><b>ここは <c>/AuditLogs</c> と同じ「閉じた集合」なのに注意書きを出す。</b>
/// 上の「黙って落とさない」の段落は、<c>/AuditLogs</c> に手当てが要らない理由として
/// 「許可リストがコード側で決まっていて、外れる値は古いブックマークか改ざんだけ」を挙げている。
/// enum も同じ性質だが、<b>この画面では出す方が一貫する</b> ——
/// <c>?severity=abc</c>(読めない値)は<b>まったく同じく</b>ブックマークか改ざんでしか起きないのに
/// 既に注意書きを出しており、しかも<b>利用者から見た 2 つの結果は区別が付かない</b>
/// (どちらも絞り込んだつもりで全件が返る)。同じ画面の同じ入力欄で、綴りが
/// <c>abc</c> なら知らせて <c>99</c> なら黙る、という状態こそ
/// <c>MalformedFilterValueResolver</c> が塞いだ「一貫性の欠如」そのもの。
/// つまり<b>伝えるかどうかを分けているのは画面であって、値の集合の性質ではない</b>
/// (<c>/AuditLogs</c> にはまだ注意書きの仕組みが無い。それが残っている境界＝issue #207)。</para>
///
/// <para><b>渡し忘れは検出網で塞ぐ。</b> 呼び出し側が enum の引数ごとに解決処理を呼ぶ形なので、
/// 3 つ目の enum 絞り込みを足した人が通し忘れると<b>その引数だけが黙って元の壊れ方に戻る</b>。
/// <c>Controllers.UnlistedFilterValuePolicyTests.IncidentsIndex_DropsAnEnumFilterValueOutsideItsDefinition</c>
/// が「<c>IncidentsController.Index</c> が受ける <c>Nullable&lt;TEnum&gt;</c> の引数」という
/// <b>独立な手がかり</b>から一覧を導き、1 つずつ実際に採用されないことを確かめる。
/// <b>手がかりは「読めない値」の検査とは別</b>にしてある ——
/// <c>?severity=99</c> は <c>ModelState</c> にエラーを積まないので、
/// あちらの作り方(エラーを手で積む)では再現しない。</para>
///
/// <para><b>残っている境界: この手当ても <c>/Incidents</c> だけ。</b>
/// <c>/PreventiveMeasures</c> の <c>?status=99</c>(<c>MeasureStatus?</c>)にも同じ穴があり、
/// カンバンが<b>絞り込みの効いた空の盤面</b>になる。広げていない理由は上の issue #207 と同じで、
/// あちらは伝え先が <c>ViewBag</c> なので旗の持たせ方と検出網の掛け方をまとめて決め直す必要がある
/// (「1 コミット = 1 論理変更」CLAUDE.md §12)。<b>解決処理側</b>
/// (<c>Controllers.Internal.UnlistedEnumFilterResolver.Resolve</c>)は画面にも enum の種類にも
/// 依存しない総称なので、そちらは配線だけで済む。
/// <b>この段落を消すときは、実際にその画面へ広げたときにすること</b>
/// ——消しただけでは、残った画面が表からも検出網からも同時に外れる。</para>
///
/// <para><b>この表が扱うのは「絞り込み入力」だけで、保存する入力は別の話(issue #196)。</b>
/// 登録・編集フォームの発生部署 <c>&lt;select&gt;</c> でも、許可リストから外された部署名を
/// 持つインシデントを開くと同じ「一致する <c>&lt;option&gt;</c> が無い」状態が起きうる。
/// ただし結果はこの表の話より重く、<b>絞り込みが消えるのではなく保存された発生部署が
/// 書き換わる</b>。上の 2 択はそのまま当てはめられない —— 一律に補完すると過去の部署名が
/// <b>新規登録でも選べる</b>ようになり、許可リストから外した意図に反するため。
/// そこで保存側は<b>「現在保存されている値に限り、その 1 件だけ選択肢へ足し、保存も通す」</b>
/// という別の規則を採る(新規登録では例外を作らない)。
/// <b>その規則の正本は <c>IncidentsController.ResolveDepartmentSaveSelection</c> の解説</b>で、
/// 実際の挙動は <c>Controllers.UnlistedDepartmentSavePolicyTests</c> が固定している。
/// <b>この表を保存側へ広げないこと</b>——問いが違う(こちらは「どの行を見るか」、
/// あちらは「どの値を書き込んでよいか」)ので、混ぜると両方の規則が曖昧になる。</para>
///
/// <para><b>並び順(<c>?sortBy=</c>)は別の型が持つが、規則の一部は共有する(issue #209)。</b>
/// <c>/Incidents</c> の <c>sortBy</c>(<c>"latest" | "severity" | "overdue"</c>)も
/// クエリ文字列から届く閉じた語彙で、規則の正本は
/// <see cref="IncidentSortOrder"/>。表を分けているのは<b>答える問いが違う</b>から ——
/// この表が答えるのは「<b>どの行を見せるか</b>を変える入力を、維持するか捨てるか」で、
/// 並び順が変えるのは<b>同じ行の並びだけ</b>。したがって上の 2 択(補完 / 採用しない)も、
/// 「採用しなかったことを画面の注意書きで伝える」も並び順には要らない
/// (適用された並び順は <c>&lt;select&gt;</c> が正しく表示しており、
/// 利用者から見て事実と食い違う表示が残らないため)。</para>
///
/// <para><b>ただし「採用しなかった値を画面へ返さない」だけは並び順も守る。</b>
/// この 1 点は自由記述のテキスト絞り込み(<see cref="Adopted"/>)と同じ理由で必要で、
/// <b>以前は「手当てが要らない」と判断されていた</b>。その根拠は
/// 「適用側の <c>switch</c> の既定枝も表示側の <c>&lt;option&gt;</c> も既定へ倒れて一致する」
/// というもので、<b>3 つ目の利用側であるページャを見落としていた</b> ——
/// <c>Views/Incidents/Index.cshtml</c> は <c>RouteValues["sortBy"] = Model.SortBy</c> と
/// 書いており、受け取った値をそのまま載せると <c>?sortBy=bogus</c> が
/// <b>ページャのリンク全部に付いて回る</b>(<c>?search=%20</c> とまったく同じ壊れ方)。
/// 判定は <see cref="IncidentSortOrder.Adopted"/> に置いてある。
/// <b>値の綴りを書き写さないこと</b>も同じ変更で塞いだ —— 以前はコントローラの
/// <c>switch</c> とビューの <c>&lt;option&gt;</c> に写しがあり、片方だけ直すと
/// 「そのメニュー項目を選んでも最新順のまま」という無言の劣化になった。</para>
/// </summary>
public static class SearchFilter
{
    /// <summary>
    /// 絞り込み入力に「意味のある値」が入っているかを判定する。
    /// </summary>
    /// <param name="input">クエリ文字列やフォームから受け取った絞り込み条件(未入力なら <c>null</c>)。</param>
    /// <returns>絞り込みを適用すべきなら <c>true</c>、空・空白のみなら <c>false</c>。</returns>
    // [NotNullWhen(true)] を付けると、true を返した枝では input が非 null だとコンパイラが分かる。
    // 呼び出し側で null 免除演算子(responsible! のような後置 !)を書かずに済ませるため
    // (! は「今は正しい」ことしか主張できず、この関数の判定を将来変えたときに
    //  NullReferenceException として現れる。属性なら判定とコンパイラの理解が連動する)。
    // 標準ライブラリの string.IsNullOrEmpty が [NotNullWhen(false)] を持つのと同じ仕組み
    public static bool HasValue([NotNullWhen(true)] string? input)
        // null・空文字・空白のみ(半角/全角スペース、タブ、改行など)はすべて「未入力」とみなす
        => !string.IsNullOrWhiteSpace(input);

    /// <summary>
    /// 絞り込みに<b>実際に使った値だけ</b>を返す。使わなかった(空・空白のみの)入力は
    /// <c>null</c> に潰す ——画面へ戻す値を組み立てるときに使う。
    /// </summary>
    /// <remarks>
    /// <para><b>なぜ要るのか(issue #204 課題 2)。</b> <c>?search=%20</c> のような空白のみの入力は
    /// <see cref="HasValue"/> が <c>false</c> なので<b>絞り込みには使われない</b>が、
    /// 受け取った値をそのまま ViewModel / ViewBag へ載せると画面だけが値を運び続ける:
    /// <c>&lt;input value=&quot;…&quot;&gt;</c> に見えない値が残り、ページャのリンクが
    /// すべて <c>?search=%20&amp;page=N</c> になる。バッジ・パネルは「絞り込み無し」と
    /// 言っているのに URL だけが違うことを言う、という食い違いになる。</para>
    ///
    /// <para><b>規則そのものは新しくない。</b> 「採用しなかった値を画面へ返さない」は
    /// 発生部署・原因分類・監査ログのエンティティ名／操作が既に守っている
    /// (<c>Controllers.Internal.DepartmentFilterResolver.DepartmentFilterSelection.Effective</c>
    /// の解説が正本)。
    /// 自由記述のテキスト絞り込みだけがその外にあり、<b>例外にしてよい理由が無かった</b>。
    /// あちらは「許可リスト・実データに載っているか」という画面ごとの判断が要るので
    /// 解決メソッドを持つが、テキスト側の判断は<b>この型が答える「入力があるか」だけ</b>なので、
    /// 画面ごとに <c>HasValue(x) ? x : null</c> を書き写さずここへ置く(§6 DRY)。</para>
    ///
    /// <para><b>値は加工しない。</b> 採用する場合は受け取った文字列をそのまま返す
    /// (前後の空白も落とさない)。トリミングは検索の一致範囲を変える別の判断で、
    /// <see cref="HasValue"/> の解説が「必要になったときに独立した変更として決める」と
    /// 書いているのと同じ扱い。</para>
    /// </remarks>
    /// <param name="input">クエリ文字列やフォームから受け取った絞り込み条件。</param>
    /// <returns>絞り込みに使った値。使わなかったなら <c>null</c>。</returns>
    public static string? Adopted(string? input)
        // 絞り込みに使った値だけを返し、使わなかった入力は null に潰す
        => HasValue(input) ? input : null;
}
