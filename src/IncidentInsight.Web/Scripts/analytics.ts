// 分析・集計画面 (Views/Analytics/Index.cshtml) の 7 つのグラフとサマリー欄を初期化する。
// 従来は Razor 内に約 330 行の inline <script> として書かれていたものを TypeScript に切り出した
// (Views/Home/Index.cshtml → Scripts/dashboard.ts と同じ「JSON データ島 + 外部 js」構成に揃える)。
//
// この切り出しで同時に直したこと:
//   1. サマリー欄が「データ読み込み中...」のまま固着する不具合。以前はサマリーの DOM を
//      ByIncidentType の成功コールバックの中だけで生成していたため、その 1 本が失敗すると
//      (セッション切れの 401・サーバエラーの 500 など) スピナーが永久に回り続けた。
//      canvas の aria-label については同じ失敗モードを既に修正済みだったが、サマリー欄は
//      取り残されていた (§7「待てば表示される」という誤った期待を与えない / §6 エラーを握り潰さない)。
//   2. コールバック間を window._topDept などのグローバル変数で受け渡していた暗黙の結合。
//      「先に描かれていれば今すぐ反映、まだなら後で反映」という同じ分岐が 4 箇所へ写経されていた (§6 DRY)。
//   3. 完了数・期限超過数を d.data[3] / d.data[2] という位置で取り出していたマジックナンバー。
//      サーバ側でバケットを 1 つ挿入すると黙って別の数値を表示してしまう (§6)。
//      サーバから受け取った labels 配列を検索してバケットを引き当てる方式に変える。
//   4. innerHTML でのマークアップ組み立て。サマリー欄と再発統計欄は Razor 側の静的マークアップに移し、
//      JS からは textContent しか書かないため、生 HTML 挿入が画面から無くなる (§9)。

// グラフの読み込み状態を表す aria-label の末尾サフィックス。
// Razor 側の静的な aria-label は「<グラフ名>（データ読み込み中）」という形で書いてあり、
// ここではこのサフィックスを目印に「グラフ名」だけを取り出す (§6 マジック文字列を避ける)。
// この書式は tests/IncidentInsight.Tests/Views/ChartAccessibilityTests.cs が固定している
const CHART_LOADING_SUFFIX = '（データ読み込み中）';
// データの取得に失敗したときに付け替えるサフィックス
const CHART_ERROR_SUFFIX = '（データを読み込めませんでした）';
// データは取れたがグラフの描画に失敗したときに付け替えるサフィックス。
// 取得失敗と区別するのは、利用者への案内(再読み込みで直るのか、環境の問題なのか)が変わるため。
// 例: Chart.js を配信する CDN が遮断されている環境ではこちらになる
const CHART_RENDER_ERROR_SUFFIX = '（グラフを表示できませんでした）';
// サマリー欄の各項目が取得できなかったときに表示する文言
const SUMMARY_ERROR_TEXT = '取得できません';
// サマリー欄・グラフラベルで「該当データが 1 件も無い」ことを示す文言
const NO_DATA_TEXT = '-';

// チャート用の共通カラーパレット (種別別・原因分類別など、意味づけの無い系列に順番に割り当てる)
const COLORS = [
  '#0d6efd', '#6610f2', '#fd7e14', '#198754', '#dc3545', '#0dcaf0', '#ffc107', '#6c757d', '#d63384',
];
// 月別トレンドの折れ線色と、その下の塗りつぶし色 (半透明)
const TREND_LINE_COLOR = '#0d6efd';
const TREND_FILL_COLOR = 'rgba(13,110,253,0.08)';

// 各 JSON API が返す {labels, data} の共通形 (Chart.js がそのまま消費する形。サーバ側の形を変えない)
interface ChartSeries {
  // 横軸 (またはドーナツの凡例) のラベル
  labels: string[];
  // ラベルと同じ並び順の件数
  data: number[];
}

// バケットごとに意味づけされた色を持つグラフ (MeasureStatus / EffectivenessRating) の共通形。
// 配色は EnumLabels(色の一元管理元)でしか解決できないため、16 進値を JS 側に直書きせず
// サーバから受け取る。直書きすると Bootstrap のテーマ色を変えたときにグラフだけ古い色が残る (§6)
interface ColoredSeries extends ChartSeries {
  // labels と同じ並び順の 16 進カラーコード (EnumLabels.Hex 由来)
  colors: string[];
}

// EffectivenessRating エンドポイントは評価分布・配色に加えて再発の有無も返す
interface EffectivenessSeries extends ColoredSeries {
  // 再発の有無ごとの対策件数
  recurrenceStats: {
    // 再発が確認された (= 対策が効かなかった) 件数
    recurred: number;
    // 再発が確認されなかった (= 対策が有効だった) 件数
    prevented: number;
  };
}

// Razor の JSON データ島 (<script type="application/json" id="analytics-data">) から受け取る初期化データ
interface AnalyticsData {
  // 各 JSON API の URL。'/Analytics/...' と直書きするとリバースプロキシのサブパス配備で
  // PathBase が付かず 404 になるため、Url.Action で生成したものをサーバから受け取る
  urls: {
    monthlyTrend: string;
    byCause: string;
    byDepartment: string;
    bySeverity: string;
    measureStatus: string;
    effectivenessRating: string;
    byIncidentType: string;
  };
  // 重症度別グラフの配色 (EnumLabels の重症度 → Bootstrap 色 → 16 進の順で解決済み。enum 定義順)
  severityColors: string[];
  // MeasureStatus の labels 配列から「期限超過」「完了」バケットを引き当てるためのラベル。
  // 位置 (インデックス) ではなくラベル一致で探すことで、バケットの増減に巻き込まれない
  measureStatusLabels: {
    overdue: string;
    completed: string;
  };
}

// 即時実行関数で他ファイル/グローバルとの名前衝突を防ぐ
(() => {
  // Razor が埋め込んだ JSON ブロックを取得
  const dataElement = document.getElementById('analytics-data');
  // 要素が存在しない、または空テキストなら何もしない (分析画面以外で誤って読み込まれた場合の保険)
  if (!dataElement || !dataElement.textContent) {
    return;
  }

  // JSON をパース (パース失敗時は黙って終了)
  let config: AnalyticsData;
  try {
    config = JSON.parse(dataElement.textContent) as AnalyticsData;
  } catch {
    return;
  }

  // ── グラフ名 (aria-label) の管理 ──────────────────────────────

  // canvas の id → グラフ名 (状態サフィックスを外したもの) の対応表。
  // グラフ名を Razor の aria-label 側だけに置き、ここには同じ文字列を書かないための退避
  // (書き写すと Razor だけ直したときに古い名前で上書きされる。§6 DRY)
  const chartBaseNames = new Map<string, string>();

  // ページ読み込み直後の aria-label からグラフ名を取り出して退避する。
  // この js は body 末尾 (@section Scripts) で読み込まれるため、この時点で canvas は DOM 上に存在する
  document.querySelectorAll<HTMLCanvasElement>('canvas[aria-label]').forEach((canvas) => {
    // Razor が書いた初期ラベル (「〜のグラフ（データ読み込み中）」) を読む
    const label = canvas.getAttribute('aria-label') ?? '';
    // 末尾が読み込み中サフィックスならそれを取り除いた部分がグラフ名。
    // 付いていないラベルはそのままグラフ名として扱う
    const baseName = label.endsWith(CHART_LOADING_SUFFIX)
      ? label.slice(0, -CHART_LOADING_SUFFIX.length)
      : label;
    // id をキーに退避する
    chartBaseNames.set(canvas.id, baseName);
  });

  // canvas の aria-label を「グラフ名＋状態」の形に組み立て直す共通処理。
  // 成功時は数値入りの本文、失敗時はエラー文言と、状態ごとの差し替え口を 1 つにまとめる
  const setChartLabel = (canvasId: string, suffix: string): void => {
    // 対象の canvas を取得する
    const canvas = document.getElementById(canvasId);
    // 想定の要素が無ければ何もしない (ページ構成変更時の保険)
    if (!canvas) {
      return;
    }
    // 退避しておいたグラフ名に、渡された状態文字列を連結して書き戻す
    canvas.setAttribute('aria-label', `${chartBaseNames.get(canvasId) ?? ''}${suffix}`);
  };

  // canvas はビットマップなので、描画されたグラフの中身は支援技術に一切伝わらない。
  // データ取得後に aria-label を実際の数値入りへ差し替え、スクリーンリーダー利用者にも
  // グラフと同じ情報が届くようにする (§7)。labels と values は Chart.js に渡すものと同一の配列。
  const describeChart = (canvasId: string, labels: string[], values: number[]): void => {
    // 「ラベル 件数件」の並びを作る (値が無いラベルは 0 件として読み上げる)
    const parts = labels.map((label, i) => `${label} ${values[i] ?? 0}件`);
    // データが 1 件も無い場合は、その旨だけを伝える
    const body = parts.length > 0 ? parts.join('、') : 'データがありません';
    // aria-label は属性値としてブラウザが解釈するテキストなので HTML エスケープは不要
    setChartLabel(canvasId, `。${body}`);
  };

  // ── サマリー欄 ────────────────────────────────────────────

  // JS から値を流し込む「初期値 - のまま置いてある」要素の id をここに集約する。
  // 分析サマリー欄の 5 項目に加え、有効性評価グラフの下に置いた再発内訳の 2 項目も含める。
  // 後者を漏らしていた頃は、EffectivenessRating の取得が 401/500 で失敗すると
  // 再発内訳だけが「-」のまま取り残され、値が 0 件なのか取得できなかったのか区別できなかった
  // (§7 待てば表示されるという誤った期待を与えない / §6 エラーを握り潰さない)。
  // 「どのフェッチがどの項目を埋めるか」を 1 か所に集約し、
  // 失敗時にどの項目をエラー表示にすべきかを機械的に決められるようにする
  const SUMMARY_FIELDS = {
    topDept: 'topDept',
    topType: 'topType',
    completionRate: 'completionRate',
    failedMeasures: 'failedMeasures',
    overdueMeasures: 'overdueMeasures',
    recurrencePrevented: 'recurrencePrevented',
    recurrenceRecurred: 'recurrenceRecurred',
  } as const;

  // サマリー欄の 1 項目にテキストを流し込む。要素が無ければ何もしない (ページ構成変更時の保険)。
  // innerHTML ではなく textContent を使うため、DB 由来の部署名・種別名に HTML 特殊文字が
  // 含まれていてもマークアップとして解釈されない (§9 生 HTML 挿入を避ける)
  const setSummary = (fieldId: string, text: string): void => {
    // 対象要素を取得する
    const el = document.getElementById(fieldId);
    // 見つかったときだけ文字列として書き込む
    if (el) {
      el.textContent = text;
    }
  };

  // サマリー欄の項目が「まだ何も書き込まれていない」(Razor の初期値のまま)ときだけ書き込む。
  // 描画コールバックが途中で落ちた場合の後始末に使う: 既に正しい値が入っている項目を
  // エラー文言で塗り潰さず、初期値のまま取り残された項目だけを確定した状態にするため
  const setSummaryIfUnset = (fieldId: string, text: string): void => {
    // 対象要素を取得する
    const el = document.getElementById(fieldId);
    // 初期値(NO_DATA_TEXT)のままの項目だけを書き換える
    if (el && el.textContent === NO_DATA_TEXT) {
      el.textContent = text;
    }
  };

  // 「ラベル (N件)」形式のサマリー表示を作る。データが空なら NO_DATA_TEXT を返す。
  // labels より data が短い(想定外のレスポンス)場合でも「undefined件」と表示しないよう 0 に倒す
  const formatTopEntry = (series: ChartSeries): string =>
    series.labels.length > 0 ? `${series.labels[0]} (${series.data[0] ?? 0}件)` : NO_DATA_TEXT;

  // ── データ取得 ────────────────────────────────────────────

  // 指定 URL から JSON を取得し、成功したらコールバックに渡す小さなヘルパー。
  //
  // canvasId は失敗時に aria-label を「読み込み中」のまま放置しないために受け取る。
  // 放置すると、描画されないグラフをスクリーンリーダーが永久に「読み込み中」と読み上げ続け、
  // 待てば表示されるという誤った期待を与えてしまう (§7 / §6 エラーを握り潰さない)。
  //
  // summaryFields は、このフェッチが埋めるはずだったサマリー項目の id。取得に失敗したときは
  // 該当項目をエラー文言に差し替え、初期表示の「-」のまま放置しない
  const loadChart = async <T>(
    url: string,
    canvasId: string,
    summaryFields: readonly string[],
    render: (data: T) => void,
  ): Promise<void> => {
    // 取得したデータの置き場 (取得と描画で try を分けるため外側で宣言する)
    let data: T;
    try {
      const res = await fetch(url);
      // HTTP エラー (401/500 等) は fetch では例外にならないため明示的に弾く。
      // これを見ないと、エラーページの HTML を JSON として解析しようとして
      // 分かりにくい構文エラーになる
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      // 本文を JSON として解析する
      data = (await res.json()) as T;
    } catch (e) {
      // 開発者向けには原因を残す (利用者向けの画面には内部詳細を出さない。§9)
      console.error('Chart load error:', url, e);
      // 支援技術には「読み込めなかった」という確定した状態を伝えて、ここで打ち切る
      setChartLabel(canvasId, CHART_ERROR_SUFFIX);
      // このフェッチが担当していたサマリー項目も「読み込み中の見た目」で放置しない
      summaryFields.forEach((field) => setSummary(field, SUMMARY_ERROR_TEXT));
      return;
    }

    // 描画は取得と別の try で包む。ここを取得側とまとめてしまうと、
    // 「グラフは描けたがサマリー計算で落ちた」場合にまで
    // 「読み込めませんでした」という誤ったラベルを付けてしまうため。
    // グラフ描画の失敗自体は drawChart が内部で処理するので、ここへ到達するのは
    // サマリー計算などコールバック本体の不具合に限られる (本来起きてはいけない経路)
    try {
      render(data);
    } catch (e) {
      // 取得失敗・描画失敗と区別できるメッセージで記録する (原因の切り分けのため)
      console.error('Chart callback error:', url, e);
      // コールバックが途中で落ちると、まだ書かれていないサマリー項目が初期値「-」のまま残る。
      // 既に正しい値が入った項目はそのままに、取り残された項目だけを確定した状態にする
      summaryFields.forEach((field) => setSummaryIfUnset(field, SUMMARY_ERROR_TEXT));
    }
  };

  // 1 つの canvas にグラフを描画し、同じ内容を aria-label へ反映する共通処理。
  //
  // この関数は「絶対に例外を投げない」ことが契約。呼び出し側の描画コールバックは
  // グラフ描画に続けてサマリー欄の更新も行うため、ここで例外が外へ抜けると
  // 後続の setSummary が実行されず、サマリーが初期値「-」のまま無言で固まってしまう。
  // (実際に Chart.js の CDN が遮断された環境で再現した。データ取得は成功しているのに
  //  new Chart() が ReferenceError で落ち、5 項目すべてが「-」のまま残る)
  // グラフが描けなくても、取得済みの数値はサマリー欄に出す方が利用者にとって有益なため、
  // 描画の失敗はこの関数の中で閉じ込め、aria-label だけを描画失敗の状態にする。
  const drawChart = (
    canvasId: string,
    chartConfig: IIChartConfiguration,
    labels: string[],
    values: number[],
  ): void => {
    // 描画先の canvas を取得する
    const canvas = document.getElementById(canvasId) as HTMLCanvasElement | null;
    // 想定の要素が無ければ描画を諦める (ページ構成変更時の保険)
    if (!canvas) {
      return;
    }
    try {
      // Chart.js でグラフを生成する
      new Chart(canvas, chartConfig);
      // 描画したグラフと同じ内容を aria-label へ反映する (スクリーンリーダー向けの等価情報)
      describeChart(canvasId, labels, values);
    } catch (e) {
      // 開発者向けには原因を残す (利用者向けの画面には内部詳細を出さない。§9)
      console.error('Chart render error:', canvasId, e);
      // 支援技術には「描画できなかった」という確定した状態を伝え、読み込み中のまま放置しない
      setChartLabel(canvasId, CHART_RENDER_ERROR_SUFFIX);
    }
  };

  // ── 各グラフの描画 ────────────────────────────────────────
  //
  // 各コールバックの構成は共通:
  //   1. drawChart(...) でグラフを描画する (失敗しても drawChart の内側で閉じる)
  //   2. setSummary(...) でサマリー欄へ数値を流し込む
  // 2 を 1 に依存させないことで、グラフが描けない環境でも数値は画面に出る。

  // 月別トレンド: 折れ線チャートを描画 (サマリー欄には寄与しない)
  void loadChart<ChartSeries>(config.urls.monthlyTrend, 'trendChart', [], (d) => {
    // 折れ線グラフを描画する
    drawChart('trendChart', {
      type: 'line',
      data: {
        labels: d.labels,
        datasets: [{
          label: 'インシデント件数',
          data: d.data,
          borderColor: TREND_LINE_COLOR,
          backgroundColor: TREND_FILL_COLOR,
          tension: 0.3,
          fill: true,
          pointRadius: 5,
          pointBackgroundColor: TREND_LINE_COLOR,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
      },
    }, d.labels, d.data);
  });

  // 原因分類別: ドーナツチャートを描画 (サマリー欄には寄与しない)
  void loadChart<ChartSeries>(config.urls.byCause, 'causeChart', [], (d) => {
    // ドーナツグラフを描画する
    drawChart('causeChart', {
      type: 'doughnut',
      data: { labels: d.labels, datasets: [{ data: d.data, backgroundColor: COLORS }] },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
    }, d.labels, d.data);
  });

  // 部署別: 横棒グラフを描画し、最多発生部署をサマリーへ流し込む
  void loadChart<ChartSeries>(
    config.urls.byDepartment,
    'deptChart',
    [SUMMARY_FIELDS.topDept],
    (d) => {
      // 横棒グラフを描画する (indexAxis: 'y' で横向きになる)
      drawChart('deptChart', {
        type: 'bar',
        data: { labels: d.labels, datasets: [{ label: '件数', data: d.data, backgroundColor: TREND_LINE_COLOR }] },
        options: {
          indexAxis: 'y',
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true, ticks: { stepSize: 1 } } },
        },
      }, d.labels, d.data);
      // ByDepartment は件数の多い順に並んでいるため先頭が最多発生部署になる
      setSummary(SUMMARY_FIELDS.topDept, formatTopEntry(d));
    },
  );

  // 重症度別: 棒グラフを描画 (サマリー欄には寄与しない)
  void loadChart<ChartSeries>(config.urls.bySeverity, 'severityChart', [], (d) => {
    // 重症度バッジと同じ配色 (サーバ側で EnumLabels から解決済み) で棒グラフを描画する
    drawChart('severityChart', {
      type: 'bar',
      data: { labels: d.labels, datasets: [{ label: '件数', data: d.data, backgroundColor: config.severityColors }] },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
      },
    }, d.labels, d.data);
  });

  // 対策ステータス別: ドーナツチャートを描画し、完了率と期限超過件数をサマリーへ流し込む
  void loadChart<ColoredSeries>(
    config.urls.measureStatus,
    'measureStatusChart',
    [SUMMARY_FIELDS.completionRate, SUMMARY_FIELDS.overdueMeasures],
    (d) => {
      // ドーナツグラフを描画する (配色もサーバ側 EnumLabels 由来)
      drawChart('measureStatusChart', {
        type: 'doughnut',
        data: { labels: d.labels, datasets: [{ data: d.data, backgroundColor: d.colors }] },
        options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
      }, d.labels, d.data);

      // バケットをラベル一致で引き当てる。以前は d.data[3] / d.data[2] と位置で取り出しており、
      // サーバ側でバケットを 1 つ挿入・並べ替えするだけで黙って別の数値を表示していた (§6)
      const bucketCount = (label: string): number | null => {
        // ラベル配列から該当バケットの位置を探す
        const index = d.labels.indexOf(label);
        // 見つからなければ null を返し、呼び出し側で「取得できません」に倒す (fail-safe)
        return index < 0 ? null : (d.data[index] ?? null);
      };

      // 全バケットの合計 = 対策の総数 (バケットは互いに排他なので単純合計でよい)
      const total = d.data.reduce((a, b) => a + b, 0);
      // 完了バケットの件数を引き当てる
      const completed = bucketCount(config.measureStatusLabels.completed);
      // 期限超過バケットの件数を引き当てる
      const overdue = bucketCount(config.measureStatusLabels.overdue);

      // 完了率を百分率で表示する。総数 0 件のときは 0% とし、バケットが見つからなければエラー表示
      setSummary(
        SUMMARY_FIELDS.completionRate,
        completed === null
          ? SUMMARY_ERROR_TEXT
          : `${total > 0 ? Math.round((completed / total) * 100) : 0}%`,
      );
      // 期限超過件数を表示する
      setSummary(
        SUMMARY_FIELDS.overdueMeasures,
        overdue === null ? SUMMARY_ERROR_TEXT : `${overdue}件`,
      );
    },
  );

  // 有効性評価: 棒グラフを描画し、再発の有無の内訳と再発確認件数を表示する
  void loadChart<EffectivenessSeries>(
    config.urls.effectivenessRating,
    'effectivenessChart',
    [
      SUMMARY_FIELDS.failedMeasures,
      SUMMARY_FIELDS.recurrencePrevented,
      SUMMARY_FIELDS.recurrenceRecurred,
    ],
    (d) => {
      // ★1〜★5 の棒グラフを描画する (配色もサーバ側 EffectivenessScale → EnumLabels 由来)
      drawChart('effectivenessChart', {
        type: 'bar',
        data: { labels: d.labels, datasets: [{ label: '対策数', data: d.data, backgroundColor: d.colors }] },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        },
      }, d.labels, d.data);

      // 再発なし / 再発ありの件数は Razor 側の静的マークアップ (<strong> 要素) へ数値だけ書き込む。
      // 以前は innerHTML でマークアップごと組み立てていた (§9 生 HTML 挿入を避ける)
      setSummary(SUMMARY_FIELDS.recurrencePrevented, `${d.recurrenceStats.prevented}件`);
      setSummary(SUMMARY_FIELDS.recurrenceRecurred, `${d.recurrenceStats.recurred}件`);
      // サマリー欄の「再発確認対策数」にも同じ値を流し込む
      setSummary(SUMMARY_FIELDS.failedMeasures, `${d.recurrenceStats.recurred}件`);
    },
  );

  // インシデント種別別: 棒グラフを描画し、最多種別をサマリーへ流し込む
  void loadChart<ChartSeries>(
    config.urls.byIncidentType,
    'typeChart',
    [SUMMARY_FIELDS.topType],
    (d) => {
      // 種別別の棒グラフを描画する
      drawChart('typeChart', {
        type: 'bar',
        data: { labels: d.labels, datasets: [{ label: '件数', data: d.data, backgroundColor: COLORS }] },
        options: {
          responsive: true,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
        },
      }, d.labels, d.data);
      // ByIncidentType は件数の多い順に並んでいるため先頭が最多種別になる
      setSummary(SUMMARY_FIELDS.topType, formatTopEntry(d));
    },
  );
})();
