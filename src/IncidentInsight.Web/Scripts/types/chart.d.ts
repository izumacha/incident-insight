// Chart.js は CDN 経由でグローバル変数 `Chart` として読み込まれている (Views/Shared/_Layout.cshtml 参照)。
// このファイルはプロジェクト内で実際に使う Chart.js の API サブセットのみをアンビエント宣言する。
// 完全な型定義が必要になった場合は npm の chart.js パッケージを devDependency に追加して `import type` する手もある。

// データセット 1 件の設定 (折れ線・棒グラフ共通で利用する最小限のプロパティだけ)
interface IIChartDataset {
  // 凡例に表示されるシリーズ名
  label?: string;
  // データ点の配列 (折れ線の y 値や棒グラフの値)
  data: number[];
  // 線の色や枠線の色
  borderColor?: string;
  // 塗りつぶしの色 (折れ線の塗り、ドーナツのセグメントなど)
  backgroundColor?: string | string[];
  // 折れ線の曲率 (0 で直線、0.4 程度で滑らかな曲線)
  tension?: number;
  // 折れ線の下を塗りつぶすか
  fill?: boolean;
  // 折れ線上のデータ点の半径
  pointRadius?: number;
  // ホバー時の点の半径
  pointHoverRadius?: number;
  // 点の塗りつぶし色
  pointBackgroundColor?: string;
  // 線の太さ
  borderWidth?: number;
}

// チャートに渡すデータ (ラベル + データセット配列)
interface IIChartData {
  // 横軸ラベル
  labels: string[];
  // データセット (複数系列を重ねたい場合は複数要素)
  datasets: IIChartDataset[];
}

// 軸スケール設定 (y 軸の最小値固定や目盛り間隔などに使う)
interface IIChartScale {
  // 0 始まりにするかどうか
  beginAtZero?: boolean;
  // 目盛りの設定
  ticks?: { stepSize?: number; display?: boolean };
  // 軸自体の表示有無
  display?: boolean;
  // グリッド線の設定
  grid?: { display?: boolean };
}

// クリックされた要素の情報 (折れ線のデータ点や棒グラフのバー)
interface IIChartElement {
  // データ配列内のインデックス
  index: number;
}

// チャート全体のオプション
interface IIChartOptions {
  // 親要素のサイズに合わせて自動リサイズするか
  responsive?: boolean;
  // 縦横比を維持するか
  maintainAspectRatio?: boolean;
  // 内部プラグインの設定 (凡例・ツールチップなど)
  plugins?: {
    legend?: { display?: boolean };
    tooltip?: { enabled?: boolean };
  };
  // x / y 軸の設定
  scales?: {
    x?: IIChartScale;
    y?: IIChartScale;
  };
  // データ点クリック時のハンドラ (期間絞り込み遷移などに使う)
  onClick?: (event: Event, elements: IIChartElement[]) => void;
  // ホバー時の挙動 (どこを近接判定するか)
  interaction?: {
    mode?: 'index' | 'point' | 'nearest';
    intersect?: boolean;
  };
}

// チャート全体の設定 (型 + データ + オプション)
interface IIChartConfiguration {
  // チャート種別
  type: 'line' | 'bar' | 'pie' | 'doughnut';
  // データ部
  data: IIChartData;
  // オプション部
  options?: IIChartOptions;
}

// グローバルに公開されている Chart クラス (CDN 由来)
// 第1引数: 描画対象の canvas 要素または 2D コンテキスト
// 第2引数: チャート設定
declare class Chart {
  constructor(canvas: HTMLCanvasElement | CanvasRenderingContext2D, config: IIChartConfiguration);
  // チャートの破棄 (SPA でない本プロジェクトでは現状未使用だが将来用に宣言)
  destroy(): void;
  // 既存チャートを再描画する (テーマ切替時に色を反映し直すために使う)
  update(): void;
  // Chart.js 全体の既定スタイル。軸ラベル/凡例の文字色やグリッド線色をここで一括設定できる。
  static defaults: {
    // 目盛り・凡例などの文字色
    color: string;
    // グリッド線・軸線の色
    borderColor: string;
  };
  // canvas 要素 (または id) から既存のチャートインスタンスを取得する。無ければ undefined。
  static getChart(item: HTMLCanvasElement | string): Chart | undefined;
}
