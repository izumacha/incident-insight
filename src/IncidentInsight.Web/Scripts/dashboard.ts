// ダッシュボード画面 (Views/Home/Index.cshtml) の月別トレンドチャートを初期化する。
// 従来は Razor 内に inline <script> として書かれていたものを TypeScript に切り出した (UI モダン化 #3)。
// データは Razor 側で <script type="application/json" id="dashboard-data"> として埋め込み、ここで読み取る。

// 月別データ点 1 件 (Razor 側の JsonSerializer.Serialize で {Label, Count, DateFrom, DateTo} 形式になる)
interface MonthlyDataPoint {
  // 表示ラベル (例: "2026年5月"、週表示では "5/24")
  Label: string;
  // 件数
  Count: number;
  // ドリルダウン用の絞り込み開始日 ("yyyy-MM-dd"。サーバー側で算出)
  DateFrom: string;
  // ドリルダウン用の絞り込み終了日 ("yyyy-MM-dd"。一覧側で「その日を含む」扱い)
  DateTo: string;
}

// ダッシュボード初期化用のデータ構造
interface DashboardData {
  // 月別データ
  monthlyData: MonthlyDataPoint[];
  // 折れ線の本体色
  primaryColor: string;
  // 折れ線の塗りつぶし色 (半透明)
  primaryColorRgba: string;
  // ドリルダウン先のインシデント一覧 URL (PathBase 対応のためサーバー側で生成)
  incidentsUrl: string;
}

// 即時実行関数で他ファイル/グローバルとの名前衝突を防ぐ
(() => {
  // Razor が埋め込んだ JSON ブロックを取得
  const dataElement = document.getElementById('dashboard-data');
  // 要素が存在しない、または空テキストなら何もしない (ダッシュボード以外のページで誤って読み込まれた場合の保険)
  if (!dataElement || !dataElement.textContent) {
    return;
  }

  // JSON をパース (パース失敗時は黙って終了)
  let data: DashboardData;
  try {
    data = JSON.parse(dataElement.textContent) as DashboardData;
  } catch {
    return;
  }

  // チャート描画先の canvas を取得
  const trendCanvas = document.getElementById('trendChart') as HTMLCanvasElement | null;
  // canvas が存在しなければ終了
  if (!trendCanvas) {
    return;
  }

  // X 軸ラベル配列を抽出
  const labels = data.monthlyData.map((m) => m.Label);
  // Y 軸 (件数) 配列を抽出
  const counts = data.monthlyData.map((m) => m.Count);

  // Chart.js で折れ線グラフを生成
  new Chart(trendCanvas, {
    // 折れ線グラフ
    type: 'line',
    // データ部 (ラベル + データセット)
    data: {
      labels,
      datasets: [
        {
          // 凡例ラベル (非表示にしているが a11y のため設定)
          label: 'インシデント件数',
          // 件数の配列
          data: counts,
          // 線色 (medical blue)
          borderColor: data.primaryColor,
          // 折れ線下の塗り (薄めの medical blue)
          backgroundColor: data.primaryColorRgba,
          // 折れ線の曲率 (0.35 で柔らかいカーブ)
          tension: 0.35,
          // 線下を塗りつぶす
          fill: true,
          // データ点の半径
          pointRadius: 4,
          // ホバー時の点の半径
          pointHoverRadius: 6,
          // 点の塗り色 (線と同色)
          pointBackgroundColor: data.primaryColor,
          // 線の太さ
          borderWidth: 2,
        },
      ],
    },
    // オプション (レスポンシブ・凡例・軸・クリックハンドラ)
    options: {
      // 親要素にあわせてリサイズ
      responsive: true,
      // 凡例は折れ線 1 本のみなので非表示
      plugins: { legend: { display: false } },
      // Y 軸は 0 始まり、整数刻み
      scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
      // データ点クリックで該当期間のインシデント一覧へ遷移
      onClick: (_evt, elements) => {
        // クリックでヒットした要素が無ければ何もしない
        if (!elements.length) {
          return;
        }
        // 最前面の要素のインデックスを取得
        const idx = elements[0].index;
        // クリックされたデータ点を取得
        const point = data.monthlyData[idx];
        // データ点が無い、または期間情報が欠けていれば何もしない (古いキャッシュ JSON 等への保険)
        if (!point || !point.DateFrom || !point.DateTo) {
          return;
        }
        // インシデント一覧へ期間絞り込みつきで遷移。
        // 期間はサーバー側で算出したバケット実期間 (DateFrom/DateTo) をそのまま使う。
        // 以前は表示ラベル「yyyy年M月」を正規表現でパースしていたが、週表示のラベル ("M/d") には
        // 年情報がなくパース不能でクリックが無反応になっていたため、ラベル形式への依存をやめた。
        // dateTo はサーバー側で「その日を含む」扱いのため、チャートの件数と一覧件数が一致する。
        // URL はサーバー生成 (incidentsUrl) を使い、PathBase 付き配備でも壊れないようにする。
        window.location.href = `${data.incidentsUrl}?dateFrom=${point.DateFrom}&dateTo=${point.DateTo}`;
      },
    },
  });
})();
