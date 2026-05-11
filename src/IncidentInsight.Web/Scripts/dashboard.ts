// ダッシュボード画面 (Views/Home/Index.cshtml) の月別トレンドチャートを初期化する。
// 従来は Razor 内に inline <script> として書かれていたものを TypeScript に切り出した (UI モダン化 #3)。
// データは Razor 側で <script type="application/json" id="dashboard-data"> として埋め込み、ここで読み取る。

// 月別データ点 1 件 (Razor 側の JsonSerializer.Serialize で {Label, Count} 形式になる)
interface MonthlyDataPoint {
  // 表示ラベル (例: "2026年5月")
  Label: string;
  // 件数
  Count: number;
}

// ダッシュボード初期化用のデータ構造
interface DashboardData {
  // 月別データ
  monthlyData: MonthlyDataPoint[];
  // 折れ線の本体色
  primaryColor: string;
  // 折れ線の塗りつぶし色 (半透明)
  primaryColorRgba: string;
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
      // データ点クリックで該当月のインシデント一覧へ遷移
      onClick: (_evt, elements) => {
        // クリックでヒットした要素が無ければ何もしない
        if (!elements.length) {
          return;
        }
        // 最前面の要素のインデックスを取得
        const idx = elements[0].index;
        // 該当月のラベル文字列を取得
        const label = data.monthlyData[idx]?.Label ?? '';
        // 「yyyy年M月」形式を正規表現でパース
        const monthMatch = label.match(/(\d{4})年(\d{1,2})月/);
        if (monthMatch) {
          // 年部分 (4 桁)
          const y = monthMatch[1];
          // 月部分 (1〜12、ゼロ埋めして 2 桁化)
          const m = monthMatch[2].padStart(2, '0');
          // 月を数値に変換 (翌月計算用)
          const monthNum = parseInt(m, 10);
          // 翌月 (12 月の場合は翌年 1 月)
          const nextM = ((monthNum % 12) + 1).toString().padStart(2, '0');
          // 翌年 (12 月のみ年が増える)
          const nextY = monthNum === 12 ? (parseInt(y, 10) + 1).toString() : y;
          // インシデント一覧へ期間絞り込みつきで遷移
          window.location.href = `/Incidents?dateFrom=${y}-${m}-01&dateTo=${nextY}-${nextM}-01`;
        }
      },
    },
  });
})();
