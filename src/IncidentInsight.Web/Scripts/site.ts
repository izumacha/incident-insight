// 静的ファイルのまとめ方・圧縮方法の公式ドキュメント:
// https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification

// このファイルはサイト全体で読み込まれる共通スクリプト。
// TypeScript のソースを `src/IncidentInsight.Web/Scripts/` に置き、tsc が `wwwroot/js/` に JavaScript を出力する。
// MSBuild の CompileTypeScript ターゲット(IncidentInsight.Web.csproj 参照)が `dotnet build` 時に tsc を呼び出す。

// ここでは、サーバーレンダリングの画面に「React 製アプリのような細やかな操作感」を後付けで足す。
// すべてプログレッシブ・エンハンスメント(JS が無くても表示は成立し、あれば体験が良くなる)として実装する。
(() => {
  // ユーザーが「動きを減らす」設定をしているかどうかを調べる(尊重してアニメーションを控える)。
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ────────────────────────────────────
  // 1) ダークモード切替: ボタンで light/dark を切り替え、localStorage に保存する
  // ────────────────────────────────────
  // テーマを適用してブラウザに保存する関数。
  const applyTheme = (theme: string): void => {
    // <html> 要素の data-theme 属性を書き換えると site.css の配色が切り替わる。
    document.documentElement.setAttribute("data-theme", theme);
    // 次回アクセス時も同じテーマになるよう保存する。
    try { localStorage.setItem("ii-theme", theme); } catch { /* プライベートモード等では無視 */ }
  };

  // ナビにあるテーマ切替ボタンを取得する。
  const themeToggle = document.querySelector<HTMLButtonElement>(".theme-toggle");
  // ボタンが存在する画面(ログイン以外)だけ、クリックで light↔dark を反転させる。
  if (themeToggle) {
    themeToggle.addEventListener("click", () => {
      // 今が dark なら light へ、そうでなければ dark へ切り替える。
      const current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  // ────────────────────────────────────
  // 2) 数値カウントアップ: KPI の数字を 0 から実際の値まで滑らかに増やす
  // ────────────────────────────────────
  // 1 つの KPI 数値要素を、目標値までアニメーションさせる関数。
  const animateCount = (el: HTMLElement): void => {
    // 要素内の「単位(件 / % など)」スパンは残したいので、先頭のテキストノードだけを対象にする。
    const firstNode = el.firstChild;
    // 先頭がテキストでなければ何もしない。
    if (!firstNode || firstNode.nodeType !== Node.TEXT_NODE) { return; }
    // 数字部分(マイナス符号・小数点を含む)だけを取り出す。完了率 66.7 のような小数も拾えるようにする。
    const match = (firstNode.textContent || "").match(/-?\d+(\.\d+)?/);
    // 数字が見つからなければ何もしない。
    if (!match) { return; }
    // 取り出した数字を(小数も保てるよう)実数に変換する。
    const target = parseFloat(match[0]);
    // 数値として読めない場合は何もしない。
    if (isNaN(target)) { return; }
    // 元の表示の小数点以下の桁数を数える(例: "66.7" → 1 桁、整数なら 0 桁)。
    const decimals = match[0].includes(".") ? match[0].split(".")[1].length : 0;
    // 途中値・最終値を、元と同じ小数桁数にそろえて文字列化する関数(66.7 を 667 にしないため)。
    const fmt = (n: number): string => n.toFixed(decimals);
    // 動きを減らす設定なら、即座に最終値だけ表示して終わる。
    if (prefersReducedMotion) { firstNode.textContent = fmt(target); return; }
    // アニメーションの開始時刻を記録する。
    const startTime = performance.now();
    // カウントアップにかける時間(ミリ秒)。
    const duration = 900;
    // 毎フレーム呼ばれて、経過時間に応じた途中値を書き込む関数。
    const step = (now: number): void => {
      // 0〜1 の進捗率を計算する。
      const progress = Math.min((now - startTime) / duration, 1);
      // 終盤をゆっくり止めるイージング(ease-out)を掛ける。
      const eased = 1 - Math.pow(1 - progress, 3);
      // 現在表示すべき値を、元の小数桁数を保ったまま書き込む。
      firstNode.textContent = fmt(target * eased);
      // まだ途中なら次のフレームを予約する。
      if (progress < 1) { requestAnimationFrame(step); }
    };
    // まず 0(同じ桁数)を表示してからアニメーションを開始する。
    firstNode.textContent = fmt(0);
    requestAnimationFrame(step);
  };

  // 画面内のすべての KPI 数値に対してカウントアップを仕掛ける。
  document.querySelectorAll<HTMLElement>(".kpi-value").forEach((el) => animateCount(el));

  // ────────────────────────────────────
  // 3) 進捗バー演出: 幅 0 から本来の値まで伸ばして「満ちていく」動きを見せる
  // ────────────────────────────────────
  // 画面内の進捗バーを取得する。
  document.querySelectorAll<HTMLElement>(".progress-bar").forEach((bar) => {
    // サーバーが設定した最終的な幅(例: "72%")を覚えておく。
    const finalWidth = bar.style.width;
    // 値が無ければ何もしない。
    if (!finalWidth) { return; }
    // 動きを減らす設定なら、そのままの幅で表示して終わる。
    if (prefersReducedMotion) { return; }
    // いったん幅を 0 にしてから…
    bar.style.width = "0%";
    // 次の描画タイミングで本来の幅に戻すと、CSS の transition で伸びていく。
    requestAnimationFrame(() => requestAnimationFrame(() => { bar.style.width = finalWidth; }));
  });

  // ────────────────────────────────────
  // 4) リップル: ボタンを押した位置から波紋が広がる、触れた感触の演出
  // ────────────────────────────────────
  // 動きを減らす設定でなければ、ボタンクリックに波紋エフェクトを付ける。
  if (!prefersReducedMotion) {
    document.addEventListener("click", (e) => {
      // クリックされた要素から一番近いボタンを探す。
      const target = e.target as HTMLElement;
      const btn = target.closest<HTMLElement>(".btn");
      // ボタン以外、または無効化されたボタンなら何もしない。
      if (!btn || btn.hasAttribute("disabled")) { return; }
      // 波紋を描く小さな span を作る。
      const circle = document.createElement("span");
      // ボタンの大きさと位置を取得する。
      const rect = btn.getBoundingClientRect();
      // 波紋の直径はボタンの長辺に合わせる。
      const size = Math.max(rect.width, rect.height);
      // 波紋を配置するためのスタイルを設定する。
      circle.style.cssText =
        `position:absolute;border-radius:50%;pointer-events:none;` +
        `width:${size}px;height:${size}px;` +
        `left:${e.clientX - rect.left - size / 2}px;top:${e.clientY - rect.top - size / 2}px;` +
        `background:rgba(255,255,255,0.45);transform:scale(0);opacity:0.7;` +
        `animation:ii-ripple 0.6s ease-out forwards;`;
      // ボタン内で絶対配置できるよう、はみ出しを隠して相対配置にする。
      const prevPosition = getComputedStyle(btn).position;
      if (prevPosition === "static") { btn.style.position = "relative"; }
      btn.style.overflow = "hidden";
      // 波紋をボタンに追加し、アニメーション後に取り除く。
      btn.appendChild(circle);
      window.setTimeout(() => circle.remove(), 600);
    });
  }
})();
