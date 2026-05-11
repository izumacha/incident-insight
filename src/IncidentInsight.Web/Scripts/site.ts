// 静的ファイルのまとめ方・圧縮方法の公式ドキュメント:
// https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification

// このファイルはサイト全体で読み込まれる共通スクリプト。
// TypeScript のソースを `src/IncidentInsight.Web/Scripts/` に置き、tsc が `wwwroot/js/` に JavaScript を出力する。
// MSBuild の CompileTypeScript ターゲット(IncidentInsight.Web.csproj 参照)が `dotnet build` 時に tsc を呼び出す。

// 現時点ではアプリ共通の処理は無いが、TypeScript パイプラインの動作確認のため空の即時実行関数だけ置いておく。
(() => {
  // ページ読み込み完了時のフックを置く場合はここに追記する(例: コンソールへのバージョン表示など)。
})();
