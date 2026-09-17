## Security

### HTTPS / HSTS

本番では `UseHttpsRedirection` と `UseHsts` が有効化されます（HTTPS 終端はリバースプロキシ想定）。

### Cookie / antiforgery

- 認証クッキーや antiforgery は `SameSite=Strict`、本番では `Secure` を前提とします。

### レスポンスヘッダー

- `SecurityHeadersMiddleware`(`src/IncidentInsight.Web/Middleware/SecurityHeadersMiddleware.cs`)が
  全レスポンスに `X-Content-Type-Options: nosniff` / `X-Frame-Options: DENY` /
  `Referrer-Policy: strict-origin-when-cross-origin` を付与します(クリックジャッキング・
  MIME スニッフィング・Referer 経由の URL 漏洩対策)。
- 同ミドルウェアが**動的な応答にだけ** `Cache-Control: no-store` を付与します(PHI を含む画面・
  集計 JSON が共用端末のディスクキャッシュや共有キャッシュに残らないようにするため)。判定は
  fail-closed で、除外するのは静的アセットが名乗る Content-Type(css / js / 画像 / フォント)だけ。
  すでに `Cache-Control` が書かれている応答(`HomeController.Error` の `[ResponseCache]`、
  `/health`)は上書きしません。付与の根拠と実測(導入前は「フォームを持つ画面だけが
  アンチフォージェリ経由で偶然保護されていた」)は同ファイルの docstring が正本です。
- Content-Security-Policy は未実装です。nonce なしのインライン `<script>`(ダッシュボードの
  JSON 埋め込み・テーマ復元スクリプト等)を複数箇所で使用しているため、`'unsafe-inline'` なしで
  安全に導入するには別途リファクタが必要です。

### Secrets

- 本番のパスワード/接続文字列は `appsettings.json` に書かず、環境変数や Secret Manager を使ってください。

