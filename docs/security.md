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
- Content-Security-Policy は未実装です。nonce なしのインライン `<script>`(ダッシュボードの
  JSON 埋め込み・テーマ復元スクリプト等)を複数箇所で使用しているため、`'unsafe-inline'` なしで
  安全に導入するには別途リファクタが必要です。

### Secrets

- 本番のパスワード/接続文字列は `appsettings.json` に書かず、環境変数や Secret Manager を使ってください。

