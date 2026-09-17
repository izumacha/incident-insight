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
- 同ミドルウェアが**誰もキャッシュ指示を書かなかった応答**へ `Cache-Control: no-store` を
  付与します(PHI を含む画面・集計 JSON が共用端末のディスクキャッシュや共有キャッシュに
  残らないようにするため)。規則はこの 1 つだけで、応答の種類では振り分けません(将来 CSV・
  添付画像のエクスポートを足しても既定で保護される fail-closed)。すでに `Cache-Control` が
  書かれている応答(`HomeController.Error` の `[ResponseCache]`、`/health`、アンチフォージェリ、
  静的ファイル配信)は上書きしません。
- 静的アセット(`wwwroot` 配下)は `Program.cs` の `UseStaticFiles` が `OnPrepareResponse` で
  `Cache-Control: public,max-age=3600` を名乗ります。これが上の既定値を静的ファイルへ
  及ばせないための仕組みです(`lib/` 配下は版付き URL でないため、長期・`immutable` にはしません)。
  付与の根拠と実測(導入前は「フォームを持つ画面だけがアンチフォージェリ経由で偶然保護されて
  いた」)は `SecurityHeadersMiddleware` の docstring が正本です。
- **例外**: 本番の HTTP → HTTPS リダイレクト(`UseHttpsRedirection` が返す 307)は、
  同ミドルウェアより手前で応答が完結するため、上記のヘッダー群が付きません。本文を持たず、
  307 は明示的な指示が無ければキャッシュされないため実害は無いと判断しています
  (覆いたい場合の手当ては `Program.cs` の該当箇所のコメントが持ちます)。
- Content-Security-Policy は未実装です。nonce なしのインライン `<script>`(ダッシュボードの
  JSON 埋め込み・テーマ復元スクリプト等)を複数箇所で使用しているため、`'unsafe-inline'` なしで
  安全に導入するには別途リファクタが必要です。

### Secrets

- 本番のパスワード/接続文字列は `appsettings.json` に書かず、環境変数や Secret Manager を使ってください。

