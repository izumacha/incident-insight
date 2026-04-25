## Security

### HTTPS / HSTS

本番では `UseHttpsRedirection` と `UseHsts` が有効化されます（HTTPS 終端はリバースプロキシ想定）。

### Cookie / antiforgery

- 認証クッキーや antiforgery は `SameSite=Strict`、本番では `Secure` を前提とします。

### Secrets

- 本番のパスワード/接続文字列は `appsettings.json` に書かず、環境変数や Secret Manager を使ってください。

