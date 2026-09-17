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
- **例外**: 同ミドルウェアより手前で応答が完結する経路が 2 つあり、そこには上記のヘッダー群が
  付きません。**どちらもこのアプリのデータを 1 文字も載せない**ため、PHI が漏れることは無いと
  判断しています(覆いたい場合の手当ては `Program.cs` の該当箇所のコメントが持ちます)。
  1. 本番の HTTP → HTTPS リダイレクト(`UseHttpsRedirection` が返す 307)。本文を持たず、
     307 は明示的な指示が無ければキャッシュされません。**ただし `Location` は要求元の
     `Host` をそのまま含みます**(`UseHttpsRedirection` は `Request.Host` から遷移先を
     組み立てるため)。つまりこの経路だけは「リクエスト由来の値を映し返さない」が
     成り立ちません —— そこを塞ぐのは次の項の `AllowedHosts` の絞り込み(issue #64)で、
     既定の `"*"` のままだと `Host: evil.example` が `Location: https://evil.example/...`
     として返り、前段の共有キャッシュがそれを保存して他の職員へ返しうる状態になります。
     **本番では必ず実ホスト名へ絞ってください。**
     なお `appsettings.json` に入っているのは既定の `"*"` で、**これは配備時の設定事項です**
     (実ホスト名をリポジトリ側で決められないため)。絞り忘れは機械的には検出できないので、
     `Program.cs` が Production 起動時に警告ログ(`AllowedHosts is permissive in Production …`、
     設定値そのものも出ます)を出します —— **配備後にこのログが出ていないことを確認してください。**
     **全許可になる綴りは `*` だけではありません**: `[::]`(IPv6 Any)と `0.0.0.0`(IPv4 Any)も
     同じで、**1 つでも混ざっていれば実ホスト名を併記しても許可リスト全体が無効**になります
     (`ASPNETCORE_URLS=http://0.0.0.0:8080` を写して `AllowedHosts` に書くと自然に起きます)。
     判定の正本は `Models/Validation/AllowedHostsPolicy`、実際の挙動は
     `HostFilteringShortCircuitTests` が固定しています。
  2. ホスト名の絞り込み(`AllowedHosts` を実ホスト名へ絞ったとき。issue #64。
     既定の `"*"` のままなら短絡しません)。一致しない `Host` ヘッダーには 400 が返ります。
     これは汎用ホストが `IStartupFilter` として登録するミドルウェアなので、`Program.cs` の
     並べ替えでは**手前に出られません**。実測では `Cache-Control` は付きませんが、
     **本文は空ではなく**フレームワークの定型ページ(`Bad Request - Invalid Hostname`)が
     返ります。安全なのは「空だから」ではなく「定型文で、要求元のホスト名も業務データも
     含まないから」で、その 2 点は `HostFilteringShortCircuitTests` が固定しています
     (映し返しがあると、キャッシュ抑止の効かない応答に攻撃者の入力が載ることになります)。
- Content-Security-Policy は未実装です。nonce なしのインライン `<script>`(ダッシュボードの
  JSON 埋め込み・テーマ復元スクリプト等)を複数箇所で使用しているため、`'unsafe-inline'` なしで
  安全に導入するには別途リファクタが必要です。

### Secrets

- 本番のパスワード/接続文字列は `appsettings.json` に書かず、環境変数や Secret Manager を使ってください。

