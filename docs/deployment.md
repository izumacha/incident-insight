## Deployment

### Docker

```bash
docker build -t incident-insight:latest .
docker run --rm -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e Database__Provider=postgres \
  -e ConnectionStrings__DefaultConnection="Host=...;Database=...;Username=...;Password=..." \
  -e Audit__HashSalt="<32 文字以上のランダム文字列>" \
  incident-insight:latest
```

`Audit__HashSalt` は Production では必須です（未設定だと fail-closed で起動に失敗します）。
監査ログの個人名を HMAC-SHA256 で擬似匿名化する鍵で、空だと擬似匿名化が容易に破られます。
値はコミットせず、シークレット管理から注入してください。ローテーションすると過去のハッシュとの
相関が失われるため、実施時は runbook に記録します。

### Health check

- `GET /health` が利用できます（DB接続確認込み）。

