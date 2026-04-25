## Deployment

### Docker

```bash
docker build -t incident-insight:latest .
docker run --rm -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e Database__Provider=postgres \
  -e ConnectionStrings__DefaultConnection="Host=...;Database=...;Username=...;Password=..." \
  incident-insight:latest
```

### Health check

- `GET /health` が利用できます（DB接続確認込み）。

