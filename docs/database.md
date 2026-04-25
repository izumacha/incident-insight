## Database & migrations

### デフォルト（SQLite）

`appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=incident_insight.db"
  }
}
```

起動時に `Database.Migrate()` によりマイグレーションが自動適用されます。

### スキーマ変更

モデル変更後は EF Core マイグレーションを追加して再起動します。

```bash
dotnet ef migrations add <MigrationName> --project src/IncidentInsight.Web
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```

### DB プロバイダ切替（sqlite / sqlserver / postgres）

`Database:Provider` を切り替えます（環境変数なら `Database__Provider`）。

> ⚠️ マイグレーションはプロバイダ依存です。SQLite 用のマイグレーションをそのまま SQL Server / Postgres に適用しないでください。

