# IncidentInsight — 医療インシデント管理システム

ASP.NET Core 8 MVC + SQLite による医療インシデントの報告・原因分析・再発防止策管理ツール。  
なぜなぜ分析（5 Whys）から対策の有効性評価まで、PDCA サイクルを一貫して管理します。

---

## 機能概要

| 機能 | 概要 |
|------|------|
| インシデント登録 | 3ステップウィザード（基本情報 → なぜなぜ分析 → 再発防止策）。対策未入力では登録不可 |
| なぜなぜ分析 | Why1〜Why5 を構造化カラムで記録。根本原因サマリまで一貫管理 |
| 再発防止策管理 | 短期/長期対策 × 担当者/期限/優先度。完了報告 → 有効性評価 → 再発確認の一貫ライフサイクル |
| 再発自動検出 | 同部署・同種別・同原因分類で複数インシデントが発生した場合、警告バナーを表示 |
| ダッシュボード | KPI（総件数/今月/未完了/期限超過）・月次トレンドチャート。期間切替（週/月/四半期/年）対応 |
| 分析 | 6チャート（月次推移・原因別・部署別・重症度別・対策状況・有効性評価分布） |
| カンバンボード | 再発防止策を「計画中 → 進行中 → 完了」で視覚管理 |

---

## 技術構成

| 要素 | 採用技術 |
|------|---------|
| バックエンド | ASP.NET Core 8.0 MVC + EF Core 8 |
| データベース | SQLite（開発デフォルト）/ SQL Server / PostgreSQL 対応（ランタイム切替） |
| フロントエンド | Bootstrap 5 + Bootstrap Icons + Chart.js 4（CDN） |
| バリデーション | jQuery Validation Unobtrusive（クライアント側）+ DataAnnotations（サーバー側） |

---

## 設計ドキュメント

設計・運用の詳細は `docs/` に分離しています。

- `docs/README.md`

## クイックスタート

### 前提条件

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### ローカル起動（SQLite）

```bash
# リポジトリをクローン
git clone https://github.com/izumacha/incident-insight.git
cd incident-insight

# 依存関係を復元
dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj

# 起動（初回は DB + シードデータが自動作成されます）
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```

ブラウザで `http://localhost:5000` にアクセスしてください。  
初回起動時に以下が自動実行されます：
- SQLite DB ファイル（`incident_insight.db`）の作成
- 原因カテゴリ 23 件 + サンプルインシデント 5 件（なぜなぜ分析・対策付き）のシードデータ投入

---

## データベース設定

### SQLite（デフォルト）

`appsettings.json` のデフォルト設定：

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=incident_insight.db"
  }
}
```

DB ファイルはアプリ起動ディレクトリ（`src/IncidentInsight.Web/`）に作成されます。  
**起動時にマイグレーション適用**：`Database.Migrate()` により、存在する EF Core マイグレーションが自動適用されます。

### スキーマ変更時の対応

モデルに変更を加えた場合は、EF Core マイグレーションを追加してから再起動してください：

```bash
dotnet ef migrations add <MigrationName> --project src/IncidentInsight.Web
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```

### DB プロバイダの切り替え

プロバイダはコード改修なしで `Database:Provider` 設定で切り替え可能です。

| 用途 | `Database:Provider` | 接続文字列例 |
|------|---------------------|---------------|
| 単一診療所 / 開発（デフォルト） | `sqlite` | `Data Source=incident_insight.db` |
| オンプレ病院（Windows + SQL Server） | `sqlserver` | `Server=...;Database=IncidentInsight;Trusted_Connection=True;TrustServerCertificate=True;` |
| Linux / セルフホスト Postgres | `postgres` | `Host=...;Database=incidentinsight;Username=...;Password=...` |
| マネージド（Supabase / Azure DB for PostgreSQL / Aurora） | `postgres` | 各サービスの標準 Postgres 接続文字列 |

環境変数で切り替える場合：

```bash
export Database__Provider=postgres
export ConnectionStrings__DefaultConnection="Host=db.example.com;Database=incidentinsight;Username=app;Password=..."
```

> ⚠️ **マイグレーションはプロバイダ依存**です。リポジトリ同梱のマイグレーションは SQLite 用のため、SQL Server / PostgreSQL に切り替える際は `src/IncidentInsight.Web/Migrations/` を削除して、対象プロバイダで `dotnet ef migrations add InitialCreate` を再実行してください（詳細は `CLAUDE.md` 参照）。

---

## 本番デプロイ

### Docker ビルド

リポジトリ直下に multi-stage Dockerfile を同梱しています。

```bash
docker build -t incident-insight:latest .
docker run --rm -p 8080:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e Database__Provider=postgres \
  -e ConnectionStrings__DefaultConnection="Host=...;Database=...;Username=...;Password=..." \
  incident-insight:latest
```

イメージは非 root (`app` ユーザ) で起動し、`8080/tcp` を listen します。

### ヘルスチェック

`/health` エンドポイントが DB 接続確認付きで利用可能です（認証不要）。Kubernetes / ECS / Cloud Run の liveness/readiness probe に指定してください。

```yaml
readinessProbe:
  httpGet: { path: /health, port: 8080 }
  periodSeconds: 10
```

### セキュリティのベースライン

- HTTPS 終端はリバースプロキシ側で行い、本番では `UseHttpsRedirection` + `UseHsts`（プリロード + 1年）が自動適用されます。
- 認証クッキー / 対策トークン (`antiforgery`) は `SameSite=Strict`、本番は `Secure` 必須。
- パスワードポリシーは本番では 12 文字以上・英大文字・英小文字・数字・記号が必須。
- `SeedAccounts` のデモアカウント作成は Development 限定です（本番環境では自動的にスキップ）。

### シークレット管理

本番では以下を環境変数 / Secret Manager で設定してください。**`appsettings.json` にはパスワードを書かないでください。**

| 設定キー | 環境変数 | 内容 |
|----------|----------|------|
| `Database:Provider` | `Database__Provider` | `sqlite` / `sqlserver` / `postgres` |
| `ConnectionStrings:DefaultConnection` | `ConnectionStrings__DefaultConnection` | DB 接続文字列 |
| `SeedAccounts:AdminPassword` | `SeedAccounts__AdminPassword` | Development のみ有効 |

### 監査ログ

`Incident` / `CauseAnalysis` / `PreventiveMeasure` への全ての Add/Modify/Delete は `AuditSaveChangesInterceptor` によって自動的に `AuditLogs` テーブルに JSON 形式で記録されます。`ExecuteUpdate` / `ExecuteDelete` は変更トラッカーをバイパスするため、これらのエンティティに対しては使用しないでください。

---

## 設定・環境変数

機密情報（本番 DB パスワード等）は **User Secrets** または環境変数で管理してください。

```bash
# User Secrets の初期化（開発環境）
dotnet user-secrets init --project src/IncidentInsight.Web

# 接続文字列を User Secrets に登録
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "接続文字列" \
  --project src/IncidentInsight.Web
```

本番環境では環境変数 `ConnectionStrings__DefaultConnection` を設定することで  
`appsettings.json` の値を上書きできます。

---

## シードデータ

`Data/DbSeeder.cs` により以下が自動投入されます：

- **原因カテゴリ 23 件**（ヒューマンエラー/環境・設備/手順・マニュアル/教育・訓練/コミュニケーション の5大分類）
- **サンプルインシデント 5 件**（Why1〜Why5・再発防止策・有効性評価付き）

シードデータはべき等設計（カテゴリ存在時はスキップ）のため、再起動で重複投入されません。

### デモアカウントのセットアップ（開発環境）

デモアカウントはセキュリティのためパスワードをリポジトリに含めていません。  
初回起動前に **User Secrets** でパスワードを設定してください：

```bash
dotnet user-secrets init --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:AdminPassword" "AdminPass1" --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:RiskManagerPassword" "RiskPass1" --project src/IncidentInsight.Web
```

パスワード未設定の場合、起動ログに警告が出力されデモアカウントの作成はスキップされます。  
パスワードは開発用ポリシー（8文字以上・英大文字含む・数字含む）を満たす必要があります。

---

## プロジェクト構成

```
src/IncidentInsight.Web/
├── Controllers/
│   ├── HomeController.cs          # ダッシュボード（期間切替対応）
│   ├── IncidentsController.cs     # インシデント CRUD + なぜなぜ編集
│   ├── PreventiveMeasuresController.cs  # 対策ライフサイクル管理
│   └── AnalyticsController.cs     # 分析チャート API
├── Models/
│   ├── Incident.cs                # インシデントエンティティ
│   ├── CauseAnalysis.cs           # なぜなぜ分析（Why1〜5）
│   ├── CauseCategory.cs           # 原因カテゴリ（階層）
│   └── PreventiveMeasure.cs       # 再発防止策（ライフサイクル付き）
├── Data/
│   ├── ApplicationDbContext.cs    # EF Core コンテキスト
│   └── DbSeeder.cs                # 初期データ投入
└── Views/
    ├── Home/                      # ダッシュボード
    ├── Incidents/                 # インシデント一覧・詳細・登録・編集
    ├── PreventiveMeasures/        # 対策カンバン・編集・完了報告・有効性評価
    └── Analytics/                 # 分析ページ
```

---

## 開発メモ

- **ビルド**: `dotnet build` — 0 エラーで通過することを確認
- **EF マイグレーション**: 起動時に `Database.Migrate()` で自動適用
- **本番運用**: リリース前にマイグレーションを作成し、適用手順をCI/CDに組み込むことを推奨
