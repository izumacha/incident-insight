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
| データベース | SQLite（開発デフォルト）/ SQL Server 対応 |
| フロントエンド | Bootstrap 5 + Bootstrap Icons + Chart.js 4（CDN） |
| バリデーション | jQuery Validation Unobtrusive（クライアント側）+ DataAnnotations（サーバー側） |

---

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
**マイグレーション不要**：`EnsureCreated()` により起動時にスキーマが自動構築されます。

### スキーマ変更時の対応

モデルに変更を加えた場合、SQLite は `ALTER TABLE` による自動マイグレーションに対応していません。  
開発環境では DB ファイルを削除して再起動してください：

```bash
rm src/IncidentInsight.Web/incident_insight.db
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
# 再起動時にシードデータも再投入されます
```

### SQL Server への切り替え

`appsettings.json` の `DefaultConnection` を SQL Server 接続文字列に変更：

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=IncidentInsight;Trusted_Connection=True;"
  }
}
```

`Program.cs` の `UseSqlite` を `UseSqlServer` に変更してください：

```csharp
options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
```

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
- **EF マイグレーション**: SQLite 環境では未使用（`EnsureCreated` を利用）
- **本番移行時**: EF Core マイグレーションの導入を推奨
