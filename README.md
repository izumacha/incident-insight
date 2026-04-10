# Incident Insight（医療インシデント管理ツール）

ASP.NET Core + SQL Server を前提にした、医療インシデント管理のサンプル実装です。

## 実装済み機能
- インシデント報告登録
- 原因分類（ヒューマンエラー等）
- 再発防止策の記録
- 集計・分析（件数・傾向）
  - 原因分類別の割合
  - 月次件数トレンド
  - 部署別件数（上位）
- 4バージョン比較を統合した改善フレーム
  - Version 1: 報告
  - Version 2: 原因分析
  - Version 3: 防止策実行
  - Version 4: 効果検証

## 技術構成
- ASP.NET Core MVC (.NET 8)
- Entity Framework Core + SQL Server
- Chart.js（ダッシュボード可視化）

## 再発防止の設計意図
- `CauseCategory` + `RootCauseSummary` で根本原因を記録
- `Countermeasure` に有効性評価（スコア/コメント）を保持
- `RecurrenceRisk` と `LifecycleStatus` により優先度と進捗を可視化
- ダッシュボードで「多発要因」「高リスク比率」「部署偏在」を同時に把握

## セットアップ例
```bash
# 依存関係復元
 dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj

# 起動
 dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```
