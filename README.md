# Incident Insight（医療インシデント管理ツール）

ASP.NET Core + SQL Server を前提にした、医療インシデント管理のサンプル実装です。

## 実装済み機能
- インシデント報告登録
- 原因分類（ヒューマンエラー等）
- 再発防止策の記録（初回登録時）
- 集計・分析（件数・傾向）
  - 原因分類別の割合
  - 月次件数トレンド

## 技術構成
- ASP.NET Core MVC (.NET 8)
- Entity Framework Core + SQL Server
- Chart.js（ダッシュボード可視化）

## 業務改善・再発防止の観点（設計意図）
- `CauseCategory` による原因の構造化で、改善テーマを分類可能
- `Severity` で優先度を可視化し、対策工数配分の判断を支援
- `Countermeasure` を報告と紐づけ、対策の実行管理（未完了件数）を追跡
- ダッシュボードで「どの原因が多いか」「いつ増えているか」を即時確認

## セットアップ例
```bash
# 依存関係復元
 dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj

# 起動
 dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```
