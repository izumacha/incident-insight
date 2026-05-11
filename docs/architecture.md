## Architecture

IncidentInsight は **ASP.NET Core 8 MVC + EF Core** で構築された、医療インシデント管理システムです。

### 構成要素（ディレクトリ）

- `src/IncidentInsight.Web/Controllers/`: UI の入口（画面遷移、入力受付）
- `src/IncidentInsight.Web/Models/`: ドメインモデル（Incident / CauseAnalysis / PreventiveMeasure など）
- `src/IncidentInsight.Web/Data/`: `ApplicationDbContext` とシード/監査インターセプタ
- `src/IncidentInsight.Web/Services/`: 再発検出などのドメインサービス
- `src/IncidentInsight.Web/Authorization/`: 部署スコープなどの認可

### コンポーネント関係

```mermaid
flowchart TB
    Browser["ブラウザ<br/>Bootstrap 5 + Chart.js 4"]

    subgraph Web["ASP.NET Core 8 MVC"]
        direction TB
        Controllers["Controllers<br/>Home / Incidents<br/>CauseAnalyses / IncidentMeasures<br/>PreventiveMeasures / Analytics / Account"]
        Services["Services<br/>RecurrenceService / IClock"]
        Auth["Authorization<br/>SameDepartmentHandler"]
        Data["Data<br/>ApplicationDbContext<br/>AuditSaveChangesInterceptor<br/>DbSeeder"]
        Models["Models<br/>Incident / CauseAnalysis<br/>CauseCategory / PreventiveMeasure<br/>AuditLog"]
    end

    DB[("DB<br/>SQLite / SQL Server / PostgreSQL")]

    Browser <-->|HTTPS| Controllers
    Controllers --> Services
    Controllers --> Auth
    Controllers --> Data
    Services --> Data
    Auth --> Data
    Data --> Models
    Data <--> DB
```

### データモデル（ER図）

`Incident` を中心に、`CauseAnalysis` と `PreventiveMeasure` がぶら下がり、`AuditLog` が変更を自動記録します。`CauseCategory` は親子階層を持つ自己参照テーブルです。

```mermaid
erDiagram
    Incident ||--o{ CauseAnalysis : "原因分析"
    Incident ||--|{ PreventiveMeasure : "再発防止策(必須1件以上)"
    CauseAnalysis }o--|| CauseCategory : "分類"
    CauseCategory ||--o{ CauseCategory : "親子階層"

    Incident {
        int Id PK
        DateTime OccurredAt
        string Department
        string IncidentType
        string Severity "Level0..Level5"
        string Description
        string ReporterName
        Guid ConcurrencyToken
    }
    CauseAnalysis {
        int Id PK
        int IncidentId FK
        int CauseCategoryId FK
        string Why1
        string Why2
        string Why3
        string Why4
        string Why5
        Guid ConcurrencyToken
    }
    PreventiveMeasure {
        int Id PK
        int IncidentId FK
        string Status "Planned|InProgress|Completed"
        DateTime DueDate
        int EffectivenessRating "1-5"
        bool RecurrenceObserved
        Guid ConcurrencyToken
    }
    CauseCategory {
        int Id PK
        int ParentId FK
        string Name
        int DisplayOrder
    }
    AuditLog {
        long Id PK
        DateTime ChangedAt
        string ChangedBy
        string EntityName
        string EntityKey
        string Operation "Added|Modified|Deleted"
        string ChangesJson "PHIはRedact/Hash済み"
    }
```

### 再発防止策のライフサイクル

`PreventiveMeasure.Status` は `Planned → InProgress → Completed` を経て、有効性評価で再発が確認された場合は新たな対策計画に戻ります。`DueDate < 今日 かつ Status != Completed` のときは `IsOverdue` 計算プロパティが立ち、UI で警告表示されます。

```mermaid
stateDiagram-v2
    [*] --> Planned: 計画作成
    Planned --> InProgress: 着手
    InProgress --> Completed: 完了報告
    Completed --> EffectivenessReviewed: 有効性評価<br/>(1〜5段階)
    EffectivenessReviewed --> [*]: 再発なし
    EffectivenessReviewed --> Planned: 再発あり<br/>(新たな対策が必要)
```

### 主要な設計ポイント

- **3ステップ登録フロー**: 基本情報 → なぜなぜ分析 → 再発防止策、の順で入力を段階化。
- **再発検出**: 同部署・同種別・同原因分類の複数発生を検知して警告。
- **監査ログ**: 更新の追跡を `AuditSaveChangesInterceptor` で一元化。

