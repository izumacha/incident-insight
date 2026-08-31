# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> このファイルの **§4 以降（共通規約 ＋ 付録）は原本テンプレート `izumacha/claude-code-rules` の
> `CLAUDE.md` と同期**している。共通規約を変更するときは、**まず原本を改訂してから**各リポジトリへ
> 反映すること（このファイルで共通規約だけを勝手に書き換えない）。§1〜§3 は本リポジトリ固有の内容。

---

## 1. プロジェクト概要

IncidentInsight は医療インシデント管理システム（ASP.NET Core 8 MVC + EF Core 9）。報告 → なぜなぜ分析（5 Whys）→ 予防策立案 → 完了 → 効果評価 → 再発検知までのライフサイクルを扱う。UI 文字列とドメイン語彙は日本語（`重症度`, `なぜなぜ分析`, `再発防止策` 等）。

アプリは**DB プロバイダ非依存**: SQLite（既定・単一ファイル）/ SQL Server（オンプレ Windows）/ PostgreSQL（Linux・クラウド・Supabase 等）を `Database:Provider` 設定で実行時切替する。モデル・クエリにプロバイダ固有 SQL／列型を持ち込まないため、同一コードベースでどこへでも配備できる。

## 2. コマンド

```bash
# ビルド（ソリューション全体）
dotnet build

# Web アプリ起動（初回起動で SQLite DB 作成＋シード）
# 待受 URL はハードコードせず、起動ログの「Now listening on:」か launchSettings.json の
# applicationUrl（例: http://localhost:32562 / http://localhost:5093）を見る。
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj

# 全テスト（xUnit）
dotnet test

# 単一テストクラス / メソッド
dotnet test --filter "FullyQualifiedName~IncidentsControllerTests"
dotnet test --filter "FullyQualifiedName=IncidentInsight.Tests.Controllers.IncidentsControllerTests.Create_Post_WithoutMeasures_ReturnsCreateView_AndDoesNotSaveIncident"

# モデル変更後の EF Core マイグレーション追加（起動時 Database.Migrate() で自動適用）
# 注: コミット済みマイグレーションは既定プロバイダ(SQLite)向け。SQL Server / PostgreSQL 本番に
#     切替える場合は Migrations/ を削除し Database__Provider と接続文字列を設定して再生成する。
dotnet ef migrations add <MigrationName> --project src/IncidentInsight.Web

# ローカルログイン用デモアカウントのシード（Development のみ。パスワードはコミットしない）
dotnet user-secrets init --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:AdminPassword" "AdminPass1" --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:RiskManagerPassword" "RiskPass1" --project src/IncidentInsight.Web
```

Dev パスワードポリシー: 8 文字以上・大文字・数字。Prod: 12 文字以上・非英数字含む（`Program.cs`）。`SeedAccounts` は Development のみシードし、空なら警告ログを出してスキップする。

## 3. アーキテクチャ

### リクエストパイプライン / 起動（`Program.cs`）

- `ApplicationDbContext` は `Database:Provider`（`sqlite` | `sqlserver` | `postgres`）で実行時プロバイダ切替。接続文字列は `ConnectionStrings:DefaultConnection`。`UseSqlite` / `UseSqlServer` / `UseNpgsql` を使い分け、移行はコード変更不要（設定のみ）。
- `AuditSaveChangesInterceptor` を `DbContext` に登録（プロバイダ中立）。`Incident` / `CauseAnalysis` / `PreventiveMeasure` の Add/Modify/Delete ごとに `AuditLogs` 行を書き、Modified では `ConcurrencyToken` Guid を回転させる。
- ASP.NET Core Identity を `ApplicationUser` ＋ 3 ロール（`AppRoles`: `Admin` / `RiskManager` / `Staff`）で構成。Cookie 認証は `/Account/Login` リダイレクト、8h スライディング、5 回失敗でロックアウト。
- 起動時（スコープ内）: `db.Database.Migrate()` → `DbSeeder.Seed(db)`（原因分類マスタ・冪等・全環境）→ `DbSeeder.SeedDemoData(db, clock)`（デモインシデント・Development のみ）→ `IdentitySeeder.SeedAsync(...)`（ロールは常時、デモ管理者/RM は Development かつ `SeedAccounts` パスワード有時のみ）。

### DB プロバイダ・マトリクス

| 配備先 | `Database:Provider` | 接続文字列の例 |
|---|---|---|
| 単一クリニック / dev（既定） | `sqlite` | `Data Source=incident_insight.db` |
| オンプレ病院（Windows / 既存 SQL Server） | `sqlserver` | `Server=...;Database=IncidentInsight;Trusted_Connection=True;TrustServerCertificate=True;` |
| Linux / 自前 Postgres | `postgres` | `Host=...;Database=incidentinsight;Username=...;Password=...` |
| マネージド（Supabase / Azure DB / Aurora） | `postgres` | プロバイダ標準の Postgres 接続文字列 |

設定は `appsettings*.json` か環境変数（`Database__Provider`, `ConnectionStrings__DefaultConnection`）。

### ドメインモデル（`src/IncidentInsight.Web/Models/`）

4 つの集約に `OnModelCreating` でカスケードを設定:

- **`Incident`**（ルート）— 発生メタデータを保持。重症度コード（`Level0`…`Level5`）・部署一覧・インシデント種別一覧は `Incident` クラスの `static readonly` 辞書/配列が**唯一の真実の源**（ドロップダウン/ラベル）。`SeverityLabel` / `SeverityColor` / `MeasureStatusSummary` 等の計算プロパティを Razor で直接使う。
- **`CauseAnalysis`** — 5 Whys を独立列 `Why1`..`Why5` で保持（深さ別検索のため）。常に 1 つの `CauseCategory` に紐づく。`DeepestWhy` / `WhyDepth`。
- **`CauseCategory`** — `ParentId` による自己参照階層。`BuildCauseCategoryOptionsAsync()`（`Controllers/Internal/IncidentControllerHelpers.cs`）が leaf を parent ごとに `<optgroup>` で出力。これをバイパスするカテゴリピッカーを作らない。
- **`PreventiveMeasure`**（ドメイン最重要）— `Planned → InProgress → Completed` と完了後フィールド（`EffectivenessRating` 1–5, `EffectivenessNote`, `EffectivenessReviewedAt`, `RecurrenceObserved`）。`IsOverdue`（`DueDate < DateTime.Today && Status != "Completed"`）の意味を一貫させる。
- **`AuditLog`** — 規制対応の監査証跡。`AuditSaveChangesInterceptor` が自動で書く。**このテーブルに直接書かない**（インターセプタが唯一の源）。

`Incident` / `CauseAnalysis` / `PreventiveMeasure` は `ConcurrencyToken`（Guid, `[ConcurrencyCheck]`）を持つ。**Edit POST 契約**: `FindAsync` で再読込後、クライアントの編集前トークンを `OriginalValue` に明示ピンしてから保存し、`DbUpdateConcurrencyException` を捕捉する:

```csharp
_db.Entry(entity).Property(nameof(Entity.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;
try { await _db.SaveChangesAsync(); }
catch (DbUpdateConcurrencyException) { TempData["Warning"] = "..."; return ...; }
```

トークンは hidden field（`<input type="hidden" asp-for="ConcurrencyToken" />` 等）で round-trip する。インデックス: `Incident(OccurredAt)`, `Incident(Department, IncidentType)`, `PreventiveMeasure(Status, DueDate)`, `CauseCategory(ParentId, DisplayOrder)`, `AuditLog(ChangedAt)`, `AuditLog(EntityName, EntityKey)`。

### コントローラ / 横断パターン

- 全コントローラ(`AccountController` 含む)がクラス既定 `[Authorize]`(fail-closed)。`AccountController` は `Login` / `AccessDenied` / `Logout` のみアクション単位の `[AllowAnonymous]`(`Logout` はクッキー失効後の 405 デッドエンド防止)。
- インシデントのライフサイクルは `/Incidents/...` 配下の**3 コントローラ**に分割:
  - `IncidentsController` — Index/Details/Create/Edit/Delete。Create は `HasAtLeastOneValidMeasure`（業務必須）を強制。`Edit` で親フォーム検証前にサブフォームキーを `ModelState.Remove` で除去。
  - `CauseAnalysesController` — `AddCauseAnalysis` / `EditCauseAnalysis` / `DeleteCauseAnalysis`。`[Route("Incidents/[action]/{id?}")]` で URL を維持し、`View("~/Views/Incidents/EditCauseAnalysis.cshtml", vm)` を再利用。
  - `IncidentMeasuresController` — `AddMeasure` / `CompleteMeasure` / `RateMeasure`（詳細ページからのインライン操作）。kanban 側の `Create`/`Edit`/`Complete`/`Review`/`UpdateStatus`/`Delete` は `PreventiveMeasuresController`。
- 共有ヘルパー（カテゴリドロップダウン生成・リソースポリシー評価）は `Controllers/Internal/IncidentControllerHelpers.cs`。**業務ルールはここに置かない**（`HasAtLeastOneValidMeasure` 等は所有コントローラに残す）。
- 移動したアクションの Tag Helper は `asp-controller="CauseAnalyses"` / `asp-controller="IncidentMeasures"` を指定する（URL は `/Incidents/...` のままだがルート解決に必要）。
- `AnalyticsController` は Chart.js 用 JSON（`{ labels, data }` 形状を変えない）。
- `HomeController.Index` はダッシュボード。`period`（`week`|`month`|`quarter`|`year`、既定 `year`）で KPI・トレンド・**再発アラート**（同部署＋同種別＋原因カテゴリ重複、直近 90 日。90 日窓は `period` から独立）を計算。
- 成功/警告トーストは `TempData["Success"]` / `TempData["Warning"]`。

### ビュー / フロント

- Razor ビューはコントローラ名に対応（`src/IncidentInsight.Web/Views/`）。重症度/状態バッジは Model の計算 `*Color` プロパティ（Bootstrap カラー名）を使い、View に直書きしない。
- Bootstrap 5 / Bootstrap Icons / jQuery Validation Unobtrusive / Chart.js 4 は CDN から SRI 付きで読み込む（バンドラは無し）。
- **アプリ固有の JS は TypeScript で書く。** `src/IncidentInsight.Web/Scripts/**/*.ts` を `tsc`（`tsconfig.json`, `strict: true`）が `wwwroot/js/` へ出力し、`.csproj` の `CompileTypeScript` ターゲットが `dotnet build` 時に実行する（`wwwroot/js/*.js` は生成物なので gitignore 済み）。型チェック単独は `npm run typecheck`。
- **ページ固有のスクリプトは inline `<script>` に書かない。** Razor からデータを渡すときは `<script type="application/json" id="...-data">` のデータ島に埋め、対応する `Scripts/<page>.ts` が IIFE で読み取る（`Home/Index.cshtml` ↔ `dashboard.ts`、`Analytics/Index.cshtml` ↔ `analytics.ts`）。inline script は tsc の型チェックを受けられず、`SecurityHeadersMiddleware` が CSP を導入する際の障害にもなる。ルート直書き（`/Analytics/...`）ではなく `Url.Action` の結果をデータ島経由で渡す（PathBase 付き配備で 404 にしないため）。
- **JS から DOM へ値を流し込むときは `textContent` を使う**（`innerHTML` でのマークアップ組み立てを避ける。§9）。表示の骨組みは Razor 側に静的に置き、JS は値だけを差し替える。フェッチ失敗時は「読み込み中」表示のまま放置せず、確定した失敗表示へ切り替える（§7）。

### テスト（`tests/IncidentInsight.Tests/`）

- xUnit / `net8.0`。`Microsoft.EntityFrameworkCore.InMemory` をテストごとに `Guid.NewGuid()` 名で使う。`TempData` を使うコントローラには `TestTempData` を注入。**Mock より `InMemory` を優先**し、新エンティティを読む/書くロジックを足したら対応 `*ControllerTests` の InMemory セットアップを拡張する。`UserContextHelper.AttachUser()` でユーザーコンテキストを設定。

### 注意点（固有の不変条件）

- **マイグレーションは起動時 `Database.Migrate()` で自動適用** — モデル変更は同一変更セットでマイグレーションを追加する。
- **ロックファイルは全プロジェクト分を同時に再生成する** — `packages.lock.json` は `src/IncidentInsight.Web` と `tests/IncidentInsight.Tests` の 2 つある。テストプロジェクトは web を `ProjectReference` で参照しているため、**web の依存が動くとテスト側の解決結果も動く**。片方だけ更新すると CI の `dotnet restore --locked-mode` が `NU1004: The project references incidentinsight.web whose dependencies has changed` で落ちる。**とくに Dependabot の nuget PR は `src/` 側しか更新しないので、そのままではマージできない**（実例: PR #180 → #181 で手当て）。取り込むときは `dotnet restore` を流して 2 ファイルとも再生成し、同一コミットに含める。ロックファイルを持つプロジェクトを増やしたときも同じ（`RestorePackagesWithLockFile` を宣言し忘れたプロジェクトは locked-mode restore も `EfCorePackageAlignmentTests` の検査もすり抜けるため、同テストが宣言漏れ自体を検出する）。
- **`HasAtLeastOneValidMeasure` をバイパスしない**（インシデントは予防策が最低 1 件ないと登録不可）。
- **重症度/部署/インシデント種別の enum は `Incident` クラス上**（DB ではない）。値追加は static 辞書/配列＋それを回す View を更新（マイグレーション不要）。enum の日本語ラベルと Bootstrap カラーは `Models/Enums/EnumLabels.cs` に集約し、`EnumLabels.Japanese()` と `EnumLabels.Color()` の両方を更新。`IncidentTypeMapping.cs` が日本語↔DB 文字列の双方向変換を担う。
- **再発ロジックは `IRecurrenceService`**（`Services/RecurrenceService.cs`）に集約。`HomeController.Index`（90 日窓 `FindRecurrenceAlertsAsync`）と `IncidentsController.Details`（時間無制限 `FindRecurrencesForIncidentAsync`）が委譲。マッチャ `RecurrenceDetector.FindSimilar` は純粋関数。ルール変更時はサービスとそのテストを更新。
- **監査ログの正しさは `SaveChanges` 経由が前提** — `Incident` / `CauseAnalysis` / `PreventiveMeasure` に `ExecuteUpdate` / `ExecuteDelete` を使わない（変更追跡を迂回し監査漏れになる）。
- **PHI を `AuditLog.ChangesJson` に平文で残さない** — 自由記述・個人名カラムには `[Sensitive(Mask.Redact)]` か `[Sensitive(Mask.Hash)]`（`Models/Auditing/SensitiveAttribute.cs`）を付与。インターセプタが `[REDACTED]` か HMAC-SHA256 擬似匿名化（鍵 = `Audit:HashSalt`）に置換。**新しい自由記述/個人名カラムは必ず annotate**。本番で `Audit:HashSalt` 空は起動失敗。salt ローテーションは過去ハッシュとの相関を失うので runbook に記録。
  - **付け忘れは「無印を許さない」形で機械的に検出する** — `SerializeChanges` は `[Sensitive]` が**無い**プロパティの値をそのまま `ChangesJson` へ書くため、annotate を忘れた列は**ビルドも全テストも緑のまま**平文の PHI を監査テーブルへ流し込む（`AuditLog` は追記専用でインターセプタが唯一の書き込み源なので、後から気付いても書かれた行は消せない）。無印が「安全だと判断した」と「判断し忘れた」の両方を意味する限り付け忘れは検出できないので、**監査対象 3 集約の永続化される `string` 列は `[Sensitive(...)]` か `[NotPhi("理由")]`（`Models/Auditing/NotPhiAttribute.cs`）のどちらかを必ず持つ**ことを `AuditedEntityPhiClassificationTests` が固定する（分類漏れ／両方付与／**shadow property** の 3 つを検出）。検査は CLR のリフレクションではなく **EF Core のモデル（`DbContext.Model`）を読む** — インターセプタが走査するのは `EntityEntry.Properties` なので、計算プロパティ（`SeverityLabel` 等）を誤検出せず shadow property も取りこぼさない。`[NotPhi]` は理由が必須（空文字・空白は実行時例外）で、「とりあえず検出網を黙らせる」使い方を塞いでいる。現在の除外は 5 件で、いずれも閉じた語彙（`Incident.Department` / `Incident.Severity` / `Incident.IncidentType` / `PreventiveMeasure.Status` / `PreventiveMeasure.MeasureType`）。
  - **「string 列」の判定は「CLR の型が `string`」と「DB へ文字列として保存される」の和集合** — どちらか一方への置き換えにすると、外れた側が誰にも見られない列になる。**本命は CLR 側**で、`SerializeChanges` が `ChangesJson` へ書くのは `prop.CurrentValue` / `OriginalValue`＝**変換前の CLR の値**だから（自由記述列に暗号化の値変換 `string → byte[]` を足すと「文字列として保存されない」列になるが、監査ログへ流れるのは相変わらず平文の `string`）。一方で `HasConversion` を通す enum 列は CLR が enum のままなので、CLR 側だけでも足りない。しかも**変換後の型が現れる場所は書き方によって違う**（実測）: `HasConversion<string>()` は `GetProviderClrType()` に出て `GetValueConverter()` は `null`（`Severity` / `Status` / `MeasureType`）、`HasConversion(v => …, v => …)` は逆（`IncidentType`）。`AuditedEntityModel.IsStringColumn` がこの 3 つすべてを見る。
  - **shadow property（CLR プロパティを持たない列）は禁止する** — `LookupSensitiveMask` は CLR プロパティに付いた `[Sensitive]` を読むため、shadow の `string` 列は**原理的にマスクできず必ず平文で** `ChangesJson` へ書かれる。分類漏れの対処法は「属性を付ける」だが shadow の対処法は「CLR プロパティへ昇格させる」で別物なので、専用の検査（`PersistedStringColumns_MustHaveBackingClrProperty`）が固有のメッセージで落とし、他の 2 つの検査は shadow 列を対象から外す。実行不能な指示を出す検出網は、いずれ「直せないので検査を緩める」方向へ倒れるため。
  - **長さ上限の検査対象は「`[Sensitive]` 付きの列」ではなく永続化される文字列列すべて** — `FreeTextMaxLengthAttributeTests` が上限の付け漏れを落とす。以前は `[Sensitive]` 付きだけを見ていたが、**分類の選択肢に `[NotPhi]` が増えた時点でそれが穴になった**（`[NotPhi("...")]` だけ付けて `[MaxLength]` を書き忘れると両テストとも緑のまま無制限の列が通り、しかも `[NotPhi]` 列は定義上マスクされないので無制限の値が監査ログへ平文で積まれる）。**エスケープハッチを足すと既存の検出網がその分だけ黙って狭くなる**ので、条件は分類の種類に依存させず「列であること」に置く。上限の判定も `[MaxLength]` 属性ではなく **EF のモデルの `GetMaxLength()`** を読む（DB の列長を決めているのはモデル側の値で、fluent の `HasMaxLength()` で設定した列を「上限なし」と誤判定しないため）。
  - **監査対象の一覧を読む側は必ず `AuditSaveChangesInterceptor.AuditedEntities` から導出する** — 現在の導出先は `AuditLogsController.AllowedEntityNames`（フィルタ許可リスト＋ドロップダウン）と 2 つのテスト（`AuditedEntityPhiClassificationTests` / `AuditEntityLabelCoverageTests`）。**長さ上限まわりの検査は監査対象から導出しない**（下記）。写しを持つと、監査対象を足したときにインターセプタだけが増えて写し側が取り残される。とくに `AllowedEntityNames` の取り残しは **fail-open**（`Contains` が false になって絞り込みが黙って外れ全件返る）＋**画面から到達不能**（ドロップダウンに出ない）の二重のずれを同時に起こす。`AuditedEntities` は集合ではなく**順序付きの `IReadOnlyList`** で、並びはドメインの順（ルート集約のインシデントが先）＝そのままドロップダウンの表示順。導出先で並べ替えない（型名の序数順にすると、日本語 UI の並びが英語の識別子の綴り順という無意味な順になる）。順序を持たせた代わりに重複が書けてしまうので、`AuditedEntities_HasNoDuplicates` が固定する。
  - **導出できない写しが 1 つだけ残っている: `EnumLabels.AuditEntityJa`（日本語ラベルの変換表）** — `JapaneseAuditEntity` は辞書に無いキーを**元の値のまま返す**フォールバックを持つため、ラベルを書き忘れても例外にならず、監査ログ画面の 3 箇所（ドロップダウン／一覧の各行／詳細）に CLR の型名が英語のまま出る。フォールバック自体は残す（監査対象から外したエンティティの過去行を表示するとき、例外で画面を落とすより安全）ので、代わりに `AuditEntityLabelCoverageTests` が「ラベル表は監査対象を全網羅する」ことを固定する。
  - **長さ上限の値は `[MaxLength]` 属性でも fluent の `HasMaxLength()` でも `FieldLengths` の定数を使う** — 上限の**充足**は EF のモデルで判定するので fluent でも通るが、そのぶん fluent が「裸の数値の抜け道」になる（上限はある＝緑、でもその値は誰も見ていない）。`FieldLengthsTests` は属性側（`EveryMaxLength_UsesAFieldLengthsConstant`）とモデル側（`EveryModelMaxLength_UsesAFieldLengthsConstant`）の**両方**を見る。許容値は**意図的に別集合**にしてある: 属性側は `{FreeText, ShortText}` だけ、モデル側はそれに `{EnumCode, EnumCodeJapanese}` を足したもの。共有すると属性側が黙って緩み、ViewModel の入力欄に裸の `[MaxLength(20)]` / `[MaxLength(50)]` を書いても「`FieldLengths` の定数だ」として通ってしまう（この 2 つは値変換した enum 列にしか意味を持たない）。モデル側の対象は `AuditedEntityModel.LengthGovernedEntityTypes()`＝**「自分たちのアセンブリで定義されたマップ済みエンティティ」から `AuditLog`（監査証跡スキーマ固有の列長）を除いたもの**で、判定は CLR プロパティの有無を問わず全文字列列に掛ける（属性を読まない検査なので shadow 列も対象にできる）。属性側の対象は型名を書き並べず、**「自分たちのアセンブリで長さ上限の属性を 1 つでも宣言している型」**から導出する（エンティティも ViewModel も同じ条件で拾う。名前空間や `"ViewModel"` という接尾辞に依存しないので、置き場所や命名を変えても対象から外れない）。
  - **「長さ上限の属性」は `[MaxLength]` だけではない** — `[StringLength]` と .NET 8 の `[Length(min, max)]` も MVC の入力検証（`[StringLength]` は EF の列長も）が尊重するので、`[MaxLength]` だけを見ると**綴りを変えるだけの抜け道**になる。実測でも ViewModel に `[StringLength(200)]` / `[Length(1, 200)]` を書くと全件緑のまま通り、裸の数値も `ErrorMessage` の指定漏れ（＝日本語 UI に英語の既定メッセージ）も素通りした。しかも後者はテスト件数すら変わらないので痕跡がゼロ。**属性の解釈は `FieldLengthsTests.ReadLengthLimit` の 1 か所に集約し、DataAnnotations に長さ上限の属性が増えたらそこへ足す**（名前空間・型名の接尾辞への依存をやめたのと同じ理由で、属性名への依存も残さない）。属性は `inherit: true` で読む（基底で宣言し派生で `override` した列を「属性なし」と誤判定すると、fluent の `HasMaxLength()` との食い違いが黙って素通りする）。
  - **長さ上限の管理範囲を監査対象から導出しない** — 「どのエンティティを監査するか」と「どのエンティティの列長を管理するか」は別の関心事で、前者から後者を導くと**監査ポリシーの変更が無関係な長さ管理まで黙って外す**（あるエンティティを監査対象から外した瞬間、裸の `[MaxLength(200)]` も上限の付け忘れも値変換列の切り詰めもまとめて素通りになる。すべて fail-open）。アセンブリベースで導出するので新しいエンティティは何もしなくても検査対象に入る。実際この分離で `CauseCategory.Description` が**上限なしのまま残っていた**のを検出し、`FieldLengths.FreeText` を付けた（同一変更セットでマイグレーション追加。SQLite は TEXT に長さ制約が無いため本体は空で、スナップショットへの記録が目的）。
  - **導出の条件は「名前空間の完全一致」ではなく「所属アセンブリ」にする** — 長さ上限の検査は 4 つ（裸の数値の禁止・上限の付け忘れ・値変換列の切り詰め・その網羅ガード）あるが、対象範囲は `LengthGovernedEntityTypes()` の 1 か所が決めている。**この導出が 1 つでもエンティティを取りこぼすと、そのエンティティは 4 つすべてから同時に、しかも黙って外れる**（すべて fail-open）。以前の `t.Namespace == "IncidentInsight.Web.Models"` は文字列の完全一致で、この repo は既に `Models/Enums` / `Models/Auditing` / `Models/Validation` 等のサブフォルダを持つため、**エンティティを 1 つサブフォルダへ移すだけ**で一致しなくなる。実測でも「導出集合から外れ、同時にその列の `[MaxLength]` が消える」変異が**全件緑のまま通った**（唯一の痕跡はテスト件数が 496 → 490 に減ることだけで、正当なリファクタと見分けが付かない）。アセンブリ単位なら名前空間をどう切り直しても外れない。**エンティティ単位の除外は `AuditedEntityModel.LengthGovernanceExclusions`（理由付きの表）だけ**で、現在の登録は `AuditLog` の 1 件。この表が意図的な除外の唯一の真実の源で、導出・網羅ガード・属性側の対象導出の 3 つが同じここを読む（写しを持つと、どちらへ除外を足しても片方が取り残される。実測でも、ガード側の表にだけ登録した型はモデル側 3 検査から除外されず、「除外したはずの型」で検査が落ちた）。**`ApplicationUser` を `IdentityUser` 派生として型ごと除外してはいけない**（下記の列単位の項を参照）。
  - **除外は「エンティティ単位」ではなく「列単位」で切る** — `ApplicationUser` を型ごと外すと、`DisplayName`（個人名）と `Department`（`Incident.Department` と同じ語彙）まで巻き添えで長さ管理から永久に外れる（実際この 2 列は上限なし＝SQL Server なら `nvarchar(max)`、PostgreSQL なら `text` のまま残っていた）。列長を Identity が決めるのは **Identity 自身が宣言した列**（`UserName` / `Email` / `PasswordHash` など）だけなので、`AuditedEntityModel.IsDeclaredInOwnAssembly`（宣言元の型が自アセンブリか）で列単位に切る。判定を 1 か所に置くのは、この絞り込みを使う検査が 4 つあり、各検査が `DeclaringType?.Assembly == …` を書き写すと条件を直したときに片方だけ取り残されるため。shadow 列は宣言元をたどれないが自分たちのモデル由来なので**残す**。
  - **上限の付け忘れを見る検査も shadow 列を対象にする** — 以前は `ClrBackedStringColumns` に絞り「shadow は `AuditedEntityPhiClassificationTests` が専用の対処法で落とす」としていたが、その検査の対象は**監査対象 3 集約だけ**。監査対象でない `CauseCategory` へ上限なしの shadow 列（`Property<string>("...")`）を足すと、4 つの検査すべてを素通りした（実測で全件緑）。上限の検査は属性を読まないので shadow 列も対象にできる。
  - **導出が効いているかは独立な手がかりで照合する** — `FieldLengthsTests.LengthGovernedTypes_CoverEveryOwnedDbSet` が、導出とは別の宣言箇所である **(a) `ApplicationDbContext` が自分で宣言した `DbSet<T>`**（`BindingFlags.DeclaredOnly` ＋ 自アセンブリの基底までを走査。Identity が宣言する `Users` / `Roles` を拾わず、将来 `DbSet` を自前の中間基底へ移しても追随する）と **(b) 基底の総称 DbContext へ自分たちが渡した型引数**（`IdentityDbContext<ApplicationUser>` の `ApplicationUser`）の両方と突き合わせ、管理対象でも「意図的な除外」でもないエンティティがあれば落とす。**(b) が要る**のは、`ApplicationUser` が Identity 側の `DbSet`（`Users`）で公開されるため (a) の `DeclaredOnly` に掛からないから — (a) だけだと、導出へ `IdentityUser` 派生の除外を戻すと `ApplicationUser` が長さ関連 4 検査から同時に消えるのに全件緑のまま通った（実測 504 → 500。痕跡はテスト件数の減少だけ）。同じ経路でガードを書くと導出が狭まったときにガードも一緒に狭まり「取りこぼしゼロ＝緑」で無力化されるため、**手がかりを変える**のが要点。`DbSet` を 1 つも読めない場合も「見るべき対象ゼロ＝緑」を避けるため fail-closed で落とす。意図的な除外は `AuditedEntityModel.LengthGovernanceExclusions`（**完全修飾名をキーにした理由付きの表**。単純名だと将来同じ単純名のエンティティを足したときに巻き添えで外れる）に登録する。この表には 3 つの検査が掛かる: `LengthGovernanceExclusions_AreAllStillReal`（キーが EF のモデル上に実在する）/ `LengthGovernanceExclusions_AllHaveAReason`（理由が空・空白でない。値を誰も読んでいなかったため、理由を `"   "` にすれば 4 検査すべてを黙らせられた）/ `LengthGovernanceExclusions_CannotDropIdentityBackedEntities`（手がかり (b) の型＝`ApplicationUser` は載せられない。もっともらしい理由で登録して `[MaxLength]` を消すと全件緑のまま通ったため）。
  - **残っている境界: 除外表そのものは人が判断するエスケープハッチ** — `AuditLog` を除外してよい理由は「列長の出所が `FieldLengths` ではない」ことだが、これを機械判定に落とすことはできない。「除外した型は全列に上限がある」を条件にする案は `AuditLog.ChangesJson` が**意図的に無制限**（JSON 本文なので `nvarchar(max)` / TEXT 相当）なので成立しない。したがって、DbSet で公開している業務エンティティ（`Incident` / `CauseAnalysis` / `PreventiveMeasure` / `CauseCategory`）をもっともらしい理由付きで登録し、同時にその列の `[MaxLength]` を消すと、4 検査すべてから外れて**全件緑のまま通る**（実測。痕跡はテスト件数の減少だけ）。`Microsoft.Data.SqlClient` のピンと同じく**期待値を機械化しない代わりにレビューで見る**箇所なので、**この表にエントリが増える差分は、理由の妥当性をレビューで必ず確認する**。
  - **`[MaxLength]` と fluent の `HasMaxLength()` を両方書くなら値を一致させる** — fluent が優先されるため、食い違うと「画面は属性の上限で検証し、DB は fluent の上限で作られる」層またぎのずれになる。上限の**充足**をモデルで判定する以上どちらも「上限あり」で緑になるので、一致そのものを `ModelMaxLength_AgreesWithMaxLengthAttribute` が固定する。
  - **値変換で文字列として保存する列は、実際に保存しうる値がすべて収まる長さにする** — 上の検査が裸の数値を禁じることで `FieldLengths.EnumCode` の使用を積極的に誘導するため、定数が実際の値より短いと誘導に従った結果として切り詰めが起きる。壊れ方は**プロバイダ依存**（SQL Server / PostgreSQL は例外、SQLite は黙って保存、テストの InMemory は列長の概念すら無い）で、**ビルドも全テストも緑のまま特定の配備先でだけ壊れる**。`ConvertedEnumColumnLengthTests` が、変換器を実際に通した文字列（`HasConversion<string>()` なら enum 名、ラムダ変換なら変換結果）の長さを上限と突き合わせて固定する。**検査範囲は誘導する検査と同じ**にする（誘導する範囲より検証する範囲が狭いと、その差分がそのまま死角になる）。あわせて `EveryLengthLimitedEnumColumn_IsActuallyExamined` が「見るべき列を全部見たか」を**判定とは独立な手がかり**（enum 型でかつ長さ上限を持つ永続化列）で照合する — 同じ判定でガードを書くと、判定が狭まったときにガードも一緒に狭まって「違反ゼロ＝緑」で無力化されるため。文字列として保存する enum 列の上限は `FieldLengths.EnumCode`（20）と `FieldLengths.EnumCodeJapanese`（50。`IncidentType` は日本語の DB 文字列を保存するため）。
- **時刻は常に `IClock`**（`Services/IClock.cs`、JST）。`DateTime.Now/Today/UtcNow` を直接呼ばない。永続業務タイムスタンプと `AuditLog.ChangedAt` は運用ローカル時刻(JST)で保存。新規 View では `@inject IClock Clock` ＋ `Clock.Today` を使う。
- **EF Core 本体とプロバイダ実装はメジャー版を全プロジェクトで揃える** — プロバイダ実装（Sqlite / SqlServer / Npgsql）は EF Core の内部 API に結び付くため、本体と同じメジャー版でしか動作保証がない。一方 `Microsoft.AspNetCore.Identity.EntityFrameworkCore` と `Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore` は公開 API しか使わず、メジャー版は .NET のリリース（`net8.0` → `net9.0`）に追随する（9.0.0 は `net9.0` 専用）ため、この規則の対象外にしている（束ねると EF Core 9 への更新が復元不能になる）。一部だけ上げてもビルドもテストも通る（テストは InMemory / SQLite しか触らない）ため、**PostgreSQL 配備でだけ実行時に壊れる**。Dependabot は `.github/dependabot.yml` の `nuget-ef-core`（通常の版更新）と `nuget-ef-core-security`（セキュリティ更新。`applies-to` の既定は version-updates なので別グループが要る）が major も含めて 1 本の PR に束ね、版ズレ自体は `EfCorePackageAlignmentTests` が検出する。検査は `packages.lock.json` の解決済み版を読む（壊れる主役は推移依存の `Relational` で、どの csproj にも直接書かれていないため）。「EF Core 系とは何か」の定義は dependabot.yml の `patterns` が唯一の真実の源で、名前に `EntityFrameworkCore` **または** `EFCore`（`EFCore.NamingConventions` 等）を含むパッケージがパターンから漏れていないことも同テストが固定する（上記 .NET リリース列の 2 つだけは理由付きで明示除外）。**プロバイダを足すときは 3 箇所（上記 2 グループの `patterns` と `nuget-minor-and-patch.exclude-patterns`）すべてに反映する。** 2 グループの `patterns` は集合として一致している必要があるが、`exclude-patterns` 側は書き方を問わず「EF Core 系を 1 つも拾わないこと」だけを求める。判定は文字列の一致ではなく、解決済みのパッケージ ID と `patterns` が表す範囲の代表値の両方が拾われないことで行う（`patterns` 側が前方一致 `"Foo*"` のときは、除外もその前置詞で始まるものをまるごと覆う必要があり、`"Foo"` と `"Foo.*"` のようにドット区切りの形を列挙する書き方では `FooBar` 等の同族が漏れるため足りない。完全一致のパターンは 1 つの ID しか指さないので、その ID を覆えていれば足りる）。そのため`"Npgsql*"` のように広く書くのは可、逆に `"Microsoft.EntityFrameworkCore*"` から末尾 `*` を落とすと（`.Sqlite` / `.SqlServer` / `.Relational` など既存のプロバイダ実装がその時点で漏れるため）通らない。広げすぎて上記 .NET リリース列の 2 つまで minor / patch の束ねから外すのも同テストが検出する。
- **SQL Server の ADO.NET ドライバ（`Microsoft.Data.SqlClient`）のメジャー版は EF Core の SqlServer プロバイダに合わせる** — このドライバは `Microsoft.EntityFrameworkCore.SqlServer` の実体で、動作保証があるのはプロバイダが宣言したメジャー版に対してだけ。ところが名前に `EntityFrameworkCore` / `EFCore` を含まないため上記の `nuget-ef-core` グループには入らず、メジャー更新が単独 PR として現れる（実際 PR #178 が 5.1.7 → 7.0.2 で出ていた）。**壊れ方は EF Core 本体とプロバイダの版ズレとまったく同じ**で、テストは InMemory / SQLite しか触らないため**ビルドも全テストも緑のまま通り、SQL Server 配備でだけ実行時に壊れる**。`.github/dependabot.yml` の nuget エコシステムの `ignore` が major 更新だけを保留し（minor / patch は csproj の「床値」を上げる更新なので止めない）、`EfCorePackageAlignmentTests` が 5 つを検出する: 解決版と EF Core 宣言版のメジャー不一致 / 床値の後退 / **ピンが直接参照でなくなること**（`packages.lock.json` の `type` が `Direct` から外れる = csproj のピン削除や推移依存への差し戻し）/ 保留の消失 / 保留の効きすぎ（`update-types` の欠落・`versions` の追加・重複エントリ）。**期待値はテストに書かず EF Core の宣言側（`packages.lock.json` の `dependencies`）から読む**ので、EF Core を上げれば検査が自動で追随する。**ただし「床値の後退」の比較相手はあくまで EF Core の宣言（現在 5.1.6）であって、csproj に書かれたピンの値ではない**——ピンを削除した場合は上記の `Direct` 検査が捕まえるが、**ピンの値を「EF Core の宣言版以上・現在のピン未満」の範囲（今なら 5.1.6 以上 5.2.3 未満、たとえば Dependabot の更新を revert して 5.1.7 に戻す変更）へ下げると 5 つすべてを素通りする**。床値検査が比べるのは EF Core の宣言であって直前のピンではないため、`5.1.7 >= 5.1.6` が成立してしまう。期待値を書かない方針と引き換えに残している穴なので、**ピンの値が下がる差分は（下げ幅の大小によらず）レビューで理由を確認する**。ドライバのメジャーを上げたいときは、それを宣言する版の `Microsoft.EntityFrameworkCore.SqlServer` へ同じ変更セットで上げる。
- **`SameDepartmentHandler`（`Authorization/SameDepartmentHandler.cs`）は `Incident` の eager-load が前提**。`PreventiveMeasure` / `CauseAnalysis` で `AuthorizeAsync` する前に `.Include(x => x.Incident)`。**fail-closed**（`Incident` が null なら拒否）。

### 新規 POST アクション追加時のチェックリスト

1. `[Authorize]`（または適切なポリシー）を付与。
2. `[ValidateAntiForgeryToken]` を付与（View には `@Html.AntiForgeryToken()`）。
3. `ConcurrencyToken` を hidden field で round-trip し `OriginalValue` にピン。
4. `SameDepartmentHandler` が必要なら `.Include(x => x.Incident)`（`IncidentControllerHelpers.IsAuthorizedForAsync` 経由でも同様）。
5. `SaveChangesAsync` を使い `ExecuteUpdate` / `ExecuteDelete` を使わない。
6. 成功時 `TempData["Success"]`、失敗時 `TempData["Warning"]`。
7. 新しい自由記述/個人名カラムには `[Sensitive(...)]` を付与（平文で残してよい列なら理由付きで `[NotPhi("...")]`。どちらも無い `string` 列は `AuditedEntityPhiClassificationTests` が落とす）。
8. 対応するテストを `tests/` に追加（`InMemory` DbContext 優先）。

### セキュリティ（固有事項）

- **部署スコープは Create/Edit でサーバ側強制**（issue #63）。Staff は自部署のみ登録/編集でき、フォームの部署値は `EnforceOwnDepartmentForStaff` で本人の `AppClaimTypes.Department` に上書き。Admin/RiskManager は全部署可。
- 認証 Cookie は `HttpOnly=true`, `SameSite=Strict`。Production は HTTPS リダイレクト＋HSTS 有効。
- **リバースプロキシ配下では `AllowedHosts` を実ホスト名に絞り、転送ヘッダを有効化**（issue #64）。既定 `"*"` のままにしない。`X-Forwarded-For` / `X-Forwarded-Proto` を信頼させるには `ForwardedHeaders:Enabled=true` ＋ `ForwardedHeaders:KnownProxies`。

### 見せ方（§15 の具体化）

- スタック形態は「DB/常駐サーバーが必要な Web」: README 冒頭のデモブロックは**デモ動画（GIF/mp4）必須**、公開 URL は任意（公開する場合は Render 等の無料枠＋PostgreSQL＋シードデータ＋定期リセットを整備してから。`Database:Provider=postgres` で切替可能）。
- 撮影対象スクリーンショット（`docs/screenshots/` 配下、シードデータのみ使用・PHI/実在の個人名厳禁）:
  1. `incident-list-default.png` — インシデント一覧（`/Incidents`）
  2. `incident-create-form.png` — 登録フォーム（なぜなぜ分析・予防策サブフォーム含む）
  3. `audit-log-list.png` — 監査ログ一覧（`/AuditLogs`）
  - 任意の追加候補: `dashboard-default.png` — ダッシュボード（KPI・再発アラート）
- デモ GIF: 「報告 → なぜなぜ分析 → 予防策 → 登録完了」の登録フロー 1 本（10MB 以下）。
- 撮影データは `DbSeeder.SeedDemoData`（Development のみ投入されるデモインシデント）＋Development のデモアカウント（§2）を使う。デモアカウントのパスワードをスクショに写さない。

---

## 4. 実装フロー（プランモード必須）

コード変更を伴う作業に着手する前に、**必ず Claude Code のプランモード（Plan Mode）で計画を作成し、ユーザーの承認を得てから実装に移る**こと。

- 対象: 機能追加・改修・リファクタ・バグ修正など、ソースコード／スキーマ／設定ファイルを変更するすべての作業。
- 計画には以下を含める:
  1. **Context**: 何を、なぜ変更するのか。正本（要件定義書・計画書）のどの項目に対応するか。
  2. **変更対象ファイル**: 修正・追加するファイルの絶対パス（既存ファイルは行番号や関数名まで具体化）。
  3. **再利用する既存実装**: 既にある関数・モジュール・Port を優先して再利用する。新規作成する場合はその理由を明記。
  4. **検証方法**: lint / typecheck / test（必要に応じて E2E）と、画面確認の手順。
- **例外**: タイポ修正・コメントのみの変更・1 行以下の自明な修正は計画作成を省略してよい。それ以外は必ず `ExitPlanMode` でユーザー承認を得る。
- 計画と異なる実装が必要になったら、いったん手を止めてプランを更新（または `AskUserQuestion` で確認）してから続行する。

## 5. コメント規約（最優先）

- **1 行ごとに初心者でも意味がわかるコメントを書く。** コード 1 行ごとに、プログラミング初心者でも処理内容が理解できる日本語コメントを付ける。変数宣言・条件分岐・関数呼び出し・ループ・`return` など、すべての実行行に対して「何をしているか」を説明するコメントを必ず添える（型定義の単純な再エクスポートなど明らかに自明な行は除く）。
- コメントは行の直前または行末に記述し、専門用語を使うときは平易な言い換えを併記する。
  - 例: `var x = users.Where(u => u.IsActive); // アクティブなユーザーだけを抜き出す`
- このルールは本方針固有であり、汎用的な「コメントは最小限に」というガイダンスよりも**優先**する。
- 言語別コメント記法: C# / JS / TS は `//`、Razor (`.cshtml`) は `@* *@`、JSON など非対応形式は対象外。

## 6. コーディング規約

- **既存コードのスタイルに合わせる。** インデント・命名・ファイル構成は周囲の慣習を踏襲する。
- **自己説明的な構成にする。** モジュールは単一責務に分割し、ファイル名・関数名から役割が推測できるようにする。公開関数には docstring / コメントで意図を残す。
- **設計判断を残す。** 非自明な実装やトレードオフには「なぜそうしたか」をコメントで残す。
- **定数・ラベルは一元管理する。** 配色・フォント・余白・UI 文言・enum ラベルなどは単一の参照元（例: `theme.py`, `constants.ts`, `EnumLabels.cs`, CSS の `:root` 変数）に集約し、各所に直書きしない。新しい値を追加したら参照元をすべて更新する。
- **マジックナンバー・マジック文字列を避ける。** 意味のある値（しきい値・キー名・パスなど）は名前付き定数にし、上記の一元管理に従って単一の参照元に置く。意図が読み取れない裸の数値・文字列をコードに散らさない。
- **重複を避ける（DRY）。** 同じロジックを書き写す前に既存の関数・モジュール・Port を探して再利用する（§4 のプラン段階で確認）。ただし将来を見越した過度な抽象化は避け、実際に 2〜3 箇所目で重複したら共通化する。
- **エラーを握り潰さない。** 例外は黙って捨てず、文脈を付けて再送出するかログに残す。空の `catch` / 裸の `except:` を作らない。回復不能な失敗は安全側に倒し（§9 の fail-closed）、ユーザーには内部詳細を含まない安全なメッセージを返す。
- **デッドコードを残さない。** 使われない import・変数・関数や、コメントアウトしただけの旧コードは削除する（履歴は Git に残る）。
- **変更は最小スコープに保つ。** 1 つの変更は単一の目的に絞り、無関係なリファクタや整形を同じ差分に混ぜない（§12 の「1 コミット = 1 論理変更」と整合）。レビューしやすい粒度を保つ。
- 言語別の補足:
  - **TypeScript**: `strict: true` を維持。`any` は禁止（不明なら `unknown`）。Props は `interface` で定義。パスエイリアス `@/*` → `src/*`。Server Component をデフォルトにし、必要時のみ `'use client'`。
  - **Python**: `from __future__ import annotations` を先頭に。公開関数に docstring。入力検証は「範囲外→クランプ、非数値→デフォルト」パターン。定数は `UPPER_SNAKE_CASE`。
  - **Bash**: 先頭で `set -euo pipefail`。ログは stderr。インデント 4 スペース。

## 7. アクセシビリティ（a11y）

- **対象は Web フロントエンド（HTML/CSS/JS を伴う UI）。** CLI・ライブラリ・バッチや、HTML を持たないネイティブ GUI（tkinter 等）には適用しない（共通規約の中で数少ない、適用範囲が限定される項目）。ネイティブ GUI の a11y は各リポジトリの固有ルールで扱う。
- **セマンティック HTML を使う。** 見出しは階層（`h1`→`h2`→…）を飛ばさず、操作要素は `<button>` / `<a>` を使う。`div` / `span` に `onClick` を乗せて疑似ボタン化しない。
- **キーボードだけで全機能を操作できるようにする。** フォーカス可能要素は可視のフォーカスリングを残す（`outline` を消す場合は代替の見た目を用意）。モーダルはフォーカストラップ＋`Esc` で閉じ、`tabindex` は `0` / `-1` のみ使う（正の値は使わない）。SPA でページ遷移したらフォーカスを新ページの先頭（`main` 等）へ移し、本文へ飛ぶスキップリンクも用意する。
- **スクリーンリーダーに情報を伝える。** 画像に `alt`（装飾画像は `alt=""`）、アイコンだけのボタンに `aria-label`、フォーム入力に対応する `<label>`（または `aria-labelledby`）を付ける。`aria-live` は簡潔な状態通知・エラーなど「即時に読み上げてほしい変化」に限って使う（検索結果・タイマー・カルーセル・ストリーミング等、頻繁に変わる領域全体に付けると読み上げ過多でかえって使いづらくなる）。
- **色だけに意味を持たせない。** エラー・成功などの状態はテキストやアイコンも併用する。コントラスト比は WCAG AA を満たす（通常文 4.5:1 / 大きな文字 3:1。加えて UI 部品の境界・状態・フォーカスリングや意味のある図形などの非テキストは 3:1＝SC 1.4.11）。配色は §6 の一元管理（CSS の `:root` 変数・`theme`）側でコントラストも担保する。
- **動きを抑えられるようにする。** `prefers-reduced-motion` を尊重し、過度なアニメーションは無効化できるようにする。
- **言語属性と外部リンクを正しく設定する。** ルート要素の `lang` は実際の文書の言語（§1 で宣言した UI 言語）に一致させる。多くは日本語なので `lang="ja"` だが、UI が他言語のリポジトリやローカライズページでは、その言語を正しく指定する（発音・言語処理が支援技術の挙動を左右するため）。別タブで開く外部リンクには `rel="noopener noreferrer"` を付ける。
- **検証する。** Lighthouse / axe などで a11y を確認し、可能なら CI（§14）に組み込む。キーボードのみでの操作確認を手動チェックに含める。

## 8. パフォーマンス・リソース

- **N+1 クエリを避ける。** ORM では関連を eager-load（EF Core の `.Include`、Prisma の `include` / `select`）でまとめて取得する（§E の `.Include(x => x.Incident)` と整合）。ループの中で 1 件ずつクエリを投げない。
- **よく絞り込む列にインデックスを張る。** `where` / `order by` / `join` で頻繁に使う列（ユーザー ID・日付・ステータス等）には DB インデックスを作成し、全件走査（sequential scan）を避ける。複合条件では複合インデックスの列順も意識する。
- **一覧取得は必ず上限・ページネーションを持たせる。** 件数無制限の取得をしない（§9 の DoS・リソース枯渇防止と整合）。既定件数・最大件数は定数で一元管理する（§6）。
- **計測してから最適化する。** 推測で最適化せず、プロファイラ／メトリクスで遅い箇所を特定してから手を入れる。早すぎる最適化で可読性を犠牲にしない。
- **重い処理で UI／イベントループを止めない。** 大量データの計算・変換・パースは分割や非同期化（Web Worker・ストリーム処理・バックグラウンドジョブ）で行い、メインスレッドやリクエスト処理をブロックしない。
- **フロントの配信を最適化する。** Web ではバンドルを分割（dynamic import / code splitting）し、画像は適切なフォーマット・サイズで最適化する。フォールド下や重要でない画像は `loading="lazy"` で遅延読み込みし、ファーストビューの LCP 候補（ヒーロー画像等）は遅延させず優先的に読み込む（Next.js は `next/image`。LCP 画像の優先読み込みはバージョンに応じて指定する: 16+ は `preload`、〜15 は `priority`）。重い依存は遅延読み込みする。
- **Core Web Vitals を意識する。** LCP / CLS / INP を悪化させない。画像・広告枠などにはサイズを指定してレイアウトシフトを防ぎ、Web フォントには `font-display: swap`（または `fallback`、装飾用途は `optional`）を設定して FOIT（文字が一定時間不可視になる現象）で LCP を悪化させない。
- **キャッシュを活用する。** 同じ計算・取得を繰り返さない（メモ化やフレームワークのキャッシュ機構 — Next.js なら 16+ の `use cache`／〜15 の `unstable_cache`、§D と整合 — を使う）。キャッシュは無効化条件を明確にし、古いデータを返さないようにする。
- **リソースを確実に解放する。** 接続・ファイル・タイマー・購読は使い終わったら閉じる（§D の SSE 購読のように、購読解除を必ず実装する）。

## 9. セキュリティ（必達）

- **入力は信用しない。** 外部入力（ユーザー入力・設定ファイル・JSON・環境変数）は必ず検証する。Web ではスキーマ検証（例: Zod の `safeParse`）を通してから永続化・API へ渡す。壊れたデータでクラッシュさせず、不正値はフォールバックする。
- **正規表現で algorithmic DoS（ReDoS）を起こさない。** 信頼できない入力に使う正規表現はネストした量指定子（`(a+)+` など）を避け、入力長に上限を設ける。複雑なパターンは線形時間のマッチャや専用の検証ライブラリに寄せ、未検証の正規表現を外部入力に直接当てない。
- **秘密情報をコミットしない。** 認証情報・トークン・API キー・個人情報をコード・ログ・コミットに含めない。`.env` / `.env.local` はコミットせず、`.env.example` にキー名だけ記載する。
- **API キーをフロントエンドに露出させない。** 外部 API はサーバー側（API ルート / Server Action）経由で呼ぶ。モデル名やエンドポイントは定数・環境変数で管理し、ハードコードしない。
- **認可はサーバー側で強制する。** UI を隠すだけに頼らず、Server Action / コントローラの冒頭で認証・ロールチェックを行う。マルチテナントではクエリに必ずテナント条件（`where.tenantId = session.user.tenantId`）を差し込み、クロステナント漏洩を防ぐ。
- **外部 Webhook は署名を検証する。** 受信 Webhook は共有シークレットで HMAC 署名（例: `X-Hub-Signature-256`）を検証し、一致しないリクエストは拒否する。アプリ層の認証だけに頼らず、なりすまし POST で状態を変えられないようにする。検証は定数時間比較で行う。
- **危険な実行・安全でない解析を避ける。** `eval` / `exec` / `pickle` / `shell=True` を使わない。外部コマンドは引数配列で実行し、ユーザー入力を文字列連結でシェルに渡さない。信頼できない XML は外部実体（XXE）・DTD を無効化したパーサで読み（.NET は `DtdProcessing = Prohibit`、Python は `defusedxml`）、YAML は `safe_load`、JSON は eval せず標準パーサで解析する。
- **失敗しても安全側に倒す（fail-safe / fail-closed）。** 例外時はクラッシュや権限昇格ではなく機能を縮退して継続する。権限・ネットワーク・パスの判定は「不明なら拒否」をデフォルトにする。
- **最小権限・最小公開。** 読み書きするファイルは想定パス配下に限定し、外部由来の値をそのままパスに連結しない（パストラバーサル防止）。
- **サーバー側の外向きリクエストを検証する（SSRF 対策）。** ユーザー由来の URL をそのまま `fetch` / HTTP クライアントに渡さない。スキーム・ホストを許可リストで制限し、プライベート IP（`127.0.0.0/8` / `10.0.0.0/8` / `169.254.0.0/16` 等）やクラウドメタデータ（`169.254.169.254`）への到達を遮断する。リダイレクト追跡先も同様に検証する。
- **リダイレクト先を検証する（オープンリダイレクト対策）。** `returnUrl` / `next` など外部由来の遷移先は、自サイト内パス（または許可リスト）に照合してからリダイレクトする。任意の絶対 URL へ飛ばさない（ログイン後フィッシング防止）。
- **出力もエスケープする（インジェクション対策）。** SQL は ORM／パラメータ化クエリで組み立て、ユーザー値を文字列連結で SQL に混ぜない。HTML はフレームワークの自動エスケープに任せ、`dangerouslySetInnerHTML` / `v-html` / `innerHTML` などの生 HTML 挿入は原則避ける（やむを得ない場合はサニタイズしてから）。OS コマンド・パス・LDAP なども同様に値を直接連結しない。
- **状態変更リクエストを保護する。** フォーム送信や書き込み系 API には CSRF トークン（またはダブルサブミットクッキー）を必須とする。`SameSite` クッキーはそれを置き換えるものではなく、多層防御として併用する（OWASP 準拠。登録ドメインを他サービスと共有する場合、サブドメイン経由や `Lax` のトップレベル遷移では `SameSite` だけでは防げない）。副作用のある操作を GET で行わない。
- **機密情報・PII・スタックトレースをログやエラー応答に漏らさない。** 外部にはサニタイズした安全なメッセージだけを返し、詳細はサーバ内ログに限定する。ログに残す前にトークン・個人情報はマスク／伏字化する。
- **暗号・認証情報は自前実装しない。** パスワードは平文・可逆形式で保存せず bcrypt / argon2 等でハッシュ化する。暗号化は標準ライブラリを使い、自前の暗号方式を発明しない。署名・擬似匿名化に使うソルトや鍵は環境変数から取得し、未設定なら起動を失敗させる（fail-closed）。
- **依存（サプライチェーン）を管理する。** ロックファイルをコミットし、新規依存は最小限に絞って出所・メンテ状況を確認する。`npm audit` / Dependabot 等で既知脆弱性を定期的に確認し、放置しない。
- **公開エンドポイントを保護する。** レート制限と、リクエストサイズ・タイムアウト・ページネーション上限を設けて DoS とリソース枯渇を防ぐ。

## 10. 移植性・プラットフォーム差異ゼロ設計

- **ロジックと UI を分離する。** ビジネスロジックは表示層に依存しない純粋関数として保ち、Web / デスクトップ / モバイルで共有できる状態を維持する。
- **プラットフォーム差を 1 か所に閉じ込める。** OS / 実行環境固有の処理は分岐（例: `platform.system()`）で局所化し、必ずフォールバックを用意する。
- **移植可能な書き方をする。** 特定 OS でしか動かない記述（例: `strftime` の `%-d`）を持ち込まない。同じ操作はどの環境でも同じ結果になるよう、判定ロジックは共有層に置きテストで担保する。
- **契約（contract）で同一性を保証する。** 言語・プラットフォーム非依存の入力→期待出力ケース（例: JSON の契約ファイル）を真実の源とし、各実装はそれに従う。

## 11. テスト

- **テストは必ず通過させること。** 変更の前後で、そのリポジトリの §2 と CI 設定（`.github/workflows/`）に記載された実際の検証コマンド（lint / 型チェック / テスト等、存在するものすべて）を通す。コマンド名や有無はスタックごとに異なるため、§2 と CI 設定を正本とし、ここに書かれた例（`lint && typecheck && test` 等）をそのまま当てはめない。
- テストファイルはそのスタックの慣習に従った場所・命名で配置する（例: Python/JS は `tests/` に `test_<module>.py` / `*.test.ts`、Maven は `src/test/java` に `<Class>Test.java`、.NET は専用テストプロジェクトに `<Class>Tests.cs`）。
- **純粋ロジックはユニットテスト、DB / 外部依存は E2E or 契約テストに寄せる。** ユニットテストに DB アクセスを持ち込まない。外部 API はモックして実際には呼ばない。
- 境界値（0・最大・空文字列・非数値など）を重視する。OS 依存処理はモック（`@patch` 等）し、特定 OS でしか通らないテストを作らない。
- DB を破壊的に扱う契約テストは、専用 DB を明示フラグで起動したときだけ走らせ、開発 DB を指さない。共有 DB を `TRUNCATE` するテストは直列実行する。

## 12. Git 規約

- コミットメッセージ形式: `type(scope): 日本語の説明`
  - type: `feat` / `fix` / `refactor` / `test` / `docs` / `chore`
  - scope: 変更領域（例: `chat`, `api`, `ui`, `tickets`, `reminder`）
  - 例: `feat(chat): ストリーミング応答の実装`
- **1 コミット = 1 論理変更。** スキーマ変更とマイグレーションは同一コミットに含める。
- 開発は機能ブランチで行い、`main`（デフォルトブランチ）への直 push は避ける。

## 13. PR・レビュー運用

- **PR は draft ではなく open（ready）で作成する。** harness のデフォルトが draft の場合は、作成直後に ready 化してから次の手順に進む。
- **コードレビューは `/code-review ultra` と `/security-review ultra` で行う（Codex 自動レビューは廃止）。** PR を ready 化して open にした直後、および PR ブランチへ push するたび（初回 PR 作成時を含む）に、この 2 つのスキルを実行して差分をレビューする。`@codex review` コメントの投稿は行わない（`chatgpt-codex-connector` 連携には依存しない）。
  - `/code-review ultra` — 差分の正確性（バグ）と、再利用・簡素化・効率・粒度（altitude）の観点でレビューする。
  - `/security-review ultra` — ブランチの保留中変更に対してセキュリティレビューを行う。
  - 指摘は対応可否を判断して反映し、対応・見送りの理由をチャットで報告する。質問返信やレビュー不要な状況報告では実行しない。
- **CI の成否（グリーン）はチャット上で報告する。** GitHub MCP（check-runs / status）で取得して報告する。
- **ユーザーへの結果報告・要約は必ず日本語で出力する。** CI の成否・レビュー結果・作業サマリなど、要約した結果は常に日本語で記述する（各リポジトリの UI／コード言語に関わらず、チャットでの報告は日本語に統一する）。

## 14. CI

- GitHub Actions（`.github/workflows/`）でそのリポジトリに必要な検証を実行する。実行するジョブはスタックに応じて異なる（例: Web/TS なら lint → typecheck → test → E2E、Maven なら `mvn -B verify`、.NET なら `dotnet build` ＋ `dotnet test`、シェル/Docker なら shellcheck / hadolint / `docker compose config` ＋ e2e）。**PR を出す前に、§2 と CI 設定に記載のローカル検証コマンド（そのリポジトリに実在するものすべて）を通す。** 存在しないコマンドを当てはめない。
- DB / ブラウザ依存のジョブはサービスコンテナ（PostgreSQL 等）や chromium を使う。依存があるスタックでは、ローカルでも `docker compose up` などで依存を起動してから実行する。

## 15. 見せ方（ショーケース）

> **成果物は「動くコード」だけでなく「伝わる見せ方」までを完成の定義に含める。** README を開いて 5 秒で「何のアプリで、どんな画面か」が伝わらない状態を不合格とする。

- **README 冒頭に「デモ」ブロックを必須で置く（UI を持つ全リポジトリ）。** 概要の直後に次の 3 点を配置する: (1) 公開デモ URL（バッジまたはリンク）、(2) 主要画面のスクリーンショット 3〜5 枚、(3) 代表的な操作フロー 1 本のデモ GIF/動画。CLI・バッチはスクショの代わりに端末操作の録画（asciinema / GIF）を置く。
- **公開デモ URL は段階必須とする。** 無料枠で維持できる形態は URL を必須、維持コストが発生する形態は動画で代替可とする（規約の形骸化を防ぐため強制度を分ける）。

  | スタック形態 | ルール | 手段の例 |
  |---|---|---|
  | 静的サイト | URL **必須** | GitHub Pages |
  | serverless で完結する Web | URL **必須** | Vercel 等の無料枠。公開前にレート制限・利用上限を設定（§9 と整合） |
  | DB/常駐サーバーが必要な Web | デモ動画 **必須**、URL は任意（推奨） | Neon・Render 等の無料枠＋シードデータ＋定期リセットを整備できる場合に公開 |
  | CLI / バッチ / サンドボックス | 録画で代替（URL 適用外） | asciinema / 端末操作 GIF |
  | ネイティブ GUI（tkinter 等） | スクショ＋GIF **必須**（URL 適用外） | OS のスクリーンショット / 画面録画 |

- **画像は保存場所・命名・品質を一元化する。** `docs/screenshots/` 配下に `<画面名>-<状態>.png`（例: `incident-list-default.png`）で置く。幅 1280px 目安、GIF は 10MB 以下に最適化し（§8 の配信最適化と整合）、すべての画像に日本語の `alt` を付ける（§7 と整合）。
- **スクショにはシード/ダミーデータのみ使う。** 実データ・PII・秘密情報・実在のメールアドレスを写さない（§9 と整合）。デモ用シードデータの投入コマンドは §2 に記載する。
- **UI 変更 PR では該当スクショを同一 PR で更新する。** コードとドキュメントの乖離を許さない原則（§3）をスクショにも適用する。変更した画面が写っている分だけ更新すればよく、全量の再撮影は不要。
- **撮影は自動化を推奨する。** Web 系リポジトリはシードデータ入りの画面を Playwright 等で自動撮影するスクリプト（例: `scripts/capture-screenshots.ts`）を用意し、実行コマンドを §2 に記載する。非 Web GUI は手動撮影でよい。
- **デモ環境は本番と分離し fail-safe にする。** デモアカウントは閲覧専用の最小権限ロール、環境変数・シークレットは本番と共有しない、書き込みは無効化または定期リセットする（§9 と整合）。
- **撮影対象画面・デプロイ先はリポジトリごとに具体化する。** 各リポジトリの `CLAUDE.md`（§1〜§3）に「どの画面を何枚撮るか」「どこへデプロイするか」を明記し、この章はその共通基準として使う。

---

## 付録: リポジトリ別のルール（Appendix）

各リポジトリの `CLAUDE.md` から、**§4〜§15 の共通規約と重複しない固有ルールだけ**を抜き出したカタログ。
新規リポジトリが似た技術スタックの場合、該当ブロックを §1〜§3 の具体化や追補として流用できる。
（出典の `CLAUDE.md` には、ここに載らないプロジェクト固有のアーキテクチャ詳細も含まれる。詳細は各リポジトリを参照。）

### A. profile-portfolio（静的 HTML/CSS/JS, GitHub Pages）

- **サイト本体にページ生成のビルドステップは無い**（`index.html` / `resume.html` をそのまま配信する）。表示確認は `open index.html` または `python -m http.server 8000`。
- 一方で検証・撮影用に npm ベースの開発ツール（html-validate / Playwright ビジュアルリグレッション / Lighthouse CI / スクショ自動撮影）を持つ。`package.json` ・ `package-lock.json` はコミットし、検証は `npm ci` の後に CI と同じコマンド（`npx html-validate` / `npm run test:e2e` / `npm run test:lighthouse`）で流す。
- ファイル構成: `index.html`（ダークテーマ）/ `resume.html`（ライトテーマ・印刷対応）/ `data/portfolio.json`（表示データ）/ `e2e/`（ビジュアルリグレッション）/ `scripts/`（スクショ・デモ GIF の自動撮影）。
- 色の変更は `:root` の CSS 変数（`--primary`, `--accent`, `--bg-dark` 等）経由。個別要素にカラーコードを直書きしない。
- レスポンシブ: ブレークポイント 968px（タブレット）・768px（モバイル）。グリッドは `auto-fit, minmax()` でメディアクエリを最小化。フォントは `clamp()` で流体タイポグラフィを適用。
- CSS は BEM 風命名（`.section-header` 等）、JS は Vanilla のみ（外部ライブラリを追加しない）。a11y の基本（セマンティック HTML・`alt`・外部リンクの `rel`・`lang`）は §7 に従う（この repo は日本語 UI なので `lang="ja"`）。
- セクション追加時は Intersection Observer の `.observe()` 対象に追加し、ナビリンク・768px 表示・`resume.html` 反映を確認する。

### B. my-task-manager（Python + tkinter, GUI）

- ビジネスロジックは GUI 非依存の純粋関数に保つ（`timeline.py` / `stats.py` / `recurrence.py` / `task.py`）。表示層を差し替えてもロジックを共有できる状態を維持。
- デザイントークン（配色・フォント・余白・カレンダー寸法）は `theme.py` に一元化。見た目の値をコードに直書きしない。
- 繰り返しタスクは「完了した時点」を起点に日/週/月/年で再スケジュール（月末日・うるう年はクランプ）。
- 言語・プラットフォーム非依存の繰り返し契約は `contract/recurrence_cases.json` を真実の源とし、契約駆動テスト（`test_recurrence_contract.py`）で検証。Web/スマホ版も同一契約に従う。
- tkinter の `StringVar` / `IntVar` はテスト用 `_DummyVar` で代替し、`AppTestCase._app()` ファクトリ（`tests/test_planner.py`）でモック済みインスタンスを生成（Tk 無しでテスト可能）。
- 入力検証は `_coerce_int()` パターン（範囲外→クランプ、非数値→デフォルト）。
- 今日のタスクは Treeview でなく `tk.Canvas` の「デイビュー」で描画し、位置・高さは分→px 換算（`HOUR_HEIGHT`）で Canvas 実サイズに依存させない。
- クロスプラットフォーム: 音/通知は macOS(`afplay`)・Windows(`winsound`)・Linux(`notify-send`+`tk.bell()`)を `platform.system()` で分岐。`cairosvg` はオプション依存で `ImportError` 時 graceful degradation。

### C. my-first-ai-app（Next.js 16 + Claude API）

- システムプロンプトは `src/lib/prompts.ts` に集約し、コンポーネントやルートハンドラに直接書かない。プロンプトは日本語で記述。
- モデル名（`claude-sonnet-4-6` 等）は環境変数または定数で管理しハードコードしない。`max_tokens` 既定 1024、長文が必要なカテゴリは `prompts.ts` で個別設定。
- `POST /api/chat` が唯一の API。Claude へのストリーミングプロキシで、`ANTHROPIC_API_KEY` はサーバ側環境変数から取得しフロントに露出させない。
- API ルートに簡易レート制限（IP ベース、1 分あたり 20 リクエスト目安）。
- API ルートのエラーは HTTP ステータスを使い分け: 400（JSON 破損・入力検証エラー・上流 Claude API の 400）/ 401（キー未設定/無効）/ 413（本文サイズ上限超過）/ 415（`Content-Type` が `application/json` でない。**レート制限より前に**検証し、第三者サイトの simple request で被害者 IP のレート枠が枯渇するのを防ぐ）/ 429（レート制限超過。`Retry-After` ヘッダ付き）/ 499（接続確立前のクライアント切断）/ 500（その他）。文言は `route.ts` の `ERROR_MESSAGES` に一元管理し、フロントはユーザーフレンドリーな日本語メッセージを表示。

### D. helpdesk-hub（Next.js 15 / Prisma / Auth.js v5）

- 正本は `docs/smb-dx-pivot-plan.md`。Lite/Pro 二層・マルチテナント化・用語簡素化等の方針に反する変更をしない。Phase 0→1→2→3→4 の順序を尊重し、後フェーズ機能を前フェーズに混ぜない。
- Prisma クライアントは `src/generated/prisma` に出力される。型/enum は必ず `@/generated/prisma` から import（`@prisma/client` ではない）。クローン後やスキーマ変更後は `npm run db:generate` を実行。
- ロールは実質 requester と agent/admin の 2 種。`isAgent(role)`（`src/lib/role.ts`）を使い、`role === 'admin'` を直接比較しない（admin 限定の意図がある場合を除く）。
- Mutation（Server Action）の定型: `auth()`＋ロール表明 → `findUniqueOrThrow` → 状態変更は `isValidTransition(from,to)` でゲート → Prisma で更新 → `recordHistory(...)` → `createNotification(...)` → `revalidatePath(...)`。
- 状態遷移テーブル `ALLOWED_TRANSITIONS`（`src/domain/ticket-status.ts`）が唯一の真実の源。バイパスせず、ブロックされたら表とテストを更新する。
- Data 層は Ports & Adapters。Port を `src/data/ports/` に定義し、本番は `adapters/prisma/`、テストは `adapters/memory/`。Prisma を直接 import するのは Adapter 内のみ。
- 未読通知数は SSE（`/api/notifications/stream`）＋ `unstable_cache` で配信。`sse-subscribers.ts` はインプロセス Map のため、水平スケール前に要注意。
- 契約テストは `*.contract.prisma.test.ts` 命名。`RUN_PRISMA_CONTRACT=1` のときだけ走り、`beforeEach` で全テーブル `TRUNCATE` するため**開発 DB を指さない**。`--no-file-parallelism` で直列実行。

### E. incident-insight（ASP.NET Core 8 MVC + EF Core 8）

- DB プロバイダ非依存。SQLite（既定）/ SQL Server / PostgreSQL を `Database:Provider` で切替。プロバイダ固有 SQL・列型をコードに持ち込まない。
- 楽観的同時実行制御: 編集 POST は `FindAsync` で再読込後、クライアントの編集前 `ConcurrencyToken` を `OriginalValue` に明示ピンして保存し、`DbUpdateConcurrencyException` を捕捉。トークンは hidden field で round-trip。
- 時刻は常に注入された `IClock`（JST）。`DateTime.Now/Today/UtcNow` を直接呼ばない。
- 監査ログは `AuditSaveChangesInterceptor` が唯一の源。`AuditLog` に直接書かない。`SaveChanges` 経由で更新し、`ExecuteUpdate`/`ExecuteDelete` を使わない（変更追跡を迂回し監査漏れになるため）。
- PHI 保護: 自由記述・個人名カラムには `[Sensitive(Mask.Redact)]` か `[Sensitive(Mask.Hash)]` を付与（`[REDACTED]` か HMAC-SHA256 擬似匿名化）。新カラム追加時も必ず annotate。本番で `Audit:HashSalt` 空は起動失敗。
- ビジネスルール `HasAtLeastOneValidMeasure`（インシデントは予防策が最低 1 件ないと登録不可）をバイパスしない。
- Enum（重症度・部署・インシデント種別）は `Incident` クラスの `static readonly` 辞書/配列が真実の源（DB ではない）。`EnumLabels.cs` に日本語ラベル＋Bootstrap カラーを集約。
- `SameDepartmentHandler` は `Incident` の eager-load（`.Include(x => x.Incident)`）が前提で fail-closed（null なら拒否）。
- 新規 POST アクション時チェック: `[Authorize]` / `[ValidateAntiForgeryToken]` / `ConcurrencyToken` ピン / 必要なら `.Include(Incident)` / `SaveChangesAsync` 使用 / `TempData["Success"|"Warning"]` / 新 PHI カラムに `[Sensitive]` / 対応テスト追加。テストは InMemory DbContext を優先（Mock より）。

### F. AI-Docker-Environment（Docker サンドボックス, bash, Linux 専用）

- 正本は `docs/requirements.md`。実装・新機能はすべて要件定義書に従い、衝突したら先に要件を改訂してから実装変更（同一 PR 内で §3/§4/§6 を更新）。
- すべて `bin/aidock` 経由で実行（`build`/`login`/`run`/`shell`/`firewall-refresh`/`logout`）。`guard_workspace()` の `/` および `$HOME` をマウント拒否するガードを削除しない。
- セキュリティ不変条件（変更禁止 or 影響必須検討）:
  - `compose.yaml`: `cap_drop: ALL`（必要 cap のみ add）/ `no-new-privileges:true` / `read_only: true`＋最小 `tmpfs` / メモリ・CPU・PID 上限 / ホストパスの追加 bind mount 原則禁止（`~/.ssh` 等）。
  - `HOST_WORKSPACE` に既定値を付けない（`${HOST_WORKSPACE:?...}`）。`bin/aidock` 非経由の直接 `docker compose run` を fail-closed にする。
  - `Dockerfile`/`entrypoint.sh`: `sudo` を含めず、root 起動 → firewall 初期化後に `gosu agent` で降格。ワークロードは `agent` で実行。
  - `init-firewall.sh`: `iptables -P OUTPUT DROP` と `ip6tables -P OUTPUT DROP`（IPv4/IPv6 両方 default-deny）を維持。許可ホスト追加は最小限・理由を PR に明記。DNS は許可 nameserver 限定。
- OAuth トークンは名前付きボリューム `claude-home` に置き、ホスト FS や Docker イメージ層に書き出さない。
- Linux 専用（iptables/ipset/cap_add 依存。macOS Docker Desktop 非対応）。スクリプトは Bash・先頭で `set -euo pipefail`、ログは stderr、インデント 4 スペース。
- このリポジトリのコミットメッセージは英語・命令形・1 行要約（既存履歴に倣う。§12 の日本語コミット規約より優先する例外）。

### G. batch-scheduler（Java 21 / Maven, バッチ実行マネージャ）

- 正本は `docs/DESIGN.md`（アーキテクチャ・セキュリティモデル・将来拡張）。実装はここに従い、衝突したら先に設計を改訂してから実装を変更する。
- バッチ定義ファイル（YAML）は **Makefile / CI パイプラインと同等の信頼入力**として扱う。一方で資源枯渇には防御する: bounded YAML parsing、出力キャプチャの上限、反復的（再帰でない）グラフアルゴリズム、state ディレクトリの安全性（runId 検証・シンボリックリンク非追従）。
- MVP 非目標（non-goals）: スケジューリング・並列実行・分散。
- テストは `src/test/java/...` の各クラス対応（`BatchConfigLoaderTest` / `BatchExecutorTest` / `DependencyGraphTest` 等）。CI は `mvn -B verify`（Java 21 / Temurin）。

### H. Expense-Management-Rest-API（Java 21 / Spring Boot, REST API）

- Java 21 / Spring Boot 3.3.5 / PostgreSQL 16 / Maven / Docker の REST API 単一プロジェクト。アプリ一式（`pom.xml` ・ `src/` ・ `Dockerfile` ・ `docker-compose.yml`）をリポジトリ直下に置く。金額は `BigDecimal` を使い浮動小数誤差を避ける。レスポンスは JSON、エラー形式は `{ "status": int, "message": string }`、入力検証は Jakarta Bean Validation。
- 課題の棚卸しは `docs/issue-analysis.md`（機能面・セキュリティ面の分析）。
- 層構成: `controller/` → `service/` → `repository/`（Spring Data JPA）→ `domain/`（JPA エンティティ）。`dto/request/` と `dto/response/` を分離し内部エンティティを API 契約から切り離す。`GlobalExceptionHandler` がカスタム例外を HTTP ステータスへマップ。
- 横断的関心事は `web/`（エラー応答の共通整形・ページング入力の無害化・リクエスト本文サイズ上限）・`security/`（IP ベースのレート制限フィルタ）・`validation/`（コードポイント単位の文字数検証・カテゴリ名の NFC 正規化）に分ける。
- CI は `.github/workflows/ci.yml` の `build-test` ジョブ 1 本で `./mvnw -B verify`（Temurin JDK 21）を実行する。`repository/` 配下のテストは Testcontainers で PostgreSQL を起動するため Docker デーモンが必要。
