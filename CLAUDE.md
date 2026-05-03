# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

IncidentInsight is a medical incident management system (ASP.NET Core 8 MVC + EF Core 8). It covers the full incident lifecycle: reporting → 5 Whys root-cause analysis → preventive measure planning → completion → effectiveness review → recurrence detection. UI strings and the domain vocabulary are Japanese (e.g. `重症度`, `なぜなぜ分析`, `再発防止策`).

The app is **database-provider-agnostic**: SQLite (default, single-file), SQL Server (on-prem Windows), and PostgreSQL (Linux / cloud / Supabase / any managed Postgres) are all first-class at runtime — selected via the `Database:Provider` setting. Model + query code contains zero provider-specific SQL or column types, so the same codebase ships everywhere.

## Common commands

All commands assume the repo root as the working directory.

```bash
# Build (whole solution)
dotnet build

# Run the web app (creates SQLite DB + seeds data on first launch at http://localhost:5000)
dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj

# Run all tests (xUnit)
dotnet test

# Run a single test class / method
dotnet test --filter "FullyQualifiedName~IncidentsControllerTests"
dotnet test --filter "FullyQualifiedName=IncidentInsight.Tests.Controllers.IncidentsControllerTests.Create_RequiresAtLeastOneMeasure"

# Add an EF Core migration after model changes (auto-applied on next startup via Database.Migrate())
# NOTE: Committed migrations target the currently-configured provider (default: SQLite).
# When switching to SQL Server or PostgreSQL for production, regenerate migrations against
# that provider (delete the Migrations/ folder, set Database__Provider and a valid
# ConnectionStrings__DefaultConnection, then run the command below).
dotnet ef migrations add <MigrationName> --project src/IncidentInsight.Web

# Seed demo accounts for local login (Development only; no passwords are committed)
dotnet user-secrets init --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:AdminPassword" "AdminPass1" --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:RiskManagerPassword" "RiskPass1" --project src/IncidentInsight.Web
```

Dev password policy: 8+ chars, uppercase, digit. Prod policy: 12+ chars and non-alphanumeric (see `Program.cs`). The `SeedAccounts` section only seeds accounts in `Development`; it is skipped silently if passwords are blank (a warning is logged).

## Architecture

### Request pipeline & bootstrapping (`Program.cs`)
- `ApplicationDbContext` is wired with a runtime provider switch keyed off `Database:Provider` (`sqlite` | `sqlserver` | `postgres`). SQLite is the default. The connection string comes from `ConnectionStrings:DefaultConnection`. Providers use the `UseSqlite` / `UseSqlServer` / `UseNpgsql` methods respectively. No code changes required to move between them — only config.
- `AuditSaveChangesInterceptor` is registered on the `DbContext`. It is **provider-neutral** — works identically on SQLite / SQL Server / PostgreSQL — and writes a row to the `AuditLogs` table for every Add / Modify / Delete on `Incident`, `CauseAnalysis`, `PreventiveMeasure`. It also rotates the `ConcurrencyToken` Guid on Modified entries.
- ASP.NET Core Identity is wired up with a custom `ApplicationUser` and three roles in `AppRoles` (`Admin`, `RiskManager`, `Staff`). Cookie auth redirects to `/Account/Login`; sliding expiration of 8h; lockout after 5 failed attempts.
- On startup (inside a scope): `db.Database.Migrate()` → `DbSeeder.Seed(db)` (cause categories + sample incidents, idempotent) → `IdentitySeeder.SeedAsync(...)` (creates roles always; creates demo admin/RM only in Development when `SeedAccounts` passwords are present).

### Database provider matrix

| Target deployment | `Database:Provider` | Example connection string |
|---|---|---|
| Single clinic / dev (default) | `sqlite` | `Data Source=incident_insight.db` |
| On-prem hospital (Windows / existing SQL Server) | `sqlserver` | `Server=...;Database=IncidentInsight;Trusted_Connection=True;TrustServerCertificate=True;` |
| Linux / self-hosted Postgres | `postgres` | `Host=...;Database=incidentinsight;Username=...;Password=...` |
| Managed (Supabase / Azure DB for PostgreSQL / Aurora) | `postgres` | provider's standard Postgres connection string |

Set via `appsettings*.json` or environment variables (`Database__Provider`, `ConnectionStrings__DefaultConnection`).

### Domain model (EF Core, `src/IncidentInsight.Web/Models/`)
The schema is centered on four aggregates with cascade rules configured in `ApplicationDbContext.OnModelCreating`:

- **`Incident`** — the root. Holds occurrence metadata (`OccurredAt`, `Department`, `IncidentType`, `Severity`, `Description`, `ReporterName`). Severity codes (`Level0`…`Level5`), department list, and incident-type list are hard-coded `static readonly` dictionaries/arrays on the class and are the single source of truth for dropdowns and labels. Computed helpers like `SeverityLabel`, `SeverityColor`, `MeasureStatusSummary`, `MeasureStatusColor` are consumed directly in Razor views for Bootstrap badge classes.
- **`CauseAnalysis`** — 5 Whys stored as independent `Why1`..`Why5` columns (so SQL can search at specific depths). Always tied to one `CauseCategory`. Helpers: `DeepestWhy`, `WhyDepth`.
- **`CauseCategory`** — self-referential hierarchy (parent/child via `ParentId`). `BuildCauseCategoryOptionsAsync()` in `Controllers/Internal/IncidentControllerHelpers.cs` emits leaf categories grouped by parent as `<optgroup>` — never add a category-picker that bypasses this helper.
- **`PreventiveMeasure`** — the "most important" entity per the domain: tracks the full lifecycle `Planned → InProgress → Completed` plus post-completion fields `EffectivenessRating` (1–5), `EffectivenessNote`, `EffectivenessReviewedAt`, and `RecurrenceObserved` (true ⇒ surface warning and prompt re-analysis). `IsOverdue` is a computed property used all over the UI; keep the `DueDate < DateTime.Today && Status != "Completed"` semantics consistent.
- **`AuditLog`** — regulatory audit trail written automatically by `AuditSaveChangesInterceptor`. Holds `ChangedAt`, `ChangedBy` (user name from the current `HttpContext`), `EntityName`, `EntityKey`, `Operation` (`Added` / `Modified` / `Deleted`), and a JSON `ChangesJson` with before/after values. Never write to this table directly — the interceptor is the single source of truth.

`Incident` / `CauseAnalysis` / `PreventiveMeasure` each carry a `ConcurrencyToken` (Guid, `[ConcurrencyCheck]`) for optimistic concurrency. The interceptor rotates this on each modification so concurrent edits fail-safe with `DbUpdateConcurrencyException`.

**Edit POST contract**: mutating actions reload the entity via `FindAsync` before applying form data. If we relied on the default `OriginalValue` (which would be the token EF just loaded from the DB — always current), the concurrency check would never trip. Every edit POST therefore pins the client's pre-edit token explicitly before saving:

```csharp
_db.Entry(entity).Property(nameof(Entity.ConcurrencyToken)).OriginalValue = vm.ConcurrencyToken;
try { await _db.SaveChangesAsync(); }
catch (DbUpdateConcurrencyException) { TempData["Warning"] = "..."; return ...; }
```

The client round-trips the token via a hidden form field (`<input type="hidden" asp-for="ConcurrencyToken" />`, or a `name="concurrencyToken"` value for modal/kanban forms that POST raw parameters). Applied across `IncidentsController.Edit`, `CauseAnalysesController.EditCauseAnalysis`, `IncidentMeasuresController.CompleteMeasure` / `RateMeasure`, and `PreventiveMeasuresController.Edit` / `Complete` / `Review` / `UpdateStatus`. When adding a new mutating POST action on any of these three entities, follow the same pattern.

Indexes worth knowing about: `Incident(OccurredAt)`, `Incident(Department, IncidentType)`, `PreventiveMeasure(Status, DueDate)`, `CauseCategory(ParentId, DisplayOrder)`, `AuditLog(ChangedAt)`, `AuditLog(EntityName, EntityKey)`.

### Controllers & cross-cutting patterns
- All app controllers except `AccountController` use `[Authorize]`. `AccountController` is explicitly `[AllowAnonymous]` on `Login` / `AccessDenied`.
- The incident lifecycle is split across **three** controllers, all routed under `/Incidents/...`:
  - `IncidentsController` — Index / Details / Create / Edit / Delete on the Incident root. Create enforces "at least one preventive measure" via `HasAtLeastOneValidMeasure` (business-critical). Strips sub-form keys from `ModelState` before validating the parent form (see the `ModelState.Remove` loop in `Edit`).
  - `CauseAnalysesController` — `AddCauseAnalysis` / `EditCauseAnalysis` (GET+POST) / `DeleteCauseAnalysis`. Uses `[Route("Incidents/[action]/{id?}")]` to keep URLs unchanged after the split. Re-uses `Views/Incidents/EditCauseAnalysis.cshtml` via explicit `View("~/Views/Incidents/EditCauseAnalysis.cshtml", vm)`.
  - `IncidentMeasuresController` — `AddMeasure` / `CompleteMeasure` / `RateMeasure` (the inline operations launched from the Incident detail page). Same `[Route]` trick. The kanban-side `Create` / `Edit` / `Complete` / `Review` / `UpdateStatus` / `Delete` continue to live on `PreventiveMeasuresController`.
- Shared helpers (cause-category dropdown builder, resource-policy evaluation) live in `Controllers/Internal/IncidentControllerHelpers.cs`. **Do not** add business rules there — keep it to pure reusable functions; rules like `HasAtLeastOneValidMeasure` stay on the controller that owns them.
- View tag helpers must specify `asp-controller="CauseAnalyses"` / `asp-controller="IncidentMeasures"` for the actions that moved out of `IncidentsController` (the URL is still `/Incidents/...`, but the route table needs the new controller name to resolve URL generation).
- `PreventiveMeasuresController` powers the kanban board (`Index` buckets measures into `Planned` / `InProgress` / `Completed` via `ViewBag`) and provides a separate `Review` action for the effectiveness evaluation form.
- `AnalyticsController` exposes JSON endpoints for Chart.js (`MonthlyTrend`, `ByCause`, `ByDepartment`, `BySeverity`, `MeasureStatus`, `EffectivenessRating`, `ByIncidentType`, `GetSubcategories`). These return `{ labels, data }` shapes that the Analytics views consume verbatim — keep the shape stable.
- `HomeController.Index` is the dashboard. It accepts a `period` (`week` | `month` | `quarter` | `year`, default `year`) and computes KPIs, trend buckets (daily for `week`, monthly otherwise), and **recurrence alerts** (same department + same incident type + overlapping cause category within the last 90 days — the 90-day window is independent of `period`). Duplicate this algorithm carefully if you touch it.
- Success/warning toasts are passed via `TempData["Success"]` / `TempData["Warning"]` and rendered in shared layout.

### Views & frontend
- Razor views under `src/IncidentInsight.Web/Views/` matching controller names. Severity/status badges rely on the Bootstrap color names returned from the computed `*Color` properties on model classes — don't hardcode them in views.
- Bootstrap 5, Bootstrap Icons, jQuery Validation Unobtrusive, and Chart.js 4 are loaded from CDN (no npm / build step on the frontend).

### Tests (`tests/IncidentInsight.Tests/`)
- xUnit, targeting `net8.0`. Uses `Microsoft.EntityFrameworkCore.InMemory` with a fresh `Guid.NewGuid()`-named database per test (see `IncidentsControllerTests` constructor). Controllers that set `TempData` are injected with `TestTempData` from `Helpers/`.
- Tests cover controller happy/edge paths and model computed properties. When adding controller logic that reads/writes new entities, extend the in-memory setup in the corresponding `*ControllerTests` rather than adding mocks.

## Things to watch for

- **Migrations are auto-applied at startup** via `Database.Migrate()`. When you change a model, add a migration in the same change set or the next developer's first run will throw.
- **Don't bypass `HasAtLeastOneValidMeasure`.** The product rule is "an incident cannot be registered without at least one preventive measure."
- **Severity / department / incident-type enums live on the `Incident` class**, not in the DB. Adding a value requires updating the static dictionary/array and any views that iterate it; no migration needed.
- **`SeedAccounts` passwords must never be committed.** `appsettings.Development.json` ships with blank passwords on purpose; use User Secrets or environment variables (`SeedAccounts__AdminPassword`, etc.).
- **Recurrence logic is centralized in `IRecurrenceService`** (`src/IncidentInsight.Web/Services/RecurrenceService.cs`). Both `HomeController.Index` (dashboard alerts, 90-day window via `FindRecurrenceAlertsAsync`) and `IncidentsController.Details` (per-incident similar list, no time bound via `FindRecurrencesForIncidentAsync`) delegate candidate extraction + matching to the service. The underlying matcher (`RecurrenceDetector.FindSimilar`) is still a pure in-memory function. If you change the matching rule (same dept + same incident type + cause category overlap), update the service and its tests in `tests/IncidentInsight.Tests/Services/RecurrenceServiceTests.cs`.
- **Committed migrations are for SQLite**. Switching production to `sqlserver` or `postgres` requires regenerating migrations against that provider (one-time operation). Don't keep multiple provider migration folders in parallel — EF Core's `ModelSnapshot` is single-provider by design; trying to mix them causes apply-time errors.
- **Don't add provider-specific SQL or column types**. The value of the abstraction comes from staying portable. If a feature absolutely requires SQL Server-only (e.g. Temporal Tables) or Postgres-only (e.g. JSONB) behavior, gate it behind a runtime `Database:Provider` check and keep a portable fallback.
- **Audit log correctness depends on going through `SaveChanges`**. Don't use `ExecuteUpdate` / `ExecuteDelete` for `Incident` / `CauseAnalysis` / `PreventiveMeasure` — those bypass the change tracker and silently skip auditing.
- **PHI must not land in `AuditLog.ChangesJson` in plaintext.** Free-text properties on `Incident` / `CauseAnalysis` / `PreventiveMeasure` (descriptions, notes, why-chains, names) carry `[Sensitive(Mask.Redact)]` or `[Sensitive(Mask.Hash)]` (`Models/Auditing/SensitiveAttribute.cs`). The `AuditSaveChangesInterceptor` reads the attribute via reflection and replaces values with `[REDACTED]` / a salted SHA-256 prefix before writing the change set. **When you add a new free-text or person-name column, you must also annotate it.** The salt comes from `Audit:HashSalt` (User Secrets / environment variable `Audit__HashSalt`); rotating the salt invalidates correlation against past hashes — document it in any rotation runbook.
- **Time source is always `IClock`** (`src/IncidentInsight.Web/Services/IClock.cs`). Never call `DateTime.Now` / `DateTime.Today` / `DateTime.UtcNow` from controllers, services, the audit interceptor, or the seeder — use the injected `IClock` instead. This is both a testability lever (tests can substitute a fake clock) and an explicit-policy point: **all persisted business timestamps and audit log `ChangedAt` are stored in operational-local time (JST)**. Previously only audit logs used UTC, which produced a confusing 9h offset vs. business data (Issue #31). If you need to migrate to UTC later, change `SystemClock` in one place and update display formatting — don't start sprinkling `DateTime.UtcNow` again. Razor views currently use `DateTime.Today` directly for display-only date arithmetic (e.g. "days overdue"); this is intentional since views don't persist data, but prefer `@inject IClock Clock` + `Clock.Today` in new views. **Upgrading across the PR #37 boundary requires a one-time `UPDATE AuditLogs SET ChangedAt = ChangedAt + 9h` on existing data (run before deploying the new binary); see PR #37 description for per-provider SQL and rollback.**
- **`SameDepartmentHandler` requires `Incident` to be eager-loaded** (`src/IncidentInsight.Web/Authorization/SameDepartmentHandler.cs`). When calling `AuthorizeAsync(User, resource, …)` with `PreventiveMeasure` or `CauseAnalysis`, the controller must `.Include(x => x.Incident)` first. The handler is **fail-closed**: if `Incident` is null on the navigation, authorization is denied (no silent fallback to `ResponsibleDepartment` — Issue #29). Authorization judges "where did the incident happen?", not "who is working on the fix?".

## Coding conventions

- **1行ごとに初心者でも意味がわかるコメントアウトをつける**。新規または変更したコード行には、プログラミング初心者でも理解できる平易な日本語のコメントを各行に付与する。コメントは「何をしているか」を具体的に説明し、専門用語や省略語を避ける(例: `var x = users.Where(u => u.IsActive); // アクティブなユーザーだけを抜き出す`)。C# は `//`、Razor (`.cshtml`) は `@* *@`、JavaScript は `//`、設定ファイル (JSON など) はコメントをサポートしないため対象外。このルールは本プロジェクト固有の方針であり、汎用的な「コメントは最小限に」というガイダンスよりも優先される。

## Enum ラベル管理

- すべての Enum の日本語ラベルと Bootstrap カラーは `Models/Enums/EnumLabels.cs` に集約する。View で直接文字列を書かない。
- 新しい Enum 値を追加したら `EnumLabels.Japanese()` と `EnumLabels.Color()` の両方を更新すること。
- `IncidentTypeMapping.cs` は日本語 ↔ DB 文字列の双方向変換を担う。新しいインシデント種別はここにも追加する。

## Controller 新規アクション追加時のチェックリスト

新しい POST アクションを追加する際は以下を確認:

1. `[Authorize]` 属性（または適切なポリシー）を付与したか
2. `[ValidateAntiForgeryToken]` を付与したか
3. `ConcurrencyToken` を hidden field で round-trip し、`OriginalValue` にピンしているか
4. `SameDepartmentHandler` が必要なら `.Include(x => x.Incident)` しているか（`IncidentControllerHelpers.IsAuthorizedForAsync` 経由でも同様）
5. `SaveChangesAsync` を使い、`ExecuteUpdate` / `ExecuteDelete` を使っていないか（監査ログのため）
6. 成功時に `TempData["Success"]`、失敗時に `TempData["Warning"]` をセットしているか
7. 新しい自由記述 / 個人名カラムを追加した場合は `[Sensitive(Mask.Redact)]` か `[Sensitive(Mask.Hash)]` を付けたか（PHI 監査ログ漏洩防止）
8. 対応するテストを `tests/` に追加したか

## View 規約

- Badge のカラーは Model の `*Color` プロパティを使う。View に直接 `bg-danger` 等を書かない。
- フォームには必ず `@Html.AntiForgeryToken()` を含める。
- 新規 View では `@inject IClock Clock` を使い、`DateTime.Today` の直接参照を避ける。
- Chart.js エンドポイント（`AnalyticsController`）の `{ labels, data }` レスポンス形状を変更しない。

## テスト追加ガイド

- 新しい Controller ロジックには `InMemory` DbContext を使ったテストを追加する。Mock よりも `InMemory` を優先。
- `UserContextHelper.AttachUser()` でテスト用ユーザーコンテキストを設定する。
- `TempData` を使う Controller は `TestTempData` を注入する。
- テストクラス名: `<対象クラス名>Tests`（例: `PreventiveMeasuresControllerTests`）

## セキュリティ

- `SeedAccounts` のパスワードは絶対にコミットしない（User Secrets または環境変数を使用）。
- Production では HTTPS リダイレクト + HSTS が有効。ローカル開発でも `https://` で動作確認を推奨。
- 認証 Cookie は `HttpOnly=true`, `SameSite=Strict`。JavaScript から Cookie を操作しない。
