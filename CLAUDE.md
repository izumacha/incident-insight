# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

IncidentInsight is a medical incident management system (ASP.NET Core 8 MVC + EF Core 8 + SQLite). It covers the full incident lifecycle: reporting → 5 Whys root-cause analysis → preventive measure planning → completion → effectiveness review → recurrence detection. UI strings and the domain vocabulary are Japanese (e.g. `重症度`, `なぜなぜ分析`, `再発防止策`).

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
dotnet ef migrations add <MigrationName> --project src/IncidentInsight.Web

# Seed demo accounts for local login (Development only; no passwords are committed)
dotnet user-secrets init --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:AdminPassword" "AdminPass1" --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:RiskManagerPassword" "RiskPass1" --project src/IncidentInsight.Web
```

Dev password policy: 8+ chars, uppercase, digit. Prod policy: 12+ chars and non-alphanumeric (see `Program.cs`). The `SeedAccounts` section only seeds accounts in `Development`; it is skipped silently if passwords are blank (a warning is logged).

## Architecture

### Request pipeline & bootstrapping (`Program.cs`)
- Single `WebApplication` configured with `ApplicationDbContext` (SQLite by default — `UseSqlite`; swap to `UseSqlServer` + update `DefaultConnection` for SQL Server).
- ASP.NET Core Identity is wired up with a custom `ApplicationUser` and three roles in `AppRoles` (`Admin`, `RiskManager`, `Staff`). Cookie auth redirects to `/Account/Login`; sliding expiration of 8h; lockout after 5 failed attempts.
- On startup (inside a scope): `db.Database.Migrate()` → `DbSeeder.Seed(db)` (cause categories + sample incidents, idempotent) → `IdentitySeeder.SeedAsync(...)` (creates roles always; creates demo admin/RM only in Development when `SeedAccounts` passwords are present).

### Domain model (EF Core, `src/IncidentInsight.Web/Models/`)
The schema is centered on four aggregates with cascade rules configured in `ApplicationDbContext.OnModelCreating`:

- **`Incident`** — the root. Holds occurrence metadata (`OccurredAt`, `Department`, `IncidentType`, `Severity`, `Description`, `ReporterName`). Severity codes (`Level0`…`Level5`), department list, and incident-type list are hard-coded `static readonly` dictionaries/arrays on the class and are the single source of truth for dropdowns and labels. Computed helpers like `SeverityLabel`, `SeverityColor`, `MeasureStatusSummary`, `MeasureStatusColor` are consumed directly in Razor views for Bootstrap badge classes.
- **`CauseAnalysis`** — 5 Whys stored as independent `Why1`..`Why5` columns (so SQL can search at specific depths). Always tied to one `CauseCategory`. Helpers: `DeepestWhy`, `WhyDepth`.
- **`CauseCategory`** — self-referential hierarchy (parent/child via `ParentId`). `BuildCauseCategoryOptions()` in `IncidentsController` emits leaf categories grouped by parent as `<optgroup>` — never add a category-picker that bypasses this helper.
- **`PreventiveMeasure`** — the "most important" entity per the domain: tracks the full lifecycle `Planned → InProgress → Completed` plus post-completion fields `EffectivenessRating` (1–5), `EffectivenessNote`, `EffectivenessReviewedAt`, and `RecurrenceObserved` (true ⇒ surface warning and prompt re-analysis). `IsOverdue` is a computed property used all over the UI; keep the `DueDate < DateTime.Today && Status != "Completed"` semantics consistent.

Indexes worth knowing about: `Incident(OccurredAt)`, `Incident(Department, IncidentType)`, `PreventiveMeasure(Status, DueDate)`, `CauseCategory(ParentId, DisplayOrder)`.

### Controllers & cross-cutting patterns
- All app controllers except `AccountController` use `[Authorize]`. `AccountController` is explicitly `[AllowAnonymous]` on `Login` / `AccessDenied`.
- `IncidentsController` hosts the registration wizard (POST `/Incidents/Create`) **and** the nested lifecycle actions for cause analyses and measures (`AddCauseAnalysis`, `EditCauseAnalysis`, `AddMeasure`, `CompleteMeasure`, `RateMeasure`, …). Create enforces "at least one preventive measure" via `HasAtLeastOneValidMeasure` — this validation is business-critical, not cosmetic. The controller also strips sub-form keys from `ModelState` before validating the parent form (see the `ModelState.Remove` loop in `Edit`).
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
- **Recurrence logic is duplicated** between `HomeController.Index` (dashboard alerts, 90-day window) and `IncidentsController.Details` (per-incident similar list, no time bound). Keep them semantically aligned if you change the matching rule.
