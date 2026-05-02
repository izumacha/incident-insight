# AGENTS.md

## Cursor Cloud specific instructions

### Service overview

IncidentInsight is a self-contained ASP.NET Core 8 MVC monolith with an embedded SQLite database. No external services (Docker, databases, message queues) are required for local development.

### Running the application

```bash
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj
```

- The dev server port is **assigned dynamically** by the ASP.NET launch profile (check terminal output for `Now listening on: http://localhost:<port>`). Do **not** hardcode port 5000.
- On first launch, SQLite DB is auto-created and migrations + seed data are applied automatically.
- Health check: `GET /health` (no auth required).

### Demo accounts

Demo accounts are seeded only in `Development` environment. Passwords must be set via User Secrets before first run:

```bash
dotnet user-secrets init --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:AdminPassword" "AdminPass1" --project src/IncidentInsight.Web
dotnet user-secrets set "SeedAccounts:RiskManagerPassword" "RiskPass1" --project src/IncidentInsight.Web
```

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@hospital.local | AdminPass1 |
| RiskManager | riskmanager@hospital.local | RiskPass1 |

### Common commands

See `CLAUDE.md` for the full command reference. Key commands:

- **Build**: `dotnet build`
- **Test**: `dotnet test` (126 xUnit tests using InMemory provider)
- **Run**: `ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/IncidentInsight.Web/IncidentInsight.Web.csproj`

### Gotchas

- The `IncidentType` field uses enum values (e.g. `PatientIdentification`, `Fall`, `Medication`), not Japanese display strings, when posting forms.
- The `Severity` field uses string codes like `Level0`..`Level5`, not labels.
- The `Department` field uses Japanese strings directly (e.g. `外来`, `外科病棟`, `ICU`).
- The `UserSecretsId` is set in the `.csproj` — `dotnet user-secrets init` only needs to run once; subsequent runs are idempotent.
- Anti-forgery tokens are required on all POST endpoints. When testing via curl, fetch a fresh token from the GET page before each POST.
