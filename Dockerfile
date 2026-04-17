# syntax=docker/dockerfile:1
# マルチステージビルド: SDK でビルド → aspnet ランタイムに発行物のみコピー。
# 既定は SQLite プロバイダでの動作確認用。本番 (SQL Server / PostgreSQL) に切り替える際は
# CLAUDE.md のマイグレーション再生成手順に従い、Database__Provider と ConnectionStrings__DefaultConnection を環境変数で上書きする。

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore を先に走らせるために csproj だけ先にコピーしてレイヤキャッシュを効かせる。
COPY IncidentInsight.sln .
COPY src/IncidentInsight.Web/IncidentInsight.Web.csproj src/IncidentInsight.Web/
COPY tests/IncidentInsight.Tests/IncidentInsight.Tests.csproj tests/IncidentInsight.Tests/
RUN dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj

COPY . .
RUN dotnet publish src/IncidentInsight.Web/IncidentInsight.Web.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# 非 root ユーザで実行 (aspnet イメージに同梱の app ユーザを使用)。
USER app

ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_GCServer=1

EXPOSE 8080

COPY --from=build /app/publish .

# aspnet ベースイメージには curl/wget が含まれないため Dockerfile の HEALTHCHECK は同梱しない。
# Kubernetes / ECS などのオーケストレータ側から GET /health を叩いて liveness/readiness を判定すること。

ENTRYPOINT ["dotnet", "IncidentInsight.Web.dll"]
