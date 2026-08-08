# syntax=docker/dockerfile:1
# マルチステージビルド: SDK でビルド → aspnet ランタイムに発行物のみコピー。
# 既定は SQLite プロバイダでの動作確認用。本番 (SQL Server / PostgreSQL) に切り替える際は
# CLAUDE.md のマイグレーション再生成手順に従い、Database__Provider と ConnectionStrings__DefaultConnection を環境変数で上書きする。

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# TypeScript をコンパイルするために Node/npm を build ステージへ持ち込む。
# .csproj の CompileTypeScript ターゲットが `npm ci` と `npx --no-install tsc` を実行するため、
# Node が無いと publish が "npm: not found" (MSB3073) で失敗する。
# SkipTsBuild=true で回避してはいけない: wwwroot/js/*.js は tsc の生成物で Git 管理外のため、
# スキップすると JS を一切含まないイメージが出来上がり、ダッシュボード/分析のグラフが動かなくなる。
# apt ではなく公式 node イメージからコピーするのは、ビルドを再現可能にし
# (バージョンがタグで固定される)、ネットワーク越しのパッケージ取得を減らすため。
# sdk:8.0 は Debian 12 (bookworm) ベースなので、glibc を揃えるため node も bookworm 系を使う。
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node
COPY --from=node:22-bookworm-slim /usr/local/lib/node_modules /usr/local/lib/node_modules
# npm / npx は node_modules 内の CLI スクリプトへのシンボリックリンクとして提供される。
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Restore を先に走らせるために csproj だけ先にコピーしてレイヤキャッシュを効かせる。
COPY IncidentInsight.sln .
COPY src/IncidentInsight.Web/IncidentInsight.Web.csproj src/IncidentInsight.Web/
COPY tests/IncidentInsight.Tests/IncidentInsight.Tests.csproj tests/IncidentInsight.Tests/
RUN dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj

# npm の依存も同様に、マニフェストだけ先にコピーしてレイヤキャッシュを効かせる。
# ここで node_modules を用意しておくと、後続の publish 内の CompileTypeScript が
# `npm ci` をスキップし (Condition="!Exists(node_modules)")、ソース変更のたびに
# 依存を取り直さずに済む。
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN dotnet publish src/IncidentInsight.Web/IncidentInsight.Web.csproj \
    -c Release \
    -o /app/publish \
    --no-restore \
    /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# SQLite 既定構成では起動時に /app 直下へ DB ファイル (incident_insight.db) を作成するため、
# WORKDIR と publish 先を app ユーザに所有させたうえで非 root 実行に切り替える。
COPY --from=build --chown=app:app /app/publish .
RUN chown app:app /app

USER app

ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_GCServer=1

EXPOSE 8080

# aspnet ベースイメージには curl/wget が含まれないため Dockerfile の HEALTHCHECK は同梱しない。
# Kubernetes / ECS などのオーケストレータ側から GET /health を叩いて liveness/readiness を判定すること。

ENTRYPOINT ["dotnet", "IncidentInsight.Web.dll"]
