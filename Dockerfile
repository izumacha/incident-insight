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
# apt ではなく公式 node イメージからコピーするのは、取得元とメジャーバージョンを
# 明示でき、apt のリポジトリ状態に依存せずに済むため。
# なお `22-bookworm-slim` は 22.x のパッチ更新で中身が変わる可動タグであり、
# ビルドがバイト単位で再現可能になるわけではない (完全固定が必要なら digest を付ける)。
# この node:<major> が CI と共有する Node バージョンの唯一の真実の源。
# .github/workflows/ci.yml の build-and-test は本行から major を読み出して setup-node に渡すため、
# ここを上げれば CI も追随する (両方に数字を直書きして片方だけ更新される事故を防ぐ)。
# タグの書式 node:<major>-... を変える場合は、読み出し側のステップも合わせて更新すること。
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
# packages.lock.json も一緒にコピーする。これが無いと RestorePackagesWithLockFile=true により
# NuGet はロックファイルを「検証」せず「新規生成」してしまい、CI の
# `dotnet restore --locked-mode` が守っている固定が、実際に配布されるイメージでは
# 効かなくなる (ロック更新漏れの PR でも docker build だけ通ってしまう)。
COPY src/IncidentInsight.Web/packages.lock.json src/IncidentInsight.Web/
COPY tests/IncidentInsight.Tests/packages.lock.json tests/IncidentInsight.Tests/
# --locked-mode で CI と同じ「ロックファイルと不一致なら失敗」の挙動に揃える。
RUN dotnet restore src/IncidentInsight.Web/IncidentInsight.Web.csproj --locked-mode

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

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
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
