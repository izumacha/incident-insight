#!/bin/bash
# Claude Code on the web 用の SessionStart フック。
# 目的: リモートのエフェメラルなコンテナに .NET 8 SDK と npm 依存を入れ、
#       dotnet build / dotnet test / tsc が即座に動く状態にする。
set -euo pipefail

# ログは標準エラー出力(stderr)へ出す（§6 Bash 規約）。
# 標準出力(stdout)はフックの結果データ用に空けておき、ログと混ざらないようにする。
log() {
    echo "$@" >&2   # 受け取った文字列をそのまま stderr に出力する
}

# 環境変数の export 行を「まだ無ければ」CLAUDE_ENV_FILE に追記するヘルパー。
# SessionStart は再開(resume)・クリア(clear)・圧縮(compact)で再発火し得るため、
# 単純な追記だと同じ行が重複する。重複チェックを挟んで冪等(何度実行しても同じ結果)にする。
append_env_once() {
    local line="$1"   # 追記したい1行（例: export DOTNET_NOLOGO=1）
    # 既に同じ行が書かれていれば何もしない（grep -qxF は行全体の完全一致を固定文字列で判定）。
    if ! grep -qxF "$line" "$CLAUDE_ENV_FILE" 2>/dev/null; then
        echo "$line" >> "$CLAUDE_ENV_FILE"   # まだ無い場合だけ末尾に追記する
    fi
}

# リモート環境 (Claude Code on the web) 以外では何もしない。
# ローカルの開発機ではユーザー自身の dotnet 環境を尊重するため早期 return する。
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    exit 0
fi

# リポジトリのルートへ移動する（フックは任意の cwd から呼ばれ得るため）。
cd "${CLAUDE_PROJECT_DIR:-$(pwd)}"

# root 以外で実行された場合に備えて sudo を補う小さなヘルパー。
# root ならそのまま、非 root なら sudo を前置して特権コマンドを実行する。
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"            # すでに root なのでそのまま実行
    else
        sudo "$@"       # 一般ユーザーなら sudo で昇格して実行
    fi
}

# --- .NET 8 SDK の用意 ---------------------------------------------------
# 公式インストーラ (dot.net / builds.dotnet.microsoft.com) は組織のegress
# ポリシーでブロックされるため使えない。Ubuntu 24.04 の apt リポジトリが
# .NET 8 を同梱しているので、そちらからインストールする。
if command -v dotnet >/dev/null 2>&1; then
    # すでに dotnet がある（コンテナキャッシュがヒットした）場合はスキップ。
    log "dotnet は既にインストール済み: $(dotnet --version)"
else
    log ".NET 8 SDK を apt からインストールします..."
    # パッケージ一覧を更新（ブロックされた PPA の失敗は警告どまりで無視される）。
    as_root apt-get update -qq || true
    # .NET 8 SDK 本体を非対話モードでインストールする。
    DEBIAN_FRONTEND=noninteractive as_root apt-get install -y dotnet-sdk-8.0
    # インストール結果を確認のため表示する。
    log "dotnet をインストールしました: $(dotnet --version)"
fi

# テレメトリ送信と初回実行メッセージを抑止して、ビルドを静かに保つ。
# append_env_once で重複追記を防ぎ、再発火しても env ファイルが膨らまないようにする。
append_env_once 'export DOTNET_CLI_TELEMETRY_OPTOUT=1'
append_env_once 'export DOTNET_NOLOGO=1'

# --- フロントエンドの npm 依存（tsc 型チェック用）-----------------------
# package.json があり npm が使える場合のみ devDependencies を入れる。
# キャッシュ活用のため再現性重視の `npm ci` ではなく `npm install` を使う。
if [ -f package.json ] && command -v npm >/dev/null 2>&1; then
    log "npm 依存をインストールします..."
    npm install
fi

# --- .NET 依存の事前復元 -------------------------------------------------
# 起動直後の初回ビルドを速くするため NuGet パッケージを先に復元しておく。
log "dotnet restore を実行します..."
dotnet restore

log "SessionStart フック完了。"
