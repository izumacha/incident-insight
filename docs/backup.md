# データベースバックアップ運用ガイド

医療インシデントデータ（PHI を含む）を失わないための定期バックアップ手順。
helpdesk-hub のバックアップ自動化（`backup.yml` + `scripts/backup-db.sh`）を移植したもので、
**PostgreSQL 配備（`Database:Provider=postgres`）** を対象に `pg_dump` で定期ダンプし、世代管理しながら保管する。

> 既定プロバイダの **SQLite 配備**（単一クリニック / dev）はこのガイドの対象外。
> アプリ停止中のファイルコピーで足りるため [operations.md](operations.md) の手順を使う。

## スクリプト

| スクリプト | 役割 |
| --- | --- |
| `scripts/backup-db.sh` | `pg_dump` で custom 形式 (圧縮込み) のダンプを作成し、古い世代を削除する |
| `scripts/restore-db.sh` | `pg_restore` でダンプから復元する（**既存データを上書き**） |

```bash
DATABASE_URL="postgresql://user:***@host:5432/incidentinsight" bash scripts/backup-db.sh
bash scripts/backup-db.sh --dry-run   # 実行内容だけ確認（dump しない）
DATABASE_URL="..." bash scripts/restore-db.sh var/backups/incident_insight_YYYYMMDD_HHMMSS.dump
```

## 設定（環境変数）

| 変数 | 既定 | 説明 |
| --- | --- | --- |
| `DATABASE_URL` | （必須） | ダンプ対象 PostgreSQL の接続文字列 |
| `BACKUP_DIR` | `./var/backups` | ダンプの保存先。本番では永続ボリュームを指定する |
| `BACKUP_RETENTION_DAYS` | `14` | 保持日数。これより古い `*.dump` は自動削除される |

ダンプは PHI（インシデントの自由記述・関係者情報等）を含むため、`var/backups/` は `.gitignore` 済み
（リポジトリにコミットしない）。

### 保存先の権限

`backup-db.sh` は先頭で `umask 077` を設定するため、**新規に作成する**ダンプは `0600`、新規に作成する
保存先ディレクトリは `0700`（作成した本人だけが読める）になる。`pg_dump` は `--file` の出力を既定の
umask のまま作るので、これが無いと多くのホストの既定 umask `022` では `0644` = 同じホストの全ユーザーが
PHI を読める状態になってしまう。

ただし **既に存在するディレクトリの権限は umask では変わらない**。永続ボリューム等の既存ディレクトリを
`BACKUP_DIR` に指定する場合は、運用側で明示的に絞ること:

```bash
install -d -m 700 -o backup -g backup /var/backups/incident-insight
```

### 接続情報の渡し方

`DATABASE_URL` は `pg_dump` / `pg_restore` の**引数**として渡るため、同じホストにログインできる他の
ユーザーからは `ps` や `/proc/<pid>/cmdline` で見える。URL にパスワードを埋め込むと、そのパスワードも
一緒に見えてしまう。共有ホストではパスワードを URL から外し、環境変数かパスワードファイルで渡すこと
（libpq が自動的に補完するため、スクリプト側の変更は不要）:

```bash
# URL からパスワードを外し、PGPASSWORD で渡す（環境変数は cmdline と違い他ユーザーから読めない）
DATABASE_URL="postgresql://backup_ro@localhost:5432/incidentinsight" \
    PGPASSWORD="..." bash scripts/backup-db.sh

# あるいは ~/.pgpass（0600 必須。ファイルなので cron 定義にも履歴にも残らない）
printf 'localhost:5432:incidentinsight:backup_ro:...\n' > ~/.pgpass && chmod 600 ~/.pgpass
DATABASE_URL="postgresql://backup_ro@localhost:5432/incidentinsight" bash scripts/backup-db.sh
```

GitHub Actions のランナーは 1 ジョブ専有の使い捨て VM で他ユーザーが同居しないため、`backup.yml` は
`BACKUP_DATABASE_URL` にパスワードを含めた形のままで問題ない。

## 自動化の選択肢

### 1. GitHub Actions（`.github/workflows/backup.yml`）

毎日 JST 03:00（cron `0 18 * * *` UTC）に実行。手動実行も可。次の 2 つのリポジトリ Secret を
両方設定すると有効化され、**GPG（AES256 対称鍵）で暗号化したダンプ**を artifact として 7 日間保持する。

| Secret | 説明 |
| --- | --- |
| `BACKUP_DATABASE_URL` | ダンプ対象 PostgreSQL の接続文字列（読み取り専用ロール推奨）。未設定ならジョブは安全に no-op で終了する |
| `BACKUP_ENCRYPTION_PASSPHRASE` | ダンプの GPG 暗号化パスフレーズ。`BACKUP_DATABASE_URL` があるのにこれが無い場合、**平文の PHI を artifact に載せないためジョブは失敗する**（fail-closed） |

暗号化済み artifact（`*.dump.gpg`）の復号:

```bash
gpg --batch --decrypt --pinentry-mode loopback --passphrase-fd 0 \
    --output incident_insight_YYYYMMDD_HHMMSS.dump incident_insight_YYYYMMDD_HHMMSS.dump.gpg
# (標準入力からパスフレーズを渡す。echo でシェル履歴に残さないこと)
```

> ⚠️ このリポジトリは **public** のため、平文の artifact は事実上誰でもダウンロードできてしまう。
> ワークフローが暗号化を必須にしているのはこのため。パスフレーズは十分に長いランダム値を使い、
> パスワードマネージャ等で管理する。PHI（暗号化済みであっても）を GitHub に一切置けない
> 運用要件（院内規程・契約等）がある場合は本ワークフローを使わず、次のホスト cron を使う。

### 2. ホスト cron（PHI を外部に出さない運用）

本番サーバー（または DB に到達できるホスト）の crontab に登録する:

パスワードは URL に埋め込まず `~/.pgpass`（`0600`）に置く（「接続情報の渡し方」参照）。
crontab に書くとバックアップ実行中の `ps` 出力にも載ってしまうため:

```cron
# 毎日 03:00 にバックアップ（出力は syslog/logger 等へ）
0 3 * * * cd /opt/incident-insight && DATABASE_URL="postgresql://backup_ro@localhost:5432/incidentinsight" \
    BACKUP_DIR=/var/backups/incident-insight BACKUP_RETENTION_DAYS=30 \
    bash scripts/backup-db.sh >> /var/log/incident-insight-backup.log 2>&1
```

### 3. Docker / マネージド DB 環境

DB コンテナに `pg_dump` が同梱されていれば、ホストから直接ダンプできる:

```bash
docker compose exec -T db pg_dump --format=custom --no-owner --no-privileges \
    -U postgres incidentinsight > "var/backups/incident_insight_$(date +%Y%m%d_%H%M%S).dump"
```

Supabase / Azure Database / Aurora 等のマネージド DB は、プロバイダ標準の自動バックアップを
一次手段とし、本スクリプトはオフサイト世代管理の補完として使う。

## 復元手順

1. 復元先 `DATABASE_URL` を確認する（**上書きされる**ので接続先を間違えない）。
2. 復元を実行する:

   ```bash
   DATABASE_URL="postgresql://postgres:***@localhost:5432/incidentinsight" \
       bash scripts/restore-db.sh var/backups/incident_insight_YYYYMMDD_HHMMSS.dump
   ```

3. 復元後にアプリを起動して動作確認する（起動時 `Database.Migrate()` が整合を確認する）。

## 検証（リストアテスト）

バックアップは「復元できて初めて有効」。定期的に空 DB へリストアして整合を確認する:

```bash
createdb incidentinsight_restore_test
DATABASE_URL="postgresql://postgres:***@localhost:5432/incidentinsight_restore_test" \
    bash scripts/restore-db.sh var/backups/<最新>.dump
dropdb incidentinsight_restore_test
```
