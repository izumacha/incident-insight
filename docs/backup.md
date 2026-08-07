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
（リポジトリにコミットしない）。保存先ディレクトリのアクセス権限は必ず絞ること。

## 自動化の選択肢

### 1. GitHub Actions（`.github/workflows/backup.yml`）

毎日 JST 03:00（cron `0 18 * * *` UTC）に実行。手動実行も可。
リポジトリ Secret `BACKUP_DATABASE_URL` を設定すると有効化され、ダンプを artifact として
7 日間保持する。**未設定ならジョブは安全に no-op で終了する**（fail-closed）。

> ⚠️ artifact には本番データ = **PHI が含まれ得る**。リポジトリ/Actions のアクセス権限を絞り、
> 可能なら読み取り専用 DB ロールを `BACKUP_DATABASE_URL` に使う。PHI を GitHub に置けない
> 運用要件（院内規程・契約等）がある場合は本ワークフローを使わず、次のホスト cron を使う。

### 2. ホスト cron（PHI を外部に出さない運用）

本番サーバー（または DB に到達できるホスト）の crontab に登録する:

```cron
# 毎日 03:00 にバックアップ（出力は syslog/logger 等へ）
0 3 * * * cd /opt/incident-insight && DATABASE_URL="postgresql://backup_ro:***@localhost:5432/incidentinsight" \
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
