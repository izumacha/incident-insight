## Operations（運用）

### バックアップ / リストア（SQLite）

- DB ファイル: `incident_insight.db`（既定）

**バックアップ**

```bash
cp incident_insight.db incident_insight.db.bak
```

**リストア**

```bash
cp incident_insight.db.bak incident_insight.db
```

> ※ アプリ停止中に実施してください。

### バックアップ（PostgreSQL / 定期ダンプの自動化）

PostgreSQL 配備（`Database:Provider=postgres`）では `pg_dump` による定期バックアップを
自動化しています（GitHub Actions `backup.yml` またはホスト cron ＋ `scripts/backup-db.sh`）。
設定・復元・リストアテストの手順は [backup.md](backup.md) を参照してください。

### 監査ログの運用

- 監査ログは `AuditLogs` テーブルに JSON 形式で記録されます。
- 重要操作（削除、権限変更など）を監査対象に含めることを推奨します。
- 運用では「保持期間」「エクスポート」「閲覧権限」を決めてください。

