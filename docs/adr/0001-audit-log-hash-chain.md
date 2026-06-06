# ADR 0001: 監査ログのハッシュチェーン化（改ざん不能化）

- ステータス: 提案中（Accepted 前の凍結ドラフト）
- 日付: 2026-06-06
- 関連: `AuditSaveChangesInterceptor`、`AuditLog`、`SensitiveAttribute`、`IClock`、Issue #31 / #37（時刻統一）

> このドキュメントは「改ざん不能・予測する再発防止エンジン」化の第一手として、
> 最も繊細な **ハッシュチェーンの決定性（determinism）** を実装前に凍結するための設計判断記録です。
> 本 ADR の段階では **コード・スキーマ・migration は一切変更しません**（自動適用 migration による事故回避のため）。

---

## コンテキスト

IncidentInsight は医療インシデント管理システムであり、`Incident` / `CauseAnalysis` / `PreventiveMeasure` の
変更を `AuditSaveChangesInterceptor` が `AuditLogs` テーブルへ自動記録しています。これは規制対応の監査証跡です。
現状の不変条件は次のとおりで、本 ADR はこれらの **上に載せる**ものであり、いずれも壊しません。

- **監査は `SaveChanges` 経由必須**。`ExecuteUpdate` / `ExecuteDelete` は変更追跡を迂回し監査を飛ばすため禁止
  （`docs/architecture.md` / CLAUDE.md「Things to watch for」参照）。
- **PHI（個人情報・自由記述）は平文で `AuditLog.ChangesJson` に残さない**。
  `[Sensitive(Mask.Redact)]` / `[Sensitive(Mask.Hash)]` を付けた列はインターセプタが reflection で
  読み取り、`[REDACTED]` または塩付き SHA-256 の先頭 8 桁へ置換してから書き込む。
- **provider 非依存**。SQLite / SQL Server / PostgreSQL のいずれでも同一コードで動作し、
  provider 固有 SQL / 列型を持ち込まない（CLAUDE.md「Don't add provider-specific SQL or column types」）。
- **時刻源は `IClock` に集約**。`AuditLog.ChangedAt` は運用ローカル時刻（JST）で保存される（Issue #31 / PR #37）。

しかし現状の監査ログには「**記録された後に書き換えられていないこと（非改変）を証明する仕組み**」がありません。
DB に直接アクセスできる者が過去行を静かに書き換える、あるいは行を削除しても、それを検出する手段がない。
規制監査では「監査ログそのものが信頼できる（改ざんされていない）」ことの立証が求められます。

そこで各 `AuditLog` 行を **暗号学的ハッシュで前の行と連結（チェーン化）** し、1 行でも改変されると
以降のハッシュが一致しなくなる仕組みを導入します。本 ADR はその設計を凍結します。

---

## 決定

`AuditLog` に **ハッシュチェーン列** を追加し、行ごとのハッシュをアプリ層（インターセプタ）で逐次計算する。

### 追加する列

`AuditLog` に追加する列:

| 列 | 型 | 意味 |
|---|---|---|
| `Sequence` | `long` | チェーン上の通し番号。直列化カウンタ（`AuditChainState`）で採番し、`AuditLog.Id` には依存しない（決定性の肝①参照）。 |
| `PrevHash` | `string`（64 hex / `MaxLength(64)`） | 直前の行の `RowHash`。先頭行はジェネシス値。 |
| `RowHash` | `string`（64 hex / `MaxLength(64)`） | この行のハッシュ。下式で算出。 |

新規テーブル `AuditChainState`（シングルトン行）:

| 列 | 型 | 意味 |
|---|---|---|
| `Id` | 固定キー | 常に 1 行のみ（シングルトン）。 |
| `LastSequence` | `long` | 直近に発行した `Sequence`。次の採番は `LastSequence + 1`。 |
| `LastRowHash` | `string`（64 hex） | チェーン先端の `RowHash`。次行の `PrevHash` になる。 |
| `ConcurrencyToken` | `Guid`（`[ConcurrencyCheck]`） | 先端更新の直列化用。**毎回新しい Guid に回転**する（決定性の肝①参照）。 |

**migration でのシード（決定的初期化）**: `AuditChainState` の唯一行（`Id=1`）は、列追加と同じ migration で
**決定的に作成**する（`LastSequence=0`、`LastRowHash=` ジェネシス値、`ConcurrencyToken=` 新規 Guid）。
アプリ起動時の**遅延生成に頼ると、初回追記が並行したときトークンが存在する前にレース**が起き得るため、
**インターセプタを有効化する前に**この行が必ず存在するようにする。既存ログがある DB では、migration / バックフィルが
既存 `AuditLog` を **`Id` 昇順で読み `Sequence` を採番しつつジェネシス封印**し、その結果で先端
（`LastSequence` / `LastRowHash`）を埋めてから有効化する。

### ハッシュ式

```
RowHash = SHA256( PrevHash ‖ 正準化シリアライズ(ChangedAt, ChangedBy, EntityName, EntityKey, Operation, ChangesJson) )
```

- `‖` は連結。`PrevHash` は **そのままの 64 hex 文字列**として正準バイト列の先頭に置く。
- `SHA256` の出力は 64 桁小文字 hex で `RowHash` 列に格納する。
- 計算は **アプリ層 `AuditSaveChangesInterceptor` で逐次** 行う。
  **DB トリガ / computed column は採用しない**（provider 依存になり、provider 非依存の不変条件を破るため。後述「却下した代替」A1）。

---

## 決定性の肝（determinism）

ハッシュチェーンの価値は「いつ・どの provider で・誰が再計算しても **同じバイト列 → 同じハッシュ** になる」ことに尽きる。
以下を凍結する。

### ① 順序の正準 = 直列化された `Sequence`（単調増加カウンタ）

チェーンは「行の並び順」に依存する。並びの正準を **`Sequence`（単調増加 long）の昇順** に固定する。
`Sequence` は DB 自動採番の `AuditLog.Id` に依存させない。後述の原子性要件のため、
**`RowHash` を計算する前に順序番号が確定している必要がある**（`Id` は挿入後にしか分からない）。

#### 原子性（atomicity）— ハッシュ未設定の行を絶対にコミットしない

> Codex レビュー（PR #65, P1）の指摘に対応。

「①行を `Id` 採番のためにいったんコミット → ②あとから `RowHash` を埋めて再コミット」という
**後追い更新（committed-then-update）は採用しない**。プロセスがフェーズ間でクラッシュすると
`RowHash` 未設定の行が確定したまま残り、別リクエストがその未完成行から連結すると
**チェーンが恒久的に壊れる / 分岐（fork）する**ためである。

代わりに、**監査行はその `RowHash` まで含めて 1 つの明示トランザクションで「完成形のまま」コミットする**。
肝は「**未ハッシュ行を一切コミットしない**」ことであって「`SaveChanges` を 1 回に限る」ことではない。
ここで `Added` エンティティの主キーは DB 採番のため保存前には確定せず（`EntityKey` はハッシュ入力に含まれる）、
ハッシュ計算には確定後のキーが要る。そこで業務変更の `SaveChanges` で**キーを確定させてから**ハッシュを計算するが、
**全体を 1 つの明示トランザクション（`BeginTransaction`）で包んで一括コミット**することで原子性を保つ:

1. **トランザクション開始**: `db.Database.BeginTransaction()`（同一接続・同一トランザクション）。
2. **業務変更を保存しキーを確定**: `Incident` / `CauseAnalysis` / `PreventiveMeasure` の `SaveChanges`。
   これで `Added` 行の **DB 採番キーが確定**し、`EntityKey` を正しく取得できる。
3. **チェーン先端を読み取り**: シングルトン行 `AuditChainState`（`LastSequence` / `LastRowHash` / `ConcurrencyToken`）を取得。
4. **採番とハッシュ計算（挿入前）**: `Sequence = LastSequence + 1`、`PrevHash = LastRowHash`、
   **確定済みの `EntityKey`** を使って式に従い `RowHash` を算出する。
5. **完成行の挿入 + 先端更新**: `RowHash` まで埋めた `AuditLog` 行を挿入し、`AuditChainState` の
   `LastSequence` / `LastRowHash` を更新し、**`ConcurrencyToken` を新しい Guid に回転**する（直列化のため。後述）。
6. **コミット**: トランザクションをコミット。手順 2〜5 は **まとめて** 確定し、途中状態（未ハッシュ行）は外から観測されない。
   いずれかで失敗すれば **トランザクションごと巻き戻る**（業務変更も監査も残らない）。

`Added` の DB 採番キーをハッシュに含めるため「保存 → キー確定 → ハッシュ → 監査挿入」の順序は避けられないが、
**明示トランザクションで包む**ことで「未ハッシュ行をコミットしない」原子性と両立する。
（`SaveChanges` 単発でも既定でトランザクション境界は張られるが、上記キー確定の都合上、ここでは
**明示トランザクション + 2 回の `SaveChanges`** を正準とする。）

#### 直列化（serialized writers）— 分岐（fork）を防ぐ

同時に 2 つの追記が走ると、両者が同じ `LastRowHash` から枝分かれし得る。これを防ぐため
**`AuditChainState` 行を唯一の直列化点**とし、provider 非依存の手段で「1 度に 1 ライターだけが先端を伸ばせる」ようにする:

- `AuditChainState` に `[ConcurrencyCheck]` トークン（`ConcurrencyToken` と同型の Guid）を持たせ、先端更新で
  楽観的同時実行を効かせる。**衝突した追記は `DbUpdateConcurrencyException` で失敗 → トランザクションごと巻き戻し →
  再試行**する（業務変更も監査も中途半端に残らない）。
- **先端更新のたびに `ConcurrencyToken` を新しい Guid に回転させる**（既存インターセプタが業務エンティティの
  `ConcurrencyToken` を Modified 時に回す挙動と同じ）。**回転しないと直列化が破れる**: 両ライターが同じ元トークン値を
  `WHERE` 条件に使うため、EF の楽観ロックが両方とも成功し（2 つ目の `UPDATE` も元の値を見てしまう）、
  同じ `LastRowHash` から fork する。トークンを回して初めて、後発ライターの
  `UPDATE ... WHERE ConcurrencyToken = <旧値>` が 0 行一致になり `DbUpdateConcurrencyException` で弾かれる。
- これは SQLite / SQL Server / PostgreSQL すべてで同一に成立する（provider 固有のロック構文に依存しない＝
  provider 非依存の不変条件を保つ）。
- `AuditLog` / `AuditChainState` 自身は監査対象外なので、再帰的に監査が増えることはない（現行の不変条件と同じ）。

- 同一トランザクションで複数の業務行が変わる場合も、`Sequence` 昇順で 1 本のチェーンに連結する。
- `Sequence` を `Id` から独立させることで、Id 体系を将来変えても順序意図が保たれ、かつ
  「挿入前にハッシュ計算 → 完成行を 1 回で書く」原子性が成立する。

#### 競合再試行時の状態保持（state-preserving retry）

手順 5 の先端更新が競合で失敗したとき、明示トランザクションを巻き戻すだけでは**安全に再試行できない**。
呼び出し側が既定の `SaveChangesAsync()` を使うと、手順 2 の業務 `SaveChanges` 完了時点で EF は業務エントリを
`Unchanged` に受理してしまい、巻き戻し後に**同一コンテキストで業務 insert/update/delete を再生できない**。
そこで次のいずれかを**実装前に凍結**する:

- **`SaveChanges(acceptAllChangesOnSuccess: false)` を使い、`AcceptAllChanges()` は監査挿入のコミット成功後にのみ呼ぶ**。
  競合時はエントリ状態が保持されるため、トランザクション巻き戻し後に**同一コンテキストでそのまま再試行**できる。
- もしくは **2 セーブ + トランザクションのオーケストレーションを `SavedChanges` インターセプタの外**（明示的な
  Unit of Work ラッパ）に出し、競合時はラッパが業務変更ごとリトライする。
  いずれにせよ「競合 → 巻き戻し → 業務変更を含めて再生 → 成功してから `AcceptAllChanges`」を原則とする。

### ② バイト列の正準化（provider 間で同一バイト列）

- **時刻は「往復一致する正準スカラー/文字列」として永続化し、それをハッシュする**。`"o"`（round-trip, ISO 8601）整形
  **だけ**では provider 往復差は消えない: `SystemClock` は `Kind=Local` の値を供給する一方、
  SQLite / SQL Server / PostgreSQL は再読込時に `Kind` や小数秒精度を変え得る。**挿入前に計算した `RowHash`** と、
  **検証時に再読込した値から再計算した `RowHash`** がズレると、無改ざんの行が provider 次第で検証 NG になる。
  さらに `DateTime.Kind` は `Local` / `Utc` / `Unspecified` しか持てず **JST の固定オフセットを表現できない**ため、
  `DateTime` 列に「正規化した Kind」を入れても往復で失われる。これを防ぐため、ハッシュ対象の時刻は
  **`DateTimeOffset`（固定 +09:00）または正準文字列（固定精度の `"o"` 文字列）/ epoch ミリ秒の `long` を、
  EF 値コンバータで往復無損失に永続化**し、**「保存した値 ＝ ハッシュした値 ＝ 検証時に再読込する値」がバイト一致**する
  ようにする（`"o"` で“差を隠す”のではなく、保存前に差を“消し”、その消した値そのものを保存・ハッシュする）。
  実装時は `ChangedAt` の列型/コンバータをこの正準表現に合わせる。
- **列順を固定**: `ChangedAt → ChangedBy → EntityName → EntityKey → Operation → ChangesJson` の順。
- **enum / JSON は既存の `JsonStringEnumConverter` を流用**し、`ChangesJson` は文字列としてそのまま連結する
  （`ChangesJson` は既にインターセプタが `JsonStringEnumConverter` で生成済みの文字列なので、再シリアライズしない）。
- 文字コードは **UTF-8** に固定（既存 `ComputeShortHash` と同じ `Encoding.UTF8`）。
- null は固定トークン（例: 空文字ではなく `\x00` 区切り等、実装時に 1 箇所で定義）で表し、
  `ChangesJson == null`（Added/Deleted で差分なし）でも一意なバイト列になるようにする。

### ③ 入力は **PHI マスキング後の `ChangesJson`**

チェーンの入力には **マスキング適用後（`[REDACTED]` / 塩付きハッシュ済み）の `ChangesJson`** を使う。
これにより以下を両立する:

- **平文 PHI ゼロ**: ハッシュの入力にも平文 PHI が混じらない（マスキング後の文字列のみ）。
- **チェーン全行被覆**: マスキングされた行も含め、すべての監査行がチェーンに乗る。
  「PHI を含むから除外」という穴を作らない（除外するとその行の改ざんを検出できなくなる）。

### ④ 塩（`Audit:HashSalt`）は **PHI ハッシュ専用。チェーンには混ぜない**

`Audit:HashSalt`（`[Sensitive(Mask.Hash)]` 用の塩）は **PHI 値の相関防止専用**であり、
**チェーンの `RowHash` 計算には一切混ぜない**。理由:

- 塩は運用上ローテーション（再生成）され得る。チェーンに塩を混ぜると、**塩を回した瞬間に過去全行の
  `RowHash` が再計算不能 → 全検証が不能**になる致命的事故が起きる。
- チェーンは「公開検証可能（誰でも再ハッシュして照合できる）」であるべきで、秘密鍵を要求してはならない。
  秘密値による真正性は別レイヤ（後述の `AuditCheckpoint` の HMAC 封印）が担う。

> 整理: **PHI マスキング**は塩あり SHA-256（相関防止）。**チェーン RowHash** は塩なし SHA-256（公開検証）。
> **封印 Checkpoint** は運用鍵の HMAC（真正性）。3 つの暗号用途を混同しない。

### ⑤ テーブル空時のジェネシス値

`AuditLogs` が空（最初の 1 行）のとき、`PrevHash` には固定の **ジェネシス値**（実装時に 1 箇所で定義する
定数、例: 64 桁の `0`）を入れる。これにより「先頭行が後から差し込まれた／削られた」改ざんも検出できる
（先頭の `PrevHash` がジェネシス値でなければ異常）。

---

## 検証と封印

### チェーン検証（純粋関数 `AuditChainVerifier`）

- 検証ロジックは **純粋関数 `AuditChainVerifier`** として切り出す。`RecurrenceDetector.FindSimilar` と同じ方針で、
  **DB アクセスを持たず in-memory のリスト（`AuditLog` を `Sequence` 昇順に並べた列）と `AuditChainState` の
  先端（`LastSequence` / `LastRowHash`）を受け取る**。IO（DB 読み出し）は呼び出し側（コントローラ）が制御し、
  InMemory でテスト可能にする（`RecurrenceServiceTests` / `RecurrenceDetectorTests` と同じテスト戦略）。
- **走査順は必ず `Sequence` 昇順**（`Id` 昇順ではない）。`Sequence` こそ `PrevHash`/`RowHash` を計算した正準順序であり、
  将来のバックフィル / インポート / provider の identity 挙動で `Id` 順が `Sequence` 順とズレても、検証は
  「ハッシュを計算した順序」と同じ順序で行う。`Id` は **報告用の行識別子** としてのみ使う。
- 検証手順: 各行を `Sequence` 昇順に走査し、`PrevHash`（先頭はジェネシス値）と正準化バイト列から `RowHash` を再計算し、
  格納値と一致するか・前行の `RowHash` と当行の `PrevHash` が連結しているか・`Sequence` が飛びなく連番かを確認。
  **最初に不一致になった行（`Sequence` と報告用 `Id`）を報告**する。
- **末尾削除（tail truncation）の検出**: 内部リンクだけだと、最新行をまるごと削除しても残りの
  `PrevHash`/`RowHash` 連結は整合したままなので「健全」と誤判定し得る。これを防ぐため、検証は
  **チェーン末尾を `AuditChainState` の `LastSequence` / `LastRowHash` と必ず突合**する
  （`AuditChainState` は **Phase 1 で導入する持続的アンカー**）。最終行の `Sequence`/`RowHash` が先端と一致しなければ
  末尾欠落／改変と判定する。
  **ただし `AuditChainState` は同一 DB 内にあるため、これで確実に検知できるのは「事故・不完全な切詰め」**
  （アプリ不具合や、tip を更新せずに行だけ消した削除）**に限る**。`AuditLog` を直接書ける特権攻撃者は、
  末尾行を消したうえで `AuditChainState` の tip も新末尾へ書き戻せるため **Phase 1 単独では検知できない**。
  この**特権・DB 直書きによる末尾切詰めへの保証は、Phase 2 の DB 外退避 ＋ HMAC 封印 `AuditCheckpoint` に依存する**
  （封印値を DB 外の WORM/別系に置き、DB 内の全体差し替えと突合する）。Phase 1 の主張は上記スコープに限定する。

### 管理者専用の検証アクション

- `AuditLogsController` に **管理者（`AppRoles.Admin`）専用**のチェーン検証アクションを追加する。
  全行を `Sequence` 昇順で読み出し（`SaveChanges` を介さない読み取り専用クエリ）、`AuditChainState` の先端とともに
  `AuditChainVerifier` に渡して「全件健全」または「最初に壊れた行（`Sequence`/`Id`）／末尾欠落」を表示する。

### 日次封印 `AuditCheckpoint`

- `AuditCheckpoint`（末尾 `Sequence`・末尾 `RowHash`・件数・封印時刻、**運用鍵による HMAC**、後述の **`KeyId`/`KeyVersion`**）を日次で記録する。
  これは「ある時点までのチェーン状態」を 1 行に要約して固定するスナップショットであり、
  過去区間をまとめて差し替える攻撃を、checkpoint 時点の HMAC との突合で検出する。
- 封印時刻も `IClock`（JST）で取得する（時刻源の不変条件を守る）。
- HMAC の **運用鍵はコミットしない**（`Audit:HashSalt` と同様に環境変数 / Secret Manager。後述「残存リスク」）。
- **鍵バージョニング（必須）**: `AuditCheckpoint` に **どの鍵で封印したかを示す `KeyId`/`KeyVersion` を保存**する。
  運用上 HMAC 鍵をローテーションすると、**版を記録していない過去 checkpoint は再検証不能**になり（旧鍵を場当たりに推測する以外に検証できない）、
  この層が担うはずの長期改ざん検査が崩れる。したがって **(a) checkpoint ごとに鍵版を記録**し、
  **(b) 旧鍵を版付きで保持（リテンション）して過去 checkpoint を検証できるようにし**、
  **(c) ローテーション/失効ポリシーを runbook 化**する（`Audit:HashSalt` のローテーション注意と同じ思想）。

---

## provider 非依存の担保

- provider 固有 SQL / 列型を一切持ち込まない。`Sequence` は `long`、`PrevHash` / `RowHash` は文字列（hex）で、
  全 provider が `TEXT` / `nvarchar` 相当へマップできる範囲に収める。
- **provider 間で同一チェーン値になる正準化関数を 1 箇所に集約**する（`CanonicalAuditBytes(...)` のような単一関数）。
  **正規化済み `ChangedAt`（固定精度・固定 `Kind`）**・列順・UTF-8・null トークン・enum 文字列化（既存 `JsonStringEnumConverter`）を
  すべてこの 1 関数に閉じ込め、SQLite / SQL Server / PostgreSQL で同一バイト列 → 同一 `RowHash` を保証する。
- DB トリガ / computed column を使わないのは、この「単一の正準化関数」を provider 横断で共有するため
  （SQL 側に式を二重実装すると provider 間でズレる）。

---

## 遡及範囲の限界（正直な線引き）

- チェーンは **導入後の行を完全被覆**するが、**導入前の既存行**には `RowHash` が無い。
- 導入時に既存行を `Id` 昇順で読み `Sequence` を採番しジェネシス封印（その時点のスナップショットとして 1 度だけチェーンを張る）するが、
  「導入前にすでに改ざんされていたかどうか」は本機構では証明できない。
- したがって対外的には **「導入後は完全被覆、導入前は対象外」** と明示する。これを曖昧にしない。

---

## 却下した代替

- **A1: DB トリガ / computed column でハッシュを計算する。**
  却下。provider 依存（SQLite / SQL Server / PostgreSQL でトリガ構文も式も異なる）になり、
  「provider 非依存・正準化関数 1 本」の不変条件を破る。アプリ層 1 箇所で計算するほうが移植性・検証可能性が高い。
- **A3: 外部台帳（QLDB / 専用 WORM / ブロックチェーン基盤）に監査を委譲する。**
  却下（今フェーズでは）。運用・コスト・provider 非依存性とのトレードオフが大きい。
  ただし `AuditCheckpoint` の封印値を **アプリ外（WORM / 別系）へ退避**する形で部分的に取り込む（残存リスク参照）。
- **塩をチェーンに混ぜる案。**
  却下。塩ローテで全行の `RowHash` が検証不能になる（決定性の肝④）。チェーンは塩なし公開検証、
  真正性は checkpoint の HMAC が担う、と役割を分離する。

---

## 残存リスク

- **DB に直接書込権限を持つ者による「全行差し替え」**（チェーン全体を辻褄が合うよう再計算して入れ替える攻撃）は、
  アプリ層のチェーン単独では防げない。`RowHash` 計算式が公開（塩なし）であるため、攻撃者も再計算できるからである。
- 緩和策:
  - `AuditCheckpoint` の封印値（特に **HMAC**）を **アプリ外（WORM ストレージ / 別系・別権限の保管先）へ退避**する。
    DB だけを差し替えても、外部退避した checkpoint と突合すれば不整合が露見する。
  - **HMAC 鍵はコミットしない**（環境変数 / Secret Manager）。鍵を DB と同じ侵害面に置かない。
  - 検証アクションは管理者専用とし、誰がいつ検証したかも監査対象の運用フローに組み込む。

---

## 段階（Phase）

- **Phase 1**: 列追加（`Sequence` / `PrevHash` / `RowHash`）＋ 新規 `AuditChainState` テーブル
  （**シングルトン行を migration で決定的にシード**）＋ インターセプタのチェーン計算
  （業務変更と同一の明示トランザクションでの **原子的・直列化書込**、`ConcurrencyToken` 回転）
  ＋ 純粋関数 `AuditChainVerifier`（`Sequence` 順走査・`AuditChainState` 先端突合で末尾削除も検知、InMemory テスト）。
  - この段階で migration が発生するため、本 ADR の凍結合意後に **別 PR** で実施する
    （migration は startup の `Database.Migrate()` で自動適用されるため、合意なしに混ぜない）。
- **Phase 2**: 検証 UI（`AuditLogsController` の管理者専用アクション）＋ `AuditCheckpoint`（日次 HMAC 封印）
  ＋ 封印値のアプリ外退避運用。

---

## 既存不変条件との整合（チェックリスト）

- [x] 監査は **`SaveChanges` 経由**（原子的・直列化チェーン書込もすべて `SaveChanges`／同一トランザクション。`ExecuteUpdate`/`ExecuteDelete` 不使用）。
- [x] **PHI マスキング後**の `ChangesJson` を入力にし、平文 PHI をチェーンに混入させない。
- [x] **`IClock`（JST）** を時刻源に使い、`ChangedAt` / 封印時刻に直接 `DateTime.Now` を使わない。
- [x] **provider 非依存**: 固有 SQL / 列型なし、正準化関数 1 本に集約。
- [x] **塩はチェーンに混ぜない**（PHI ハッシュ専用）。秘密性は checkpoint の HMAC で分離。
- [x] 本 ADR では **コード / schema / migration を変更しない**（凍結のみ）。
