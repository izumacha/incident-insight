// 自プロジェクトのモデル(Incident など)を使う
using IncidentInsight.Web.Models;
// enum(重症度・種別)を使う
using IncidentInsight.Web.Models.Enums;
// 時刻源サービスを使う
using IncidentInsight.Web.Services;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Data;

// 起動時に初期データ(原因分類マスタ + デモインシデント群)を投入するシーダー
public static class DbSeeder
{
    // 呼び出されるたびに実行される本体メソッド(データがあれば何もしない冪等処理)
    public static void Seed(ApplicationDbContext db, IClock clock)
    {
        // ── 原因カテゴリ（親カテゴリ） ─────────────────────────────
        // 原因分類が1件もないときだけマスタを登録する(冪等化)
        if (!db.CauseCategories.Any())
        {
        // 親カテゴリ「ヒューマンエラー」を生成
        var humanError = new CauseCategory { Name = "ヒューマンエラー", Description = "人的要因によるミス・判断誤り", DisplayOrder = 1 };
        // 親カテゴリ「医療機器」を生成
        var device = new CauseCategory { Name = "医療機器", Description = "機器の不具合・操作ミス", DisplayOrder = 2 };
        // 親カテゴリ「薬剤」を生成
        var medication = new CauseCategory { Name = "薬剤", Description = "調剤・投与に関するミス", DisplayOrder = 3 };
        // 親カテゴリ「環境・体制」を生成
        var environment = new CauseCategory { Name = "環境・体制", Description = "施設環境・人員体制に関する問題", DisplayOrder = 4 };
        // 親カテゴリ「コミュニケーション」を生成
        var communication = new CauseCategory { Name = "コミュニケーション", Description = "情報伝達・連携の問題", DisplayOrder = 5 };

        // 親カテゴリをまとめて ChangeTracker に追加
        db.CauseCategories.AddRange(humanError, device, medication, environment, communication);
        // 先に保存して親 ID を確定させる(子で参照するため)
        db.SaveChanges();

        // ── 子カテゴリ ────────────────────────────────────────────
        // 各親にぶら下がる子カテゴリ一覧(親 Id を FK に指定)
        var subCategories = new List<CauseCategory>
        {
            // ヒューマンエラー
            new() { Name = "確認不足", ParentId = humanError.Id, DisplayOrder = 1 },
            new() { Name = "疲労・注意力低下", ParentId = humanError.Id, DisplayOrder = 2 },
            new() { Name = "手順不遵守", ParentId = humanError.Id, DisplayOrder = 3 },
            new() { Name = "知識・技術不足", ParentId = humanError.Id, DisplayOrder = 4 },
            new() { Name = "思い込み・先入観", ParentId = humanError.Id, DisplayOrder = 5 },
            new() { Name = "多重課題による判断ミス", ParentId = humanError.Id, DisplayOrder = 6 },

            // 医療機器
            new() { Name = "機器不具合・故障", ParentId = device.Id, DisplayOrder = 1 },
            new() { Name = "操作ミス", ParentId = device.Id, DisplayOrder = 2 },
            new() { Name = "メンテナンス不良", ParentId = device.Id, DisplayOrder = 3 },
            new() { Name = "警報設定誤り", ParentId = device.Id, DisplayOrder = 4 },

            // 薬剤
            new() { Name = "調剤ミス（秤量・混合）", ParentId = medication.Id, DisplayOrder = 1 },
            new() { Name = "投与量・速度誤り", ParentId = medication.Id, DisplayOrder = 2 },
            new() { Name = "患者アレルギー確認漏れ", ParentId = medication.Id, DisplayOrder = 3 },
            new() { Name = "類似薬品名混同", ParentId = medication.Id, DisplayOrder = 4 },
            new() { Name = "投与経路誤り", ParentId = medication.Id, DisplayOrder = 5 },

            // 環境・体制
            new() { Name = "照明・視認性不良", ParentId = environment.Id, DisplayOrder = 1 },
            new() { Name = "人員不足・過重労働", ParentId = environment.Id, DisplayOrder = 2 },
            new() { Name = "設備・レイアウト不良", ParentId = environment.Id, DisplayOrder = 3 },
            new() { Name = "マニュアル未整備", ParentId = environment.Id, DisplayOrder = 4 },

            // コミュニケーション
            new() { Name = "申し送り漏れ", ParentId = communication.Id, DisplayOrder = 1 },
            new() { Name = "指示の不明確さ", ParentId = communication.Id, DisplayOrder = 2 },
            new() { Name = "多職種間連携不足", ParentId = communication.Id, DisplayOrder = 3 },
            new() { Name = "患者・家族への説明不足", ParentId = communication.Id, DisplayOrder = 4 },
        };

            // 子カテゴリを一括追加して保存
            db.CauseCategories.AddRange(subCategories);
            db.SaveChanges();
        }

        // ── サンプルインシデント + 分析 + 対策 ───────────────────────
        // インシデントが既にあれば以降のサンプル投入はスキップ
        if (db.Incidents.Any()) return;

        // 子カテゴリ名 → Id の辞書を作り、以降の分析レコード作成で使う
        var cats = db.CauseCategories.ToDictionary(c => c.Name, c => c.Id);
        // 現在時刻(JST)をデモデータの基準時刻として取得
        var now = clock.Now;

        // デモ用のサンプルインシデントリスト(発生日は 90 日前〜7 日前までばらつかせる)
        var incidents = new List<Incident>
        {
            new()
            {
                OccurredAt = now.AddDays(-90),
                Department = "内科病棟",
                IncidentType = IncidentTypeKind.Medication,
                Severity = IncidentSeverity.Level3a,
                Description = "夜勤帯に担当患者Aさんと患者Bさんの名前が似ており、Aさん処方の降圧薬をBさんに投与した。Bさんは軽度の血圧低下を示し、臥床安静にて回復。",
                ImmediateActions = "直ちに主治医に報告。バイタルサイン監視強化。1時間後に正常値を確認。",
                ReporterName = "山田 花子",
                ReportedAt = now.AddDays(-90).AddHours(2)
            },
            new()
            {
                OccurredAt = now.AddDays(-60),
                Department = "外科病棟",
                IncidentType = IncidentTypeKind.Fall,
                Severity = IncidentSeverity.Level2,
                Description = "術後2日目の患者Cさんが夜間にトイレへ一人で歩行しようとして転倒。床頭台に手をついて転倒を防いだが、軽度の打撲が生じた。",
                ImmediateActions = "傷の確認・処置。レントゲン撮影（骨折なし確認）。転倒リスク再評価。",
                ReporterName = "佐藤 次郎",
                ReportedAt = now.AddDays(-60).AddHours(1)
            },
            new()
            {
                OccurredAt = now.AddDays(-45),
                Department = "ICU",
                IncidentType = IncidentTypeKind.TubeOrLine,
                Severity = IncidentSeverity.Level3a,
                Description = "体動時に中心静脈カテーテルが自己抜去。再挿入が必要となり患者の苦痛が増した。抑制帯の使用可否の確認が不十分だった。",
                ImmediateActions = "バイタル確認・主治医報告。代替の末梢静脈ルート確保。翌日再挿入。",
                ReporterName = "鈴木 三郎",
                ReportedAt = now.AddDays(-45).AddHours(3)
            },
            new()
            {
                OccurredAt = now.AddDays(-20),
                Department = "内科病棟",
                IncidentType = IncidentTypeKind.Medication,
                Severity = IncidentSeverity.Level2,
                Description = "電子カルテの画面切替操作中に処方確認を怠り、インスリン単位数の入力値を誤って確認しないまま投与した（10単位→4単位）。患者は低血糖症状なし。",
                ImmediateActions = "血糖測定実施（正常範囲）。主治医報告。経過観察。",
                ReporterName = "山田 花子",
                ReportedAt = now.AddDays(-20).AddHours(1)
            },
            new()
            {
                OccurredAt = now.AddDays(-7),
                Department = "外来",
                IncidentType = IncidentTypeKind.PatientIdentification,
                Severity = IncidentSeverity.Level1,
                Description = "外来採血室にて患者確認をフルネームではなく苗字のみで行い、同姓の別患者に採血指示を実施しそうになった。採血直前に本人から申し出があり未遂に終わった。",
                ImmediateActions = "即座に謝罪。正しい患者の採血を実施。インシデント報告。",
                ReporterName = "田中 美咲",
                ReportedAt = now.AddDays(-7).AddHours(1)
            }
        };

        // インシデントをまとめて追加
        db.Incidents.AddRange(incidents);
        // 保存して各 Incident の ID を採番させる
        db.SaveChanges();

        // ── CauseAnalysis (なぜなぜ分析) ─────────────────────────
        // 各インシデントに対する5段階「なぜなぜ」分析のデモデータ
        var analyses = new List<CauseAnalysis>
        {
            // 投薬ミス（降圧薬混同）
            new()
            {
                IncidentId = incidents[0].Id,
                CauseCategoryId = cats["確認不足"],
                Why1 = "Aさんの薬をBさんに渡した",
                Why2 = "名前を確認せずに配薬した",
                Why3 = "夜勤で業務が重なり確認を省略した",
                Why4 = "夜勤体制が一人で担当患者数が多く多忙だった",
                Why5 = "適切な夜勤人員配置の基準と確認ダブルチェック手順が文書化されていなかった",
                RootCauseSummary = "夜勤時のダブルチェック手順書の未整備と人員配置基準の不明確さ",
                AnalystName = "インシデント分析委員会",
                AnalyzedAt = now.AddDays(-87)
            },
            // 転倒
            new()
            {
                IncidentId = incidents[1].Id,
                CauseCategoryId = cats["思い込み・先入観"],
                Why1 = "患者が一人でトイレへ歩行しようとした",
                Why2 = "転倒リスクを自覚していなかった",
                Why3 = "術後の体力低下について患者への説明が不十分だった",
                Why4 = "入院時の転倒リスク説明の標準化が不足していた",
                Why5 = "術後患者への動作制限説明のクリニカルパスが整備されていなかった",
                RootCauseSummary = "術後患者向けクリニカルパスにおける動作制限・転倒リスク説明項目の欠如",
                AnalystName = "安全管理委員会",
                AnalyzedAt = now.AddDays(-57)
            },
            // CVCライン自己抜去
            new()
            {
                IncidentId = incidents[2].Id,
                CauseCategoryId = cats["申し送り漏れ"],
                Why1 = "患者がCVCラインを自己抜去した",
                Why2 = "抑制帯の使用可否が申し送られていなかった",
                Why3 = "申し送り時のチェックリストに抑制帯項目がなかった",
                Why4 = "ICU引継ぎプロトコルが更新されていなかった",
                Why5 = "ICUプロトコル定期見直しの仕組みと責任者が明確でなかった",
                RootCauseSummary = "ICU申し送りプロトコルの定期見直し体制の欠如",
                AnalystName = "ICU師長",
                AnalyzedAt = now.AddDays(-42)
            },
            // インスリン入力誤り
            new()
            {
                IncidentId = incidents[3].Id,
                CauseCategoryId = cats["確認不足"],
                Why1 = "インスリン単位数を誤った値で確認なく投与した",
                Why2 = "電子カルテ画面切替後の再確認を怠った",
                Why3 = "電子カルテ操作中の割り込み業務で集中が途切れた",
                Why4 = "インスリン投与前の2人確認ルールが形骸化していた",
                Why5 = "ハイリスク薬（インスリン）のダブルチェック義務が明文化・徹底されていなかった",
                RootCauseSummary = "ハイリスク薬投与前ダブルチェック手順の未徹底",
                AnalystName = "インシデント分析委員会",
                AnalyzedAt = now.AddDays(-17)
            },
            // 患者確認ミス
            new()
            {
                IncidentId = incidents[4].Id,
                CauseCategoryId = cats["手順不遵守"],
                Why1 = "苗字のみで患者確認を行い同姓別患者に処置しそうになった",
                Why2 = "フルネーム確認の手順を省略した",
                Why3 = "業務多忙時に確認手順を省略する慣行があった",
                Why4 = "「忙しいときは省略可」という暗黙のルールが存在した",
                Why5 = "患者確認手順の遵守についての定期的な監査・フィードバックがなかった",
                RootCauseSummary = "患者確認手順の監査・フィードバック体制の不備",
                AnalystName = "外来師長",
                AnalyzedAt = now.AddDays(-5)
            }
        };

        // 分析レコードをまとめて追加して保存
        db.CauseAnalyses.AddRange(analyses);
        db.SaveChanges();

        // ── PreventiveMeasures (再発防止策) ──────────────────────
        // 各インシデントに対する再発防止策のデモデータ(完了済み / 進行中 / 期限超過の混在)
        var measures = new List<PreventiveMeasure>
        {
            // 投薬ミス対策
            new()
            {
                IncidentId = incidents[0].Id,
                Description = "夜勤配薬時のダブルチェック手順書を作成し、全スタッフへ周知・訓練を実施する",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "看護師長",
                ResponsibleDepartment = "内科病棟",
                DueDate = now.AddDays(-60),
                Status = MeasureStatus.Completed,
                CompletedAt = now.AddDays(-65),
                CompletionNote = "手順書を作成し、朝礼にて全スタッフへ説明。配薬ダブルチェックシート導入。",
                EffectivenessRating = 4,
                EffectivenessNote = "ダブルチェック定着率90%に向上。類似インシデント未発生。",
                EffectivenessReviewedAt = now.AddDays(-30),
                RecurrenceObserved = false,
                Priority = 1
            },
            new()
            {
                IncidentId = incidents[0].Id,
                Description = "夜勤時の患者担当数の上限を設定し、必要時の補助体制を整備する",
                MeasureType = MeasureTypeKind.LongTerm,
                ResponsiblePerson = "看護部長",
                ResponsibleDepartment = "看護部",
                DueDate = now.AddDays(30),
                Status = MeasureStatus.InProgress,
                Priority = 1
            },

            // 転倒対策
            new()
            {
                IncidentId = incidents[1].Id,
                Description = "術後患者向けクリニカルパスに「転倒リスク・動作制限説明」チェック項目を追加する",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "病棟師長",
                ResponsibleDepartment = "外科病棟",
                DueDate = now.AddDays(-30),
                Status = MeasureStatus.Completed,
                CompletedAt = now.AddDays(-35),
                CompletionNote = "クリニカルパス改訂完了。術後説明チェックリストに転倒リスク欄を追加。",
                EffectivenessRating = 3,
                EffectivenessNote = "説明実施率は向上したが、夜間の一人歩行は引き続き課題。",
                EffectivenessReviewedAt = now.AddDays(-10),
                RecurrenceObserved = false,
                Priority = 2
            },
            new()
            {
                IncidentId = incidents[1].Id,
                Description = "転倒リスク評価スコアに基づく離床センサー使用基準を策定する",
                MeasureType = MeasureTypeKind.LongTerm,
                ResponsiblePerson = "安全管理委員長",
                ResponsibleDepartment = "医療安全室",
                DueDate = now.AddDays(-5),
                Status = MeasureStatus.Planned,
                Priority = 2
            },

            // CVCライン対策
            new()
            {
                IncidentId = incidents[2].Id,
                Description = "ICU申し送りチェックリストに「抑制帯使用可否」「ライン固定状態」を追加し、申し送り時の必須確認項目とする",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "ICU師長",
                ResponsibleDepartment = "ICU",
                DueDate = now.AddDays(-20),
                Status = MeasureStatus.Completed,
                CompletedAt = now.AddDays(-25),
                CompletionNote = "チェックリスト改訂・運用開始。スタッフ全員へ説明済み。",
                EffectivenessRating = 5,
                EffectivenessNote = "改訂以降のライン自己抜去インシデントはゼロ。",
                EffectivenessReviewedAt = now.AddDays(-7),
                RecurrenceObserved = false,
                Priority = 1
            },
            new()
            {
                IncidentId = incidents[2].Id,
                Description = "ICUプロトコルの定期見直し会議を年2回開催する体制を構築し、責任者を明確化する",
                MeasureType = MeasureTypeKind.LongTerm,
                ResponsiblePerson = "ICU部長",
                ResponsibleDepartment = "ICU",
                DueDate = now.AddDays(60),
                Status = MeasureStatus.InProgress,
                Priority = 2
            },

            // インスリン対策 (ハイリスク薬)
            new()
            {
                IncidentId = incidents[3].Id,
                Description = "ハイリスク薬（インスリン・抗がん剤・麻薬等）の投与前ダブルチェックを院内規定として明文化し、全病棟へ周知する",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "医療安全管理者",
                ResponsibleDepartment = "医療安全室",
                DueDate = now.AddDays(14),
                Status = MeasureStatus.InProgress,
                Priority = 1
            },
            new()
            {
                IncidentId = incidents[3].Id,
                Description = "電子カルテへのハイリスク薬投与時アラート機能を実装し、確認ボタンなしでは進めない設計とする（システム担当に依頼）",
                MeasureType = MeasureTypeKind.LongTerm,
                ResponsiblePerson = "情報システム担当",
                ResponsibleDepartment = "情報管理部",
                DueDate = now.AddDays(90),
                Status = MeasureStatus.Planned,
                Priority = 1
            },

            // 患者確認ミス対策
            new()
            {
                IncidentId = incidents[4].Id,
                Description = "患者確認手順（フルネーム+生年月日）の遵守を月次で監査し、結果をスタッフにフィードバックする体制を構築する",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "外来師長",
                ResponsibleDepartment = "外来",
                DueDate = now.AddDays(21),
                Status = MeasureStatus.Planned,
                Priority = 1
            },

            // 期限超過サンプル（ダッシュボードアラートのデモ用）
            new()
            {
                IncidentId = incidents[1].Id,
                Description = "転倒予防ポスターをトイレ入口・病室ベッド周辺に設置し、患者への視覚的注意喚起を実施する",
                MeasureType = MeasureTypeKind.ShortTerm,
                ResponsiblePerson = "担当看護師",
                ResponsibleDepartment = "外科病棟",
                DueDate = now.AddDays(-10), // 期限超過
                Status = MeasureStatus.Planned,
                Priority = 3
            }
        };

        // 対策をまとめて追加して保存
        db.PreventiveMeasures.AddRange(measures);
        db.SaveChanges();
    }
}
