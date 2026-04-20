// 自プロジェクトのモデル群を使う
using IncidentInsight.Web.Models;
// enum 変換ヘルパーを使う
using IncidentInsight.Web.Models.Enums;
// Identity + EF Core の DbContext 基底を使う
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
// EF Core 本体を使う
using Microsoft.EntityFrameworkCore;

// この型の名前空間(置き場所)
namespace IncidentInsight.Web.Data;

// アプリケーション全体の DB アクセスを司る DbContext(Identity テーブルも同じ DB に入る)
public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    // コンストラクタ: DI コンテナから DbContextOptions を受け取って基底に渡す
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    // インシデントテーブルへのアクセスプロパティ
    public DbSet<Incident> Incidents => Set<Incident>();
    // 原因分類テーブルへのアクセスプロパティ
    public DbSet<CauseCategory> CauseCategories => Set<CauseCategory>();
    // なぜなぜ分析テーブルへのアクセスプロパティ
    public DbSet<CauseAnalysis> CauseAnalyses => Set<CauseAnalysis>();
    // 再発防止策テーブルへのアクセスプロパティ
    public DbSet<PreventiveMeasure> PreventiveMeasures => Set<PreventiveMeasure>();
    // 監査ログテーブルへのアクセスプロパティ
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    // モデル構成(リレーション・インデックス・enum 変換)を定義する
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // 基底クラス(Identity)の定義を先に適用
        base.OnModelCreating(modelBuilder);

        // CauseCategory: self-referential hierarchy
        // 原因分類の親子関係を設定(親削除で子が消えないよう Restrict)
        modelBuilder.Entity<CauseCategory>()
            .HasOne(c => c.Parent)
            .WithMany(c => c.Children)
            .HasForeignKey(c => c.ParentId)
            .OnDelete(DeleteBehavior.Restrict);

        // 親ID+表示順の複合インデックスで、子一覧の表示を高速化
        modelBuilder.Entity<CauseCategory>()
            .HasIndex(c => new { c.ParentId, c.DisplayOrder });

        // CauseAnalysis -> Incident
        // なぜなぜ分析はインシデントに従属し、インシデント削除時に一緒に消す(Cascade)
        modelBuilder.Entity<CauseAnalysis>()
            .HasOne(ca => ca.Incident)
            .WithMany(i => i.CauseAnalyses)
            .HasForeignKey(ca => ca.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // CauseAnalysis -> CauseCategory
        // 原因分類が消えても分析ログは残るよう Restrict(マスタ変更を安全に)
        modelBuilder.Entity<CauseAnalysis>()
            .HasOne(ca => ca.CauseCategory)
            .WithMany(cc => cc.CauseAnalyses)
            .HasForeignKey(ca => ca.CauseCategoryId)
            .OnDelete(DeleteBehavior.Restrict);

        // PreventiveMeasure -> Incident
        // 再発防止策もインシデントに従属し、インシデント削除で連動削除される
        modelBuilder.Entity<PreventiveMeasure>()
            .HasOne(pm => pm.Incident)
            .WithMany(i => i.PreventiveMeasures)
            .HasForeignKey(pm => pm.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // Enum <-> string 永続化 (プロバイダ非依存の TEXT 列で保存)
        // 既存 DB 値と一致する enum 名は HasConversion<string>() で双方向。
        // IncidentType のみ DB 文字列が日本語のため、専用マッピングで変換する。
        // 重症度は enum 名文字列で DB に保存(SQL/Sqlite/Pg 共通で安全)
        modelBuilder.Entity<Incident>()
            .Property(i => i.Severity)
            .HasConversion<string>()
            .HasMaxLength(20);

        // インシデント種別は日本語文字列との双方向変換を挟む(既存DB互換)
        modelBuilder.Entity<Incident>()
            .Property(i => i.IncidentType)
            .HasConversion(
                v => IncidentTypeMapping.ToDbString(v),
                v => IncidentTypeMapping.FromDbString(v))
            .HasMaxLength(50);

        // 対策ステータスは enum 名文字列で保存
        modelBuilder.Entity<PreventiveMeasure>()
            .Property(pm => pm.Status)
            .HasConversion<string>()
            .HasMaxLength(20);

        // 対策種別(短期/長期)も enum 名文字列で保存
        modelBuilder.Entity<PreventiveMeasure>()
            .Property(pm => pm.MeasureType)
            .HasConversion<string>()
            .HasMaxLength(20);

        // Indexes for analytics queries
        // 発生日時で検索・並べ替えを行うためのインデックス
        modelBuilder.Entity<Incident>()
            .HasIndex(i => i.OccurredAt);
        // 部署 + 種別での集計や絞り込みを高速化するインデックス
        modelBuilder.Entity<Incident>()
            .HasIndex(i => new { i.Department, i.IncidentType });
        // 対策のステータス + 期限での抽出(Kanban・期限超過検出)を高速化
        modelBuilder.Entity<PreventiveMeasure>()
            .HasIndex(pm => new { pm.Status, pm.DueDate });

        // Audit log: 問い合わせを早くするためのインデックス(対象エンティティ + 変更時刻)
        // 対象エンティティ + キーの複合インデックス(履歴ページング用)
        modelBuilder.Entity<AuditLog>()
            .HasIndex(a => new { a.EntityName, a.EntityKey });
        // 変更時刻でのソート・範囲検索用インデックス
        modelBuilder.Entity<AuditLog>()
            .HasIndex(a => a.ChangedAt);
    }
}
