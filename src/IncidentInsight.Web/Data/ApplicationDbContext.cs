using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<CauseCategory> CauseCategories => Set<CauseCategory>();
    public DbSet<CauseAnalysis> CauseAnalyses => Set<CauseAnalysis>();
    public DbSet<PreventiveMeasure> PreventiveMeasures => Set<PreventiveMeasure>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // CauseCategory: self-referential hierarchy
        modelBuilder.Entity<CauseCategory>()
            .HasOne(c => c.Parent)
            .WithMany(c => c.Children)
            .HasForeignKey(c => c.ParentId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<CauseCategory>()
            .HasIndex(c => new { c.ParentId, c.DisplayOrder });

        // CauseAnalysis -> Incident
        modelBuilder.Entity<CauseAnalysis>()
            .HasOne(ca => ca.Incident)
            .WithMany(i => i.CauseAnalyses)
            .HasForeignKey(ca => ca.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // CauseAnalysis -> CauseCategory
        modelBuilder.Entity<CauseAnalysis>()
            .HasOne(ca => ca.CauseCategory)
            .WithMany(cc => cc.CauseAnalyses)
            .HasForeignKey(ca => ca.CauseCategoryId)
            .OnDelete(DeleteBehavior.Restrict);

        // PreventiveMeasure -> Incident
        modelBuilder.Entity<PreventiveMeasure>()
            .HasOne(pm => pm.Incident)
            .WithMany(i => i.PreventiveMeasures)
            .HasForeignKey(pm => pm.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // Enum <-> string 永続化 (プロバイダ非依存の TEXT 列で保存)
        // 既存 DB 値と一致する enum 名は HasConversion<string>() で双方向。
        // IncidentType のみ DB 文字列が日本語のため、専用マッピングで変換する。
        modelBuilder.Entity<Incident>()
            .Property(i => i.Severity)
            .HasConversion<string>()
            .HasMaxLength(20);

        modelBuilder.Entity<Incident>()
            .Property(i => i.IncidentType)
            .HasConversion(
                v => IncidentTypeMapping.ToDbString(v),
                v => IncidentTypeMapping.FromDbString(v))
            .HasMaxLength(50);

        modelBuilder.Entity<PreventiveMeasure>()
            .Property(pm => pm.Status)
            .HasConversion<string>()
            .HasMaxLength(20);

        modelBuilder.Entity<PreventiveMeasure>()
            .Property(pm => pm.MeasureType)
            .HasConversion<string>()
            .HasMaxLength(20);

        // Indexes for analytics queries
        modelBuilder.Entity<Incident>()
            .HasIndex(i => i.OccurredAt);
        modelBuilder.Entity<Incident>()
            .HasIndex(i => new { i.Department, i.IncidentType });
        modelBuilder.Entity<PreventiveMeasure>()
            .HasIndex(pm => new { pm.Status, pm.DueDate });

        // Audit log: 問い合わせを早くするためのインデックス(対象エンティティ + 変更時刻)
        modelBuilder.Entity<AuditLog>()
            .HasIndex(a => new { a.EntityName, a.EntityKey });
        modelBuilder.Entity<AuditLog>()
            .HasIndex(a => a.ChangedAt);
    }
}
