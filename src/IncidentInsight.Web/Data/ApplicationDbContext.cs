using IncidentInsight.Web.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<CauseCategory> CauseCategories => Set<CauseCategory>();
    public DbSet<CauseAnalysis> CauseAnalyses => Set<CauseAnalysis>();
    public DbSet<PreventiveMeasure> PreventiveMeasures => Set<PreventiveMeasure>();

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

        // Indexes for analytics queries
        modelBuilder.Entity<Incident>()
            .HasIndex(i => i.OccurredAt);
        modelBuilder.Entity<Incident>()
            .HasIndex(i => new { i.Department, i.IncidentType });
        modelBuilder.Entity<PreventiveMeasure>()
            .HasIndex(pm => new { pm.Status, pm.DueDate });
    }
}
