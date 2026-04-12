using IncidentInsight.Web.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<IncidentReport> IncidentReports => Set<IncidentReport>();
    public DbSet<Countermeasure> Countermeasures => Set<Countermeasure>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<IncidentReport>()
            .HasMany(i => i.Countermeasures)
            .WithOne(c => c.IncidentReport)
            .HasForeignKey(c => c.IncidentReportId)
            .OnDelete(DeleteBehavior.Cascade);

        modelBuilder.Entity<IncidentReport>()
            .Property(i => i.CauseCategory)
            .HasConversion<string>();

        modelBuilder.Entity<IncidentReport>()
            .Property(i => i.LifecycleStatus)
            .HasConversion<string>();
    }
}
