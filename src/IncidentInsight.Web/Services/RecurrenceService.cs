using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Web.Services;

/// <inheritdoc />
public class RecurrenceService : IRecurrenceService
{
    private readonly IClock _clock;

    public RecurrenceService(IClock clock) { _clock = clock; }

    /// <inheritdoc />
    public async Task<List<Incident>> FindRecurrencesForIncidentAsync(
        Incident incident,
        IQueryable<Incident> scope,
        TimeSpan? within = null,
        CancellationToken ct = default)
    {
        var catIds = incident.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
        if (catIds.Count == 0) return new List<Incident>();

        var query = scope
            .AsNoTracking()
            .Include(o => o.CauseAnalyses)
            .Where(o => o.Id != incident.Id
                && o.Department == incident.Department
                && o.IncidentType == incident.IncidentType);

        if (within is { } w)
        {
            var since = _clock.Today - w;
            query = query.Where(o => o.OccurredAt >= since);
        }

        var candidates = await query.ToListAsync(ct);
        return RecurrenceDetector.FindSimilar(incident, candidates);
    }

    /// <inheritdoc />
    public async Task<List<RecurrenceAlert>> FindRecurrenceAlertsAsync(
        IQueryable<Incident> scope,
        TimeSpan recentWindow,
        CancellationToken ct = default)
    {
        var since = _clock.Today - recentWindow;

        var recentList = await scope
            .AsNoTracking()
            .Include(i => i.CauseAnalyses)
            .Where(i => i.OccurredAt >= since)
            .OrderByDescending(i => i.OccurredAt)
            .ToListAsync(ct);

        if (recentList.Count == 0) return new List<RecurrenceAlert>();

        var recentDepts = recentList.Select(i => i.Department).Distinct().ToList();
        var recentTypes = recentList.Select(i => i.IncidentType).Distinct().ToList();
        var recentCatIds = recentList
            .SelectMany(i => i.CauseAnalyses.Select(ca => ca.CauseCategoryId))
            .ToHashSet();

        // Over-fetches slightly (superset of dept × type) but collapses the loop's
        // per-iteration queries into one. Final matching is done in-memory below.
        var candidates = recentCatIds.Count == 0
            ? new List<Incident>()
            : await scope
                .AsNoTracking()
                .Include(i => i.CauseAnalyses)
                .Where(i => recentDepts.Contains(i.Department)
                    && recentTypes.Contains(i.IncidentType)
                    && i.CauseAnalyses.Any(ca => recentCatIds.Contains(ca.CauseCategoryId)))
                .ToListAsync(ct);

        var candidatesByKey = candidates.ToLookup(i => (i.Department, i.IncidentType));

        var alerts = new List<RecurrenceAlert>();
        var processed = new HashSet<int>();
        foreach (var incident in recentList)
        {
            if (processed.Contains(incident.Id)) continue;

            var bucket = candidatesByKey[(incident.Department, incident.IncidentType)];
            var similar = RecurrenceDetector.FindSimilar(incident, bucket);

            if (similar.Count > 0)
            {
                alerts.Add(new RecurrenceAlert
                {
                    CurrentIncident = incident,
                    SimilarIncidents = similar,
                    PatternDescription = $"{incident.Department} / {incident.IncidentType}"
                });
                processed.Add(incident.Id);
                foreach (var s in similar) processed.Add(s.Id);
            }
        }

        return alerts;
    }
}
