namespace IncidentInsight.Web.Models.ViewModels;

public class DashboardViewModel
{
    // KPI
    public int TotalIncidents { get; set; }
    public int ThisMonthIncidents { get; set; }
    public int OpenMeasures { get; set; }
    public int OverdueMeasures { get; set; }
    public int CompletedMeasures { get; set; }

    public double CompletionRate => (OpenMeasures + CompletedMeasures) == 0
        ? 0
        : Math.Round((double)CompletedMeasures / (OpenMeasures + CompletedMeasures) * 100, 1);

    // Recent incidents
    public List<Incident> RecentIncidents { get; set; } = new();

    // Overdue measures for alert panel
    public List<PreventiveMeasure> OverdueMeasureList { get; set; } = new();

    // Recurrence alerts: incidents that share same department+type+cause as another recent incident
    public List<RecurrenceAlert> RecurrenceAlerts { get; set; } = new();

    // Monthly trend data for sparkline chart (last 12 months)
    public List<MonthlyCount> MonthlyCounts { get; set; } = new();

    // Failed measures: RecurrenceObserved = true
    public int FailedMeasures { get; set; }
}

public class RecurrenceAlert
{
    public Incident CurrentIncident { get; set; } = null!;
    public List<Incident> SimilarIncidents { get; set; } = new();
    public string PatternDescription { get; set; } = "";
}

public class MonthlyCount
{
    public string Label { get; set; } = ""; // e.g. "2024年3月"
    public int Count { get; set; }
}
