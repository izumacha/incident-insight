namespace IncidentInsight.Web.ViewModels;

public class DashboardViewModel
{
    public int TotalIncidents { get; set; }
    public int OpenCountermeasures { get; set; }
    public List<CategoryStat> CategoryStats { get; set; } = [];
    public List<MonthlyStat> MonthlyStats { get; set; } = [];
}

public class CategoryStat
{
    public string Category { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class MonthlyStat
{
    public string Month { get; set; } = string.Empty;
    public int Count { get; set; }
}
