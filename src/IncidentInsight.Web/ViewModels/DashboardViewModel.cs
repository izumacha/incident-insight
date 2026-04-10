namespace IncidentInsight.Web.ViewModels;

public class DashboardViewModel
{
    public int TotalIncidents { get; set; }
    public int OpenCountermeasures { get; set; }
    public double HighRiskRatio { get; set; }
    public List<CategoryStat> CategoryStats { get; set; } = [];
    public List<MonthlyStat> MonthlyStats { get; set; } = [];
    public List<DepartmentStat> DepartmentStats { get; set; } = [];
    public List<VersionComparison> FourVersionComparisons { get; set; } = [];
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

public class DepartmentStat
{
    public string Department { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class VersionComparison
{
    public string VersionName { get; set; } = string.Empty;
    public string Focus { get; set; } = string.Empty;
    public string Indicator { get; set; } = string.Empty;
    public string ImprovementAction { get; set; } = string.Empty;
}
