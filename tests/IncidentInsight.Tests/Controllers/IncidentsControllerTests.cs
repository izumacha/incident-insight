using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IncidentInsight.Tests.Controllers;

public class IncidentsControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly IncidentsController _controller;

    public IncidentsControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new IncidentsController(_db)
        {
            TempData = new TestTempData()
        };
    }

    public void Dispose()
    {
        _db.Dispose();
    }

    private IncidentCreateEditViewModel ValidViewModel(string dept = "内科病棟") => new()
    {
        OccurredAt = DateTime.Now,
        Department = dept,
        IncidentType = "投薬ミス",
        Severity = "Level2",
        Description = "テスト状況",
        ReporterName = "テスト太郎",
        Measures = new List<MeasureFormViewModel>
        {
            new()
            {
                Description = "テスト対策",
                MeasureType = "ShortTerm",
                ResponsiblePerson = "担当者",
                ResponsibleDepartment = dept,
                DueDate = DateTime.Today.AddDays(30),
                Priority = 2
            }
        }
    };

    // --- Create POST ---

    [Fact]
    public async Task Create_Post_ValidModel_RedirectsToDetails()
    {
        var vm = ValidViewModel();

        var result = await _controller.Create(vm);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Details", redirect.ActionName);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesIncidentToDb()
    {
        var vm = ValidViewModel("外科病棟");

        await _controller.Create(vm);

        var saved = await _db.Incidents.FirstOrDefaultAsync();
        Assert.NotNull(saved);
        Assert.Equal("外科病棟", saved.Department);
        Assert.Equal("投薬ミス", saved.IncidentType);
    }

    [Fact]
    public async Task Create_Post_ValidModel_SavesMeasure()
    {
        var vm = ValidViewModel();

        await _controller.Create(vm);

        var measure = await _db.PreventiveMeasures.FirstOrDefaultAsync();
        Assert.NotNull(measure);
        Assert.Equal("テスト対策", measure.Description);
        Assert.Equal("Planned", measure.Status);
    }

    [Fact]
    public async Task Create_Post_InvalidModel_ReturnsCreateView()
    {
        _controller.ModelState.AddModelError("Department", "Required");
        var vm = new IncidentCreateEditViewModel();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
    }

    [Fact]
    public async Task Create_Post_WithoutMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>();

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    [Fact]
    public async Task Create_Post_WithOnlyWhitespaceMeasures_ReturnsCreateView_AndDoesNotSaveIncident()
    {
        var vm = ValidViewModel();
        vm.Measures = new List<MeasureFormViewModel>
        {
            new() { Description = "   " },
            new() { Description = "\t" }
        };

        var result = await _controller.Create(vm);

        var viewResult = Assert.IsType<ViewResult>(result);
        Assert.Equal("Create", viewResult.ViewName ?? "Create");
        Assert.False(_controller.ModelState.IsValid);
        Assert.True(_controller.ModelState.ContainsKey(nameof(vm.Measures)));
        Assert.Empty(_db.Incidents);
    }

    // --- Index GET / Filtering ---

    [Fact]
    public async Task Index_NoFilter_ReturnsAllIncidents()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = "転倒・転落", Severity = "Level2", Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = "投薬ミス", Severity = "Level1", Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(2, vm!.TotalCount);
    }

    [Fact]
    public async Task Index_DepartmentFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = "転倒・転落", Severity = "Level2", Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = "投薬ミス", Severity = "Level1", Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, "ICU", null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.All(vm.Incidents, i => Assert.Equal("ICU", i.Department));
    }

    [Fact]
    public async Task Index_SeverityFilter_ReturnsMatchingOnly()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = "転倒・転落", Severity = "Level4", Description = "A", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = "投薬ミス", Severity = "Level0", Description = "B", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index(null, null, null, "Level4", null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Equal("Level4", vm.Incidents[0].Severity);
    }

    [Fact]
    public async Task Index_SearchFilter_MatchesDescription()
    {
        _db.Incidents.AddRange(
            new Incident { Department = "ICU", IncidentType = "投薬ミス", Severity = "Level2", Description = "点滴ラインが抜けた", ReporterName = "A", OccurredAt = DateTime.Now },
            new Incident { Department = "外来", IncidentType = "投薬ミス", Severity = "Level1", Description = "薬を誤投与", ReporterName = "B", OccurredAt = DateTime.Now }
        );
        await _db.SaveChangesAsync();

        var result = await _controller.Index("点滴", null, null, null, null, null, null, null, 1) as ViewResult;
        var vm = result?.Model as IncidentListViewModel;

        Assert.Equal(1, vm!.TotalCount);
        Assert.Contains("点滴", vm.Incidents[0].Description);
    }

    // --- Details GET ---

    [Fact]
    public async Task Details_ExistingId_ReturnsViewWithIncident()
    {
        var incident = new Incident
        {
            Department = "内科病棟",
            IncidentType = "転倒・転落",
            Severity = "Level2",
            Description = "廊下で転倒",
            ReporterName = "山田",
            OccurredAt = DateTime.Now
        };
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();

        var result = await _controller.Details(incident.Id) as ViewResult;
        var vm = result?.Model as IncidentDetailViewModel;

        Assert.NotNull(vm);
        Assert.Equal(incident.Id, vm.Incident.Id);
    }

    [Fact]
    public async Task Details_NonExistentId_ReturnsNotFound()
    {
        var result = await _controller.Details(9999);
        Assert.IsType<NotFoundResult>(result);
    }
}
