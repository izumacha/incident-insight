using IncidentInsight.Tests.Helpers;
using IncidentInsight.Web.Controllers;
using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace IncidentInsight.Tests.Controllers;

public class PreventiveMeasuresControllerTests : IDisposable
{
    private readonly ApplicationDbContext _db;
    private readonly PreventiveMeasuresController _controller;

    public PreventiveMeasuresControllerTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ApplicationDbContext(options);
        _controller = new PreventiveMeasuresController(
            _db,
            UserContextHelper.BuildAuthService(),
            NullLogger<PreventiveMeasuresController>.Instance);
        UserContextHelper.AttachUser(_controller, UserContextHelper.Admin());
    }

    public void Dispose() => _db.Dispose();

    private async Task<PreventiveMeasure> SeedMeasureAsync(string department)
    {
        var incident = new Incident
        {
            Department = department,
            IncidentType = IncidentTypeKind.Fall,
            Severity = IncidentSeverity.Level2,
            Description = "テスト",
            ReporterName = "担当",
            OccurredAt = DateTime.Now
        };
        var measure = new PreventiveMeasure
        {
            Incident = incident,
            Description = "対策",
            MeasureType = MeasureTypeKind.ShortTerm,
            ResponsiblePerson = "担当A",
            ResponsibleDepartment = department,
            DueDate = DateTime.Today.AddDays(30),
            Priority = 2
        };
        incident.PreventiveMeasures.Add(measure);
        _db.Incidents.Add(incident);
        await _db.SaveChangesAsync();
        return measure;
    }

    [Fact]
    public async Task Delete_Staff_OtherDepartment_ReturnsForbid()
    {
        var measure = await SeedMeasureAsync("外来");

        UserContextHelper.AttachUser(_controller, UserContextHelper.Staff("内科病棟"));
        var result = await _controller.Delete(measure.Id);

        Assert.IsType<ForbidResult>(result);
        Assert.True(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
    }

    [Fact]
    public async Task Delete_NotFound_ReturnsNotFound()
    {
        var result = await _controller.Delete(99999);
        Assert.IsType<NotFoundResult>(result);
    }

    [Fact]
    public async Task Delete_Admin_RemovesMeasure()
    {
        var measure = await SeedMeasureAsync("内科病棟");

        var result = await _controller.Delete(measure.Id);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(PreventiveMeasuresController.Index), redirect.ActionName);
        Assert.False(await _db.PreventiveMeasures.AnyAsync(m => m.Id == measure.Id));
        Assert.NotNull(_controller.TempData["Success"]);
    }
}
