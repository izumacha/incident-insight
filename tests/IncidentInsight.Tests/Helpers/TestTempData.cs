using Microsoft.AspNetCore.Mvc.ViewFeatures;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// No-op ITempDataDictionary for controller unit tests that don't need TempData persistence.
/// </summary>
public class TestTempData : Dictionary<string, object?>, ITempDataDictionary
{
    public void Keep() { }
    public void Keep(string key) { }
    public void Load() { }
    public object? Peek(string key) => TryGetValue(key, out var v) ? v : null;
    public void Save() { }
}
