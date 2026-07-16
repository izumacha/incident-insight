using Microsoft.AspNetCore.Mvc.ViewFeatures;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// No-op ITempDataDictionary for controller unit tests that don't need TempData persistence.
/// </summary>
public class TestTempData : Dictionary<string, object?>, ITempDataDictionary
{
    // Dictionary<TKey,TValue>'s inherited indexer throws KeyNotFoundException on a missing
    // key, but the real ASP.NET Core TempDataDictionary's indexer getter never throws (it's
    // backed by TryGetValue and returns null for a missing key). Shadow it here so this test
    // double matches the real ITempDataDictionary contract that production code relies on.
    public new object? this[string key]
    {
        get => TryGetValue(key, out var v) ? v : null;
        set => base[key] = value;
    }

    public void Keep() { }
    public void Keep(string key) { }
    public void Load() { }
    public object? Peek(string key) => TryGetValue(key, out var v) ? v : null;
    public void Save() { }
}
