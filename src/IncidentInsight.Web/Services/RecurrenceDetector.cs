using IncidentInsight.Web.Models;

namespace IncidentInsight.Web.Services;

/// <summary>
/// 再発検出の共通マッチングロジック。
/// 「同じ部署 × 同じインシデント種別 × 原因分類の重なり」を再発と判定する。
/// DB アクセスは呼び出し側で制御できるように、純粋関数として in-memory マッチングのみ提供する
/// (HomeController のダッシュボード用バッチ検出と IncidentsController.Details の単発検索で
///  DB 読み方が異なるため、ここに DbContext を持たせない)。
/// </summary>
public static class RecurrenceDetector
{
    /// <summary>
    /// <paramref name="target"/> と再発関係にある候補を <paramref name="candidates"/> から抽出する。
    /// target.CauseAnalyses と各 candidate.CauseAnalyses が事前にロードされている必要がある。
    /// </summary>
    public static List<Incident> FindSimilar(Incident target, IEnumerable<Incident> candidates)
    {
        var catIds = target.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
        if (catIds.Count == 0) return new List<Incident>();

        return candidates
            .Where(o => o.Id != target.Id
                && o.Department == target.Department
                && o.IncidentType == target.IncidentType
                && o.CauseAnalyses.Any(ca => catIds.Contains(ca.CauseCategoryId)))
            .ToList();
    }
}
