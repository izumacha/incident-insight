// モデル(Incidentなど)を使えるようにする
using IncidentInsight.Web.Models;

// このサービスの名前空間(置き場所)を宣言している
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
        // 対象インシデントが持つ原因分類IDの集合を作る(Hashで照合を高速化)
        var catIds = target.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
        // 原因分類が1件もないなら再発判定はできないので空リストを返す
        if (catIds.Count == 0) return new List<Incident>();

        // 候補の中から「自分自身を除く/同部署/同種別/原因分類が1つでも重なる」ものを抽出
        return candidates
            .Where(o => o.Id != target.Id
                && o.Department == target.Department
                && o.IncidentType == target.IncidentType
                && o.CauseAnalyses.Any(ca => catIds.Contains(ca.CauseCategoryId)))
            .ToList();
    }
}
