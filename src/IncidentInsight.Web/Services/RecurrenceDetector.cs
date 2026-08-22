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
        var catIds = CauseCategoryIdsOf(target);
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

    /// <summary>
    /// <paramref name="target"/> と <paramref name="similar"/> の間で実際に重なった原因分類の ID を、
    /// 「重なりの強い順」(その分類を共有する類似インシデントが多い順、同数なら ID の昇順)で返す。
    /// </summary>
    /// <remarks>
    /// 「何をもって重なりとみなすか」は <see cref="FindSimilar"/> と同じ規則でなければならない
    /// (説明文だけが古い規則のまま取り残されると、画面が「重なった分類」を誤って示す)。
    /// そのため判定に使う分類 ID の取り出しは <see cref="CauseCategoryIdsOf"/> に集約し、
    /// この 2 つのメソッドが同じ 1 つの定義を共有する形にしている(§6 DRY)。
    /// 並び順を「重なりの強い順」にするのは、呼び出し側(ダッシュボードの見出し)が
    /// 上限件数で打ち切って表示するため、切り捨てるなら共有の弱い分類からにしたいため。
    /// 同数のときの副次キーを ID にするのは、表示のたびに順番が入れ替わらないようにする
    /// (名前順にしないのは、文字列比較の結果が実行環境のロケール設定で変わり得るため)。
    /// </remarks>
    /// <param name="target">再発アラートの基点インシデント。</param>
    /// <param name="similar"><see cref="FindSimilar"/> が返した類似インシデント。</param>
    /// <returns>重なった原因分類の ID(重なりの強い順)。重なりが無ければ空リスト。</returns>
    public static List<int> FindSharedCauseCategoryIds(Incident target, IEnumerable<Incident> similar)
    {
        // 基点インシデントが持つ原因分類 ID の集合(FindSimilar と同じ取り出し方)
        var catIds = CauseCategoryIdsOf(target);
        // 原因分類が1件もないなら重なりようが無いので空リストを返す
        if (catIds.Count == 0) return new List<int>();

        // 類似インシデントごとに分類 ID を重複除去してから並べ、基点と重なるものだけを残す。
        // インシデント単位で重複除去してから数えることで、グループの件数が
        // 「その分類を共有する類似インシデントの数」と一致する
        // (同じ分類のなぜなぜ分析を 1 件のインシデントが複数持っていても二重に数えない)
        return similar
            .SelectMany(s => CauseCategoryIdsOf(s))
            .Where(id => catIds.Contains(id))
            .GroupBy(id => id)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key)
            .Select(g => g.Key)
            .ToList();
    }

    /// <summary>
    /// インシデントが持つ原因分類 ID の集合を取り出す(重複は除去する)。
    /// 再発判定の「重なり」を数える単位を 1 か所に定めるヘルパー。
    /// </summary>
    /// <remarks>
    /// 「重なりの単位」を変える（例: 親分類へ丸めて突き合わせる）ときに、この 1 か所だけを
    /// 直せば全経路が追随するようにするため public にしている。ダッシュボード側
    /// （<see cref="FindSimilar"/> / <see cref="FindSharedCauseCategoryIds"/>）だけでなく、
    /// インシデント詳細の類似一覧を組み立てる <see cref="RecurrenceService"/> からも呼ぶ。
    /// </remarks>
    /// <param name="incident">分類 ID を取り出す対象のインシデント。</param>
    /// <returns>そのインシデントが指す原因分類 ID の集合。</returns>
    public static HashSet<int> CauseCategoryIdsOf(Incident incident) =>
        // なぜなぜ分析それぞれが指す原因分類 ID を集めて集合にする(Hash で照合を高速化)
        incident.CauseAnalyses.Select(ca => ca.CauseCategoryId).ToHashSet();
}
