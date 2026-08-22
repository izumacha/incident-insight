// モデル(Incidentなど)を使えるようにする
using IncidentInsight.Web.Models;
// ViewModel(RecurrenceAlertなど)を使えるようにする
using IncidentInsight.Web.Models.ViewModels;

// このサービスの名前空間(置き場所)を宣言している
namespace IncidentInsight.Web.Services;

/// <summary>
/// 再発(recurrence)検出の候補抽出クエリと時間フィルタを一箇所に集約する。
/// 以前は HomeController.Index (ダッシュボード警告 / 90 日窓) と
/// IncidentsController.Details (類似一覧 / 時間無制限) にハードコードされており、
/// マッチングルール変更時に実装が乖離しやすかった。
/// </summary>
public interface IRecurrenceService
{
    /// <summary>
    /// <paramref name="incident"/> と再発関係にあるインシデントを返す。
    /// 「同部署 × 同インシデント種別 × 原因分類の重なり」が判定ルール。
    /// 候補クエリは <see cref="RecurrenceService.MaxAlertCandidateRows"/> 件（発生日の
    /// 新しい順）で打ち切られる（<see cref="FindRecurrenceAlertsAsync"/> と同じ上限）。
    /// </summary>
    /// <param name="incident">対象インシデント。CauseAnalyses が事前にロードされていること。</param>
    /// <param name="scope">
    /// 検索対象となるインシデントの集合。呼び出し側で <c>ScopedByUser</c> などの
    /// 部署スコープを済ませた <see cref="IQueryable{Incident}"/> を渡す。
    /// </param>
    /// <param name="within">時間窓。null の場合は無制限。</param>
    // 指定インシデントと類似する過去案件を検索するメソッド(非同期)
    Task<List<Incident>> FindRecurrencesForIncidentAsync(
        Incident incident,
        IQueryable<Incident> scope,
        TimeSpan? within = null,
        CancellationToken ct = default);

    /// <summary>
    /// ダッシュボード用のバッチ検出。<paramref name="recentWindow"/> 以内に発生した
    /// インシデント群から再発アラートを組み立てる。候補抽出は 1 クエリに集約される。
    /// </summary>
    /// <param name="scope">
    /// 検索対象となるインシデントの集合。呼び出し側で <c>ScopedByUser</c> などの
    /// 部署スコープを済ませた <see cref="IQueryable{Incident}"/> を渡す。
    /// </param>
    /// <param name="causeCategories">
    /// 原因分類マスタ。アラート見出しに出す分類名（「親 &gt; 子」）を引くためだけに使う。
    /// インシデントと違い部署スコープの対象ではない（分類マスタは非 PHI で、
    /// 原因分類ドロップダウンでも全ユーザーに絞り込み無しで見せている）。
    /// DbContext を保持しない設計を保つため、<paramref name="scope"/> と同じく
    /// クエリを呼び出し側から受け取る。
    /// </param>
    /// <param name="recentWindow">再発とみなす時間窓。</param>
    /// <param name="ct">キャンセル用トークン。</param>
    // ダッシュボード用に、最近発生したインシデント群から再発アラートを一括生成する
    Task<List<RecurrenceAlert>> FindRecurrenceAlertsAsync(
        IQueryable<Incident> scope,
        IQueryable<CauseCategory> causeCategories,
        TimeSpan recentWindow,
        CancellationToken ct = default);
}
