using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.ViewModels;

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
    /// </summary>
    /// <param name="incident">対象インシデント。CauseAnalyses が事前にロードされていること。</param>
    /// <param name="scope">
    /// 検索対象となるインシデントの集合。呼び出し側で <c>ScopedByUser</c> などの
    /// 部署スコープを済ませた <see cref="IQueryable{Incident}"/> を渡す。
    /// </param>
    /// <param name="within">時間窓。null の場合は無制限。</param>
    Task<List<Incident>> FindRecurrencesForIncidentAsync(
        Incident incident,
        IQueryable<Incident> scope,
        TimeSpan? within = null,
        CancellationToken ct = default);

    /// <summary>
    /// ダッシュボード用のバッチ検出。<paramref name="recentWindow"/> 以内に発生した
    /// インシデント群から再発アラートを組み立てる。候補抽出は 1 クエリに集約される。
    /// </summary>
    Task<List<RecurrenceAlert>> FindRecurrenceAlertsAsync(
        IQueryable<Incident> scope,
        TimeSpan recentWindow,
        CancellationToken ct = default);
}
