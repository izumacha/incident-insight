// JSON のパースに使う
using System.Text.Json;
// 認可ポリシー名定数
using IncidentInsight.Web.Authorization;
// 共通ヘルパ(日付上限フィルタの安全な排他的上限計算)を使う
using IncidentInsight.Web.Controllers.Internal;
// DbContext を使う
using IncidentInsight.Web.Data;
// AuditLog モデルを使う
using IncidentInsight.Web.Models;
// 日本語ラベル / Bootstrap カラーの一元解決(EnumLabels)を使う
using IncidentInsight.Web.Models.Enums;
// 監査ログ画面用 ViewModel を使う
using IncidentInsight.Web.Models.ViewModels;
// 認可属性
using Microsoft.AspNetCore.Authorization;
// MVC のコントローラ基底
using Microsoft.AspNetCore.Mvc;
// SelectListItem(<select> 用)
using Microsoft.AspNetCore.Mvc.Rendering;
// EF Core 拡張
using Microsoft.EntityFrameworkCore;

// このコントローラの名前空間
namespace IncidentInsight.Web.Controllers;

// 監査ログ閲覧画面(管理者専用)。書き込み API は提供しない — 監査ログは
// AuditSaveChangesInterceptor が単一の入口になるという設計上のルールを守るため。
[Authorize(Policy = Policies.CanViewAuditLog)]
public class AuditLogsController : Controller
{
    // DB アクセス用コンテキスト
    private readonly ApplicationDbContext _db;
    // 1 ページあたりの件数(監査ログは件数が多くなりやすいので少し大きめ)
    private const int PageSize = 50;

    // フィルタ用エンティティ名の許可リスト(監査対象は 3 種類だけ)
    private static readonly string[] AllowedEntityNames = new[]
    {
        nameof(Incident),
        nameof(CauseAnalysis),
        nameof(PreventiveMeasure)
    };

    // フィルタ用操作種別の許可リスト
    private static readonly string[] AllowedOperations = new[] { "Added", "Modified", "Deleted" };

    // コンストラクタ: DI で依存を受け取る
    public AuditLogsController(ApplicationDbContext db)
    {
        _db = db;
    }

    // GET /AuditLogs
    // 監査ログ一覧。エンティティ名 / 操作 / 期間 / 変更者 / 対象キーで絞り込み + ページング
    public async Task<IActionResult> Index(
        string? entityName,
        string? operation,
        string? changedBy,
        string? entityKey,
        DateTime? dateFrom,
        DateTime? dateTo,
        int page = 1)
    {
        // 読み取り専用クエリを用意(監査ログは絶対に変更しないため AsNoTracking)
        var query = _db.AuditLogs.AsNoTracking().AsQueryable();

        // エンティティ名で絞り込み(許可リストにあるときだけ採用)
        if (!string.IsNullOrEmpty(entityName) && AllowedEntityNames.Contains(entityName))
            query = query.Where(a => a.EntityName == entityName);
        // 操作種別で絞り込み(許可リストにあるときだけ採用)
        if (!string.IsNullOrEmpty(operation) && AllowedOperations.Contains(operation))
            query = query.Where(a => a.Operation == operation);
        // 変更者(ユーザー名)で部分一致(大文字小文字を区別しない)
        // string.Contains は SQLite/SQL Server では大文字小文字を区別しない LIKE に翻訳されるが、
        // Npgsql(PostgreSQL) は既定で大文字小文字を区別する比較に翻訳するため、ToUpper() 同士の
        // 比較に統一してプロバイダ間で検索結果が変わらないようにする(DB プロバイダ非依存の原則)
        if (!string.IsNullOrWhiteSpace(changedBy))
        {
            var normalizedChangedBy = changedBy.ToUpper();
            query = query.Where(a => a.ChangedBy.ToUpper().Contains(normalizedChangedBy));
        }
        // 対象キー(エンティティの ID)で完全一致
        if (!string.IsNullOrWhiteSpace(entityKey))
            query = query.Where(a => a.EntityKey == entityKey);
        // 期間下限で絞り込み
        if (dateFrom.HasValue)
            query = query.Where(a => a.ChangedAt >= dateFrom.Value);
        // 期間上限で絞り込み(その日を含めるため翌日 0 時より前まで)
        // 排他的上限は共通ヘルパで安全に計算する(9999-12-31 でも桁あふれで 500 にしない)
        if (dateTo.HasValue)
        {
            // 排他的上限をクエリ式の外で計算しておく(式ツリー内にヘルパ呼び出しを持ち込まない)
            var dateToExclusive = IncidentControllerHelpers.ToExclusiveUpperBound(dateTo.Value);
            // 翌日 0 時(または DateTime.MaxValue)より前の変更日時だけに絞る
            query = query.Where(a => a.ChangedAt < dateToExclusive);
        }

        // 総件数を取得(ページング用)
        var total = await query.CountAsync();
        // ページ番号を有効範囲[1..総ページ数]に補正する(URL 改ざん・桁あふれ対策)。
        // 補正しないと ?page=0 や負数で (page-1)*PageSize が負の OFFSET になり、
        // また巨大値では (page-1)*PageSize が int の範囲を超えて桁あふれ(オーバーフロー)で
        // 負値に化ける。SQLite は負の OFFSET を 0 とみなすが、PostgreSQL / SQL Server は
        // 例外を投げて 500 になるため、DB プロバイダ非依存の不変条件を守るためにここで丸める。
        // (IncidentsController.Index と同じ補正パターン)
        var totalPages = (int)Math.Ceiling(total / (double)PageSize);
        page = Math.Clamp(page, 1, Math.Max(1, totalPages));
        // 新しい順に並べて現在ページ分だけ取得
        var logs = await query
            .OrderByDescending(a => a.ChangedAt)
            .ThenByDescending(a => a.Id)
            .Skip((page - 1) * PageSize)
            .Take(PageSize)
            .ToListAsync();

        // ビュー用のドロップダウン選択肢を組み立てる(ラベルは EnumLabels で一元解決)
        var entityOptions = AllowedEntityNames
            .Select(n => new SelectListItem(EnumLabels.JapaneseAuditEntity(n), n))
            .ToList();
        var operationOptions = AllowedOperations
            .Select(o => new SelectListItem(EnumLabels.JapaneseAuditOperation(o), o))
            .ToList();

        // ViewModel を組み立ててビューに渡す
        var vm = new AuditLogListViewModel
        {
            Logs = logs,
            TotalCount = total,
            Page = page,
            PageSize = PageSize,
            EntityName = entityName,
            Operation = operation,
            ChangedBy = changedBy,
            EntityKey = entityKey,
            DateFrom = dateFrom,
            DateTo = dateTo,
            EntityNameOptions = entityOptions,
            OperationOptions = operationOptions
        };

        // 一覧ビューを描画
        return View(vm);
    }

    // GET /AuditLogs/Details/123
    // 監査ログ 1 件の詳細。ChangesJson をプロパティ単位にパースして表示する
    public async Task<IActionResult> Details(long id)
    {
        // 該当ログを 1 件だけ取得(更新しないので AsNoTracking)
        var log = await _db.AuditLogs.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id);
        // 見つからなければ 404
        if (log == null) return NotFound();

        // JSON を name -> (old, new) の行リストに変換(失敗時は null)
        var changes = ParseChanges(log.ChangesJson);

        // ViewModel を組み立てて詳細ビューを描画
        var vm = new AuditLogDetailViewModel
        {
            Log = log,
            Changes = changes
        };
        return View(vm);
    }

    // ChangesJson(例: {"Description":{"old":"A","new":"B"}, ...})を行リストにパースする。
    // 形式が想定外なら null を返し、ビュー側で生 JSON にフォールバックする。
    private static List<AuditLogChangeRow>? ParseChanges(string? json)
    {
        // 中身が空ならパース不要
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            // ルートが JSON オブジェクトであることを確認
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;

            // 各プロパティを 1 行に変換
            var rows = new List<AuditLogChangeRow>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                // 値がオブジェクトでなければそのまま 1 行として表示する
                if (prop.Value.ValueKind != JsonValueKind.Object)
                {
                    rows.Add(new AuditLogChangeRow
                    {
                        PropertyName = prop.Name,
                        OldValue = null,
                        NewValue = prop.Value.ToString()
                    });
                    continue;
                }

                // {"old": ..., "new": ...} の形を期待してそれぞれ取り出す
                string? oldVal = null;
                string? newVal = null;
                if (prop.Value.TryGetProperty("old", out var oldEl)) oldVal = JsonValueToString(oldEl);
                if (prop.Value.TryGetProperty("new", out var newEl)) newVal = JsonValueToString(newEl);

                rows.Add(new AuditLogChangeRow
                {
                    PropertyName = prop.Name,
                    OldValue = oldVal,
                    NewValue = newVal
                });
            }
            // プロパティ名でソートして View での見比べを安定させる
            return rows.OrderBy(r => r.PropertyName, StringComparer.Ordinal).ToList();
        }
        catch (JsonException)
        {
            // パース失敗(壊れた JSON 等)は null を返してビュー側でフォールバック
            return null;
        }
    }

    // JsonElement を文字列に変換するヘルパ。null は null のまま返す
    private static string? JsonValueToString(JsonElement el) => el.ValueKind switch
    {
        // null はそのまま null として扱う(View で「(なし)」と表示する)
        JsonValueKind.Null => null,
        // 文字列はそのまま
        JsonValueKind.String => el.GetString(),
        // 数値・真偽値・オブジェクト・配列などは生 JSON 表現で返す
        _ => el.ToString()
    };

}
