// JSON の直列化・解析に使う
using System.Text.Json;
// JsonResult / IActionResult を扱う
using Microsoft.AspNetCore.Mvc;

namespace IncidentInsight.Tests.Helpers;

/// <summary>
/// <see cref="JsonResult"/> を返すアクション(グラフ用 JSON API)の中身を読むための共有ヘルパー。
/// </summary>
/// <remarks>
/// <para><b>なぜ匿名型を直接見ないのか。</b> コントローラが返すのは匿名型なので、
/// テストからプロパティ名で辿るにはリフレクションか動的型が要る。実際に本番のフロントが
/// 受け取るのは<b>直列化された JSON</b> なので、同じ経路(MVC と同じ camelCase 規約)を
/// 通してから読む方が、キー名の変更まで含めて忠実に固定できる。</para>
///
/// <para><b>置き場所を共有にした理由。</b> 同じ読み取りが
/// <c>AnalyticsControllerTests</c>(形状の固定)と <c>UnlistedFilterValuePolicyTests</c>
/// (絞り込み方式の固定)の 2 か所で要るようになった。写しを持つと、片方だけ
/// 直列化の設定(命名規約)を直したときに、もう片方が本番と違う読み方のまま緑になる。</para>
/// </remarks>
public static class JsonResultReader
{
    // MVC の既定と同じ命名規約(camelCase)で直列化する。
    // ここを既定(PascalCase)のままにすると、テストだけが本番と違うキー名を読むことになる
    private static readonly JsonSerializerOptions MvcJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    /// <summary>
    /// アクションの戻り値を <see cref="JsonResult"/> として直列化し、解析した文書を返す。
    /// </summary>
    /// <param name="result">グラフ用 JSON API のアクションが返した結果。</param>
    /// <returns>呼び出し側が <c>using</c> で解放する <see cref="JsonDocument"/>。</returns>
    public static JsonDocument ToJsonDocument(IActionResult result)
    {
        // JsonResult でなければテストとして失敗させる(View などが返っていたら形が違う)
        var json = Assert.IsType<JsonResult>(result);
        // MVC と同じ規約で直列化する
        var serialized = JsonSerializer.Serialize(json.Value, MvcJsonOptions);
        // 解析した文書を返す
        return JsonDocument.Parse(serialized);
    }
}
