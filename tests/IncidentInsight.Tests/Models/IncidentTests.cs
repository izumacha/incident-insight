using IncidentInsight.Web.Models;
using IncidentInsight.Web.Models.Enums;
using System.ComponentModel.DataAnnotations;

namespace IncidentInsight.Tests.Models;

public class IncidentTests
{
    // テスト内で使う固定の「今日」— DateTime.Today 直呼びを避け決定論的テストにするため固定値を使う
    private static readonly DateTime Today = new DateTime(2026, 6, 11);

    // --- SeverityLabel / SeverityColor ---

    [Theory]
    [InlineData(IncidentSeverity.Level0, "レベル0 (ヒヤリハット)", "secondary")]
    [InlineData(IncidentSeverity.Level1, "レベル1 (患者への影響なし)", "info")]
    [InlineData(IncidentSeverity.Level3a, "レベル3a (軽微な処置)", "warning")]
    [InlineData(IncidentSeverity.Level5, "レベル5 (死亡)", "dark")]
    public void SeverityLabel_And_Color_AreCorrect(IncidentSeverity severity, string expectedLabel, string expectedColor)
    {
        // 各重症度に対応する日本語ラベルと Bootstrap カラー名が正しいか検証する
        var incident = new Incident { Severity = severity };
        // SeverityLabel が期待ラベルと一致するか確認する
        Assert.Equal(expectedLabel, incident.SeverityLabel);
        // SeverityColor が期待色と一致するか確認する
        Assert.Equal(expectedColor, incident.SeverityColor);
    }

    // --- MeasureStatusSummaryOn ---

    [Fact]
    public void MeasureStatusSummary_NoMeasures_Returns未登録()
    {
        // 再発防止策が一件も登録されていないとき「未登録」になることを確認する
        var incident = new Incident();
        // MeasureStatusSummaryOn に固定の今日を渡して「未登録」が返るか検証する
        Assert.Equal("未登録", incident.MeasureStatusSummaryOn(Today));
    }

    [Fact]
    public void MeasureStatusSummary_AllCompleted_Returns完了()
    {
        // すべての再発防止策が完了済みのとき「完了」になることを確認する
        var incident = new Incident
        {
            // 期限が将来に設定された完了済み対策を2件登録する
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                // 1件目：10日後が期限の完了済み対策
                new() { Status = MeasureStatus.Completed, DueDate = Today.AddDays(10) },
                // 2件目：5日後が期限の完了済み対策
                new() { Status = MeasureStatus.Completed, DueDate = Today.AddDays(5) }
            }
        };
        // 全件完了なので「完了」が返るはずと検証する
        Assert.Equal("完了", incident.MeasureStatusSummaryOn(Today));
    }

    [Fact]
    public void MeasureStatusSummary_AnyOverdue_Returns期限超過()
    {
        // 期限超過の対策が1件でもあれば「期限超過」になることを確認する（昨日が期限）
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                // 昨日が期限の計画中対策（期限超過）
                new() { Status = MeasureStatus.Planned, DueDate = Today.AddDays(-1) }
            }
        };
        // 超過対策があるので「期限超過」が返るはずと検証する
        Assert.Equal("期限超過", incident.MeasureStatusSummaryOn(Today));
    }

    [Fact]
    public void MeasureStatusSummary_InProgressNotOverdue_Returns進行中()
    {
        // 期限内の進行中対策があれば「進行中」になることを確認する
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                // 5日後が期限の進行中対策（期限内）
                new() { Status = MeasureStatus.InProgress, DueDate = Today.AddDays(5) }
            }
        };
        // 期限内の進行中対策があるので「進行中」が返るはずと検証する
        Assert.Equal("進行中", incident.MeasureStatusSummaryOn(Today));
    }

    [Fact]
    public void MeasureStatusSummary_OnlyPlanned_Returns計画中()
    {
        // 計画中の対策のみ存在するとき「計画中」になることを確認する
        var incident = new Incident
        {
            PreventiveMeasures = new List<PreventiveMeasure>
            {
                // 10日後が期限の計画中対策（期限内）
                new() { Status = MeasureStatus.Planned, DueDate = Today.AddDays(10) }
            }
        };
        // 期限内の計画中対策のみなので「計画中」が返るはずと検証する
        Assert.Equal("計画中", incident.MeasureStatusSummaryOn(Today));
    }

    // --- Validation ---

    [Fact]
    public void Incident_MissingRequired_FailsValidation()
    {
        // 必須フィールドが空のとき DataAnnotations バリデーションが失敗することを確認する
        var incident = new Incident { Department = "", ReporterName = "" };
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(incident);
        // バリデーションを実行して結果をリストに収集する
        Validator.TryValidateObject(incident, ctx, results, true);

        // バリデーションに失敗したフィールド名の一覧を取り出す
        var failedFields = results.SelectMany(r => r.MemberNames).ToList();
        // Department が失敗リストに含まれるか確認する
        Assert.Contains("Department", failedFields);
        // ReporterName が失敗リストに含まれるか確認する
        Assert.Contains("ReporterName", failedFields);
        // Description が失敗リストに含まれるか確認する
        Assert.Contains("Description", failedFields);
    }

    [Fact]
    public void Incident_AllRequired_PassesValidation()
    {
        // 必須フィールドをすべて設定したとき DataAnnotations バリデーションが通ることを確認する
        var incident = new Incident
        {
            // 発生日時に固定の今日を設定する（DateTime.Now 直呼びを避ける）
            OccurredAt = Today,
            // 部署名を設定する
            Department = "内科病棟",
            // インシデント種別を設定する
            IncidentType = IncidentTypeKind.Medication,
            // 重症度を設定する
            Severity = IncidentSeverity.Level2,
            // インシデント内容の説明を設定する
            Description = "患者AにBさんの薬を投与した",
            // 報告者名を設定する
            ReporterName = "山田 花子"
        };
        // バリデーション結果を受け取るリストを用意する
        var results = new List<ValidationResult>();
        // バリデーションコンテキストを作成する
        var ctx = new ValidationContext(incident);
        // バリデーションを実行し、成功/失敗フラグを受け取る
        var isValid = Validator.TryValidateObject(incident, ctx, results, true);

        // 全フィールド設定済みなのでバリデーションが通るはずと確認する
        Assert.True(isValid);
        // エラーリストが空であることを確認する
        Assert.Empty(results);
    }
}
