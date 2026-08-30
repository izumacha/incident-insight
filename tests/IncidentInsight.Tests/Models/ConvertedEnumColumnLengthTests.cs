// ApplicationDbContext(EF Core のモデル定義)を使うために取り込む
using IncidentInsight.Web.Data;
// 監査対象エンティティを導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;
// DbContextOptionsBuilder / UseInMemoryDatabase を使うために取り込む
using Microsoft.EntityFrameworkCore;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Models;

// 値変換で文字列として保存する列が、実際に保存しうる値をすべて収められる長さを持つことを固定するテスト。
//
// なぜ必要か: FieldLengths.EnumCode(20)は「enum の名前を保存する列の上限」として定義してあり、
// EveryModelMaxLength_UsesAFieldLengthsConstant は fluent の裸の数値を禁じることで
// **この定数を使うよう積極的に誘導する**。ところが定数の値が実際の enum 名より短いと、
// 誘導に従った結果として保存時に切り詰めが起きる。
//
// 壊れ方が悪質なのは、それが**プロバイダ依存**で、しかもテストからは見えないこと:
//   - SQL Server / PostgreSQL … 列長超過で例外(本番だけ HTTP 500)
//   - SQLite … 長さ制約を強制しないので黙って保存される
//   - テストが使う InMemory … そもそも列長の概念が無い
// つまりビルドも全テストも緑のまま、特定の配備先でだけ壊れる(この repo が各所で避けている形)。
//
// 判定は「enum の名前の長さ」ではなく**変換器が実際に生成する文字列の長さ**で行う。
// Incident.IncidentType は IncidentTypeMapping が日本語の DB 文字列へ変換して保存するため、
// enum 名の長さを見ても意味がない(実際 EnumCode ではなく EnumCodeJapanese を使っている)。
public class ConvertedEnumColumnLengthTests
{
    // 検査対象は監査対象の集約(値変換した列を持つのはこの 3 つ)
    public static TheoryData<Type> AuditedEntityTypes => AuditedEntityModel.AuditedEntityTheoryData();

    [Theory]
    [MemberData(nameof(AuditedEntityTypes))]
    public void ConvertedColumns_CanHoldEveryValueTheyStore(Type entityType)
    {
        // EF のモデルを組み立てる(実 DB は不要)
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        using var probe = new ApplicationDbContext(options);

        // 対象エンティティの定義を引く
        var entity = probe.Model.FindEntityType(entityType);
        // モデルに載っていない型は前提が崩れているので落とす(fail-closed)
        Assert.NotNull(entity);

        // 上限に収まらない値を見つけた列を溜める
        var offenders = new List<string>();

        // 値変換が設定されていて、かつ長さ上限を持つ列だけを見る
        foreach (var property in entity!.GetProperties())
        {
            // この列に設定された変換器(書き方によっては null になる。下の分岐参照)
            var converter = property.GetValueConverter();

            // 「文字列として保存される」判定は 2 通りの書き方の両方を見る必要がある(実測):
            //   - HasConversion<string>()       → GetProviderClrType() が string / 変換器は null
            //   - HasConversion(v => …, v => …) → 変換器が string / GetProviderClrType() は null
            // 片方だけを見ると、もう一方の書き方の列がこの検査から丸ごと外れる
            //   (実際この検査の初版は変換器しか見ておらず、EnumCode を 5 に縮める変異で
            //    赤にならなかった —— Severity / Status / MeasureType が素通りしていた)
            var storedAsString = converter?.ProviderClrType == typeof(string)
                || property.GetProviderClrType() == typeof(string);
            if (!storedAsString) continue;

            // 長さ上限が無い列は「収まらない」ことが起きえないので対象外
            var maxLength = property.GetMaxLength();
            if (maxLength is null) continue;

            // CLR 側が enum のときだけ、取りうる値を全列挙できる
            var clrType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
            if (!clrType.IsEnum) continue;

            // その enum が取りうる値を 1 つずつ変換し、上限を超えるものを探す
            foreach (var value in Enum.GetValues(clrType))
            {
                // 実際に DB へ入る文字列を得る。変換器があればそれを通し、
                // 無い場合(HasConversion<string>())は EF と同じく enum の名前が保存される
                var stored = converter is not null
                    ? converter.ConvertToProvider(value) as string
                    : value.ToString();

                // 変換結果が文字列でなければこの検査の前提外なので読み飛ばす
                if (stored is null) continue;

                // 上限を超えていれば、どの列のどの値が何文字なのかを記録する
                if (stored.Length > maxLength.Value)
                {
                    offenders.Add(
                        $"{entityType.Name}.{property.Name}: \"{stored}\" は {stored.Length} 文字で上限 {maxLength.Value} を超えます");
                }
            }
        }

        // 超過が 1 件も無いことを確認する(失敗時は列・値・長さをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "値変換で文字列として保存する列の長さ上限が、実際に保存しうる値より短いです。" +
            "SQL Server / PostgreSQL では保存時に例外、SQLite では黙って切り詰められ、" +
            "テストが使う InMemory では列長そのものが無いため気付けません: " +
            string.Join(" / ", offenders));
    }
}
