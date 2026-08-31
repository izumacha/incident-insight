// 長さ上限の管理対象を導出する共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

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
    // 検査対象は長さ上限の管理対象となる業務エンティティ。裸の数値を禁じて EnumCode の使用を
    // 誘導する検査(EveryModelMaxLength_UsesAFieldLengthsConstant)と同じ範囲にそろえる —
    // 誘導する範囲より検証する範囲が狭いと、その差分が切り詰めの起きる死角になる
    public static TheoryData<Type> LengthGovernedEntityTypes =>
        AuditedEntityModel.LengthGovernedTheoryData();

    [Theory]
    [MemberData(nameof(LengthGovernedEntityTypes))]
    public void ConvertedColumns_CanHoldEveryValueTheyStore(Type entityType)
    {
        // 走査は純粋関数に委ね、ここは結果の表明だけを行う。
        // 以前は網羅ガードの [Fact] がこのテストメソッドをそのまま呼び、static の側路
        // (ConcurrentDictionary)経由で「見た列」を受け取っていた。その形だと
        //   - 切り詰め違反があるとガード側も同じ例外で落ち、ガード固有の失敗メッセージ
        //     (「見るべき列を全部見ていない」)が出ないので原因の切り分けが逆に難しくなる
        //   - 側路がプロセス寿命の static として残り続ける
        // という副作用があった。純粋関数にすれば、両者が同じ走査を独立に呼べる。
        //
        // なお走査そのものは今も 2 回走る([Theory] の各ケースで 1 回、下の網羅ガードで全件もう 1 回)。
        // 監査対象は数エンティティ・各 20 列程度で、EF の組み立て済みモデルを読むだけなので
        // 実測でも差は出ない。ここで結果を共有すると、また「片方が書いて片方が読む」形に戻り、
        // 実行順に依存する脆さを持ち込むことになるため、素直に 2 回走らせている
        var (offenders, _) = ScanConvertedColumns(entityType);

        // 超過が 1 件も無いことを確認する(失敗時は列・値・長さをメッセージで示す)
        Assert.True(offenders.Count == 0,
            "値変換で文字列として保存する列の長さ上限が、実際に保存しうる値より短いです。" +
            "SQL Server / PostgreSQL では保存時に例外、SQLite では黙って切り詰められ、" +
            "テストが使う InMemory では列長そのものが無いため気付けません: " +
            string.Join(" / ", offenders));
    }

    /// <summary>
    /// 指定エンティティの「値変換で文字列として保存する列」を走査し、
    /// 上限に収まらない値の一覧と、実際に検査できた列名の一覧を返す純粋関数。
    /// Assert を含まないので、切り詰めの検査と網羅ガードの両方から独立に呼べる。
    /// </summary>
    private static (IReadOnlyList<string> Offenders, IReadOnlyList<string> Examined)
        ScanConvertedColumns(Type entityType)
    {
        // 共有のモデルから対象エンティティの定義を引く。
        // ここで DbContext を作り直すと、検査ごとに InMemory のストアがプロセス内キャッシュへ
        // 溜まり続ける(AuditedEntityModel が Lazy でモデルを 1 回だけ組み立てている理由と同じ)
        var entity = AuditedEntityModel.EfModel.FindEntityType(entityType);
        // モデルに載っていない型は前提が崩れているので落とす(fail-closed)。
        // 純粋関数なので Assert ではなく例外で伝える
        if (entity is null)
        {
            // どの型が解決できなかったのかを示して失敗させる
            throw new InvalidOperationException(
                $"型 '{entityType.Name}' に対応するエンティティが EF のモデルに見つかりません。");
        }

        // 上限に収まらない値を見つけた列を溜める
        var offenders = new List<string>();

        // 実際に検査できた列の名前(網羅ガード用。下の [Fact] が「見るべき列を全部見たか」を照合する)
        var examined = new List<string>();

        // 値変換が設定されていて、かつ長さ上限を持つ列だけを見る
        foreach (var property in entity.GetProperties())
        {
            // この列に設定された変換器(書き方によっては null になる。下の分岐参照)
            var converter = property.GetValueConverter();

            // 「文字列列か」の判定は共有ヘルパーに委ねる。ここに規則を書き写すと、
            // 規則を直したとき(EF の版が上がって型の現れる場所が変わる等)に片方だけが
            // 取り残され、この検査だけが黙って対象を狭める
            //   (実際この検査の初版は独自に変換器だけを見ており、EnumCode を 5 に縮める変異で
            //    赤にならなかった —— Severity / Status / MeasureType が素通りしていた)
            if (!AuditedEntityModel.IsStringColumnPublic(property)) continue;

            // 長さ上限が無い列は「収まらない」ことが起きえないので対象外
            var maxLength = property.GetMaxLength();
            if (maxLength is null) continue;

            // CLR 側が enum のときだけ、取りうる値を全列挙できる
            var clrType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
            if (!clrType.IsEnum) continue;

            // ここまで来た列は実際に中身を検査する
            examined.Add(property.Name);

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

        // 走査結果をそのまま返す(判断は呼び出し側が行う)
        return (offenders, examined);
    }

    [Fact]
    public void EveryLengthLimitedEnumColumn_IsActuallyExamined()
    {
        // 「見るべきだった列」を、この検査が使う判定とは**独立した手がかり**で求める。
        //
        // 独立させるのが要点。上の検査は AuditedEntityModel.IsStringColumn で対象を絞るので、
        // その判定が狭まった瞬間(EF の版が上がって型の現れる場所が変わる / 3 つ目の
        // HasConversion の書き方が増える 等)に列が読み飛ばされ、「違反ゼロ」= 緑として
        // 通ってしまう。同じ判定でガードを書くと、判定と一緒にガードも狭まって意味がない。
        //
        // 独立な手がかりとして「enum 型で、かつ長さ上限が設定されている永続化列」を使う。
        // enum に長さ上限を付ける理由は文字列として保存する以外に無いので、この条件に当てはまる
        // 列は必ず切り詰めの検査対象であるべき。
        var missed = new List<string>();

        foreach (var entityType in AuditedEntityModel.LengthGovernedEntityTypes())
        {
            // [Theory] と同じ走査を独立に呼び、実際に見た列を受け取る。
            // Assert を含まない純粋関数なので、切り詰め違反があってもここは落ちず、
            // 「見るべき列を全部見たか」というこのガード固有の失敗だけを報告できる
            var (_, seen) = ScanConvertedColumns(entityType);

            // このエンティティで見るべきだった列を独立な条件で求める
            var entity = AuditedEntityModel.EfModel.FindEntityType(entityType)!;
            foreach (var property in entity.GetProperties())
            {
                // 長さ上限が無い列は切り詰めようがないので対象外
                if (property.GetMaxLength() is null) continue;
                // enum 以外は取りうる値を全列挙できないので対象外
                var clrType = Nullable.GetUnderlyingType(property.ClrType) ?? property.ClrType;
                if (!clrType.IsEnum) continue;
                // 見るべきなのに見ていない列を記録する
                if (!seen.Contains(property.Name)) missed.Add($"{entityType.Name}.{property.Name}");
            }
        }

        // 取りこぼしが 1 件も無いことを確認する(fail-closed)
        Assert.True(missed.Count == 0,
            "長さ上限を持つ enum 列が切り詰めの検査対象になっていません: " + string.Join(", ", missed) +
            "。判定(AuditedEntityModel.IsStringColumn)が対象を拾えなくなっている可能性があります " +
            "——このままだと切り詰めの検出網は「違反ゼロ」として緑のまま無力化されます。");
    }
}
