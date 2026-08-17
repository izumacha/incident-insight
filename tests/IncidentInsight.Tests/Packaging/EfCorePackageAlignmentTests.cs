// csproj / dependabot.yml を正規表現で走査するために取り込む
using System.Text.RegularExpressions;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Packaging;

// Guard-rail test: EF Core 系 NuGet パッケージのメジャー版が全プロジェクトで揃っていることを検査する。
//
// 背景: このアプリは DB プロバイダ非依存(SQLite / SQL Server / PostgreSQL を Database:Provider で
// 実行時切替)で、各プロバイダ実装は EF Core 本体(Microsoft.EntityFrameworkCore.Relational)と
// 同じメジャー版でしか動作保証がない。ところが一部のパッケージだけメジャー版を上げても、
//   - ビルドは通る(NuGet は Relational を最も高い版へ解決するだけ)
//   - テストも通る(テストは InMemory / SQLite しか触らず、PostgreSQL 経路を実行しない)
// ため、「PostgreSQL 配備でだけ実行時に壊れる」という無言の破壊になる。
// 実際、Dependabot の既定(major は個別 PR)ではプロバイダごとに 1 本ずつ PR が作られ、
// どれか 1 本をマージした時点でこの状態になっていた。
//
// 対策は 2 段構え。
//   (1) .github/dependabot.yml の nuget-ef-core グループが major も含めて 1 本の PR に束ねる(予防)
//   (2) 本テストが版ズレそのものを検出する(手動編集や設定変更で束ねが外れた場合の最後の砦)
//
// 「EF Core 系とは何か」の定義は dependabot.yml のグループ patterns を唯一の真実の源として読む。
// ここへ書き写すと、パッケージを 1 つ足したときに片方だけ更新されて検出網に穴が空くため(§6)。
public class EfCorePackageAlignmentTests
{
    // dependabot.yml で EF Core 系を束ねているグループ名(この名前が消えたら束ねが外れたということ)
    private const string EfCoreGroupName = "nuget-ef-core";

    // minor / patch をまとめているグループ名(EF Core 系を除外していることを確認する対象)
    private const string MinorAndPatchGroupName = "nuget-minor-and-patch";

    // 検査対象の csproj(リポジトリルートからの相対パス)。両プロジェクトが同じ EF Core 版を
    // 参照している必要がある(テスト側だけ上げても web 側と食い違う)
    private static readonly string[] ProjectFiles =
    {
        Path.Combine("src", "IncidentInsight.Web", "IncidentInsight.Web.csproj"),
        Path.Combine("tests", "IncidentInsight.Tests", "IncidentInsight.Tests.csproj")
    };

    // csproj の <PackageReference Include="..." Version="..." /> から ID と版を抜き出す正規表現。
    // 属性順は Include → Version 固定(このリポジトリの既存記述に合わせる)
    private static readonly Regex PackageReferenceRegex =
        new(@"<PackageReference\s+Include=""(?<id>[^""]+)""\s+Version=""(?<version>[^""]+)""", RegexOptions.None);

    [Fact]
    public void EfCorePackages_ShareTheSameMajorVersion()
    {
        // dependabot.yml が定める「EF Core 系」の判定パターンを読み出す
        var patterns = ReadGroupPatterns(EfCoreGroupName, "patterns");

        // 見つかった EF Core 系パッケージを「どのファイルの・どの ID が・どの版か」の形で集める
        var found = new List<(string Project, string Id, string Version)>();

        // 検査対象の csproj を 1 つずつ読む
        foreach (var relativePath in ProjectFiles)
        {
            // csproj の絶対パスを組み立てる
            var path = Path.Combine(FindRepositoryRoot(), relativePath);
            // 移動・改名を検知できるよう存在を確認する
            Assert.True(File.Exists(path), $"{path} が見つかりません。ProjectFiles の一覧を更新してください。");
            // ファイル全体を読み込む
            var source = File.ReadAllText(path);

            // この csproj のパッケージ参照をすべて列挙する
            foreach (Match match in PackageReferenceRegex.Matches(source))
            {
                // パッケージ ID を取り出す
                var id = match.Groups["id"].Value;
                // EF Core 系でなければ対象外(xunit や Bootstrap などは版が揃う必要はない)
                if (!MatchesAnyPattern(id, patterns)) continue;
                // EF Core 系なので、判定材料として記録する
                found.Add((relativePath, id, match.Groups["version"].Value));
            }
        }

        // 1 件も見つからないのは検出パターンの劣化(csproj の書式変更など)を疑うべき状態
        Assert.True(found.Count > 0,
            "EF Core 系のパッケージ参照が 1 件も見つかりませんでした。"
            + "csproj の記述形式か dependabot.yml の patterns が変わった可能性があります。");

        // 版のメジャー番号だけを取り出して重複を除く(9.0.19 と 9.0.20 は「揃っている」とみなす。
        // EF Core が動作保証を切るのはメジャー版の食い違いで、パッチ差は問題にならないため)
        var majors = found.Select(p => MajorVersionOf(p.Project, p.Id, p.Version)).Distinct().ToList();

        // メジャー版が 1 種類であること(2 種類以上あれば、どれがどの版かを添えて落とす)
        Assert.True(majors.Count == 1,
            "EF Core 系パッケージのメジャー版が揃っていません。プロバイダ実装は EF Core 本体と同じ"
            + "メジャー版でしか動作保証がなく、揃っていない組み合わせは PostgreSQL 配備でだけ実行時に壊れます"
            + "(ビルドもテストも通るため気付けません)。全て同時に上げてください:\n"
            + string.Join("\n", found.Select(p => $"  {p.Project}: {p.Id} = {p.Version}")));
    }

    [Fact]
    public void DependabotConfig_KeepsEfCorePackagesOutOfTheMinorAndPatchGroup()
    {
        // EF Core 系グループの patterns(束ねる対象)を読み出す
        var efCorePatterns = ReadGroupPatterns(EfCoreGroupName, "patterns");
        // minor / patch グループの exclude-patterns(束ねから外す対象)を読み出す
        var excludedPatterns = ReadGroupPatterns(MinorAndPatchGroupName, "exclude-patterns");

        // 2 つの一覧が完全に一致すること。片方だけにパッケージを足すと、そのパッケージは
        // update-type によって入るグループが変わり(minor は minor-and-patch 側、major は
        // ef-core 側)、結局メジャー更新だけが単独 PR で現れる状態に戻ってしまう
        Assert.True(efCorePatterns.SequenceEqual(excludedPatterns, StringComparer.Ordinal),
            $"dependabot.yml の {EfCoreGroupName}.patterns と {MinorAndPatchGroupName}.exclude-patterns が"
            + "一致していません。EF Core 系を追加・削除するときは両方を同じ内容に保ってください:\n"
            + $"  {EfCoreGroupName}.patterns         = [{string.Join(", ", efCorePatterns)}]\n"
            + $"  {MinorAndPatchGroupName}.exclude-patterns = [{string.Join(", ", excludedPatterns)}]");
    }

    // 版文字列("8.0.29" など)からメジャー番号を取り出す。解釈できない形式は
    // 黙って 0 として扱わず、どのパッケージが原因かを示して失敗させる(fail-closed)
    private static int MajorVersionOf(string project, string id, string version)
    {
        // '.' より前の部分がメジャー番号にあたる(区切りが無ければ全体を見る)
        var head = version.Split('.')[0];
        // 数値として解釈できることを確認しつつ値を得る
        Assert.True(int.TryParse(head, out var major),
            $"{project} の {id} のバージョン \"{version}\" からメジャー番号を読み取れませんでした。");
        // 読み取れたメジャー番号を返す
        return major;
    }

    // パッケージ ID が patterns のいずれかに当てはまるかを判定する。
    // dependabot の patterns は末尾 '*' のワイルドカードを使うため、正規表現へ変換して照合する
    // (パターンはリポジトリ内の設定ファイル由来で外部入力ではないが、記号は必ずエスケープする)
    private static bool MatchesAnyPattern(string packageId, IReadOnlyList<string> patterns) =>
        // いずれか 1 つでも一致すれば EF Core 系とみなす
        patterns.Any(pattern => Regex.IsMatch(
            packageId,
            // '*' だけをワイルドカードとして扱い、それ以外の記号は literal として扱う
            "^" + string.Join(".*", pattern.Split('*').Select(Regex.Escape)) + "$",
            // NuGet のパッケージ ID は大文字小文字を区別しないため、照合も区別しない
            RegexOptions.IgnoreCase));

    // dependabot.yml から「指定グループの指定キー(patterns / exclude-patterns)」の一覧を読み出す。
    //
    // YAML パーサを新しく依存に足さず、既存テスト(AnalyticsScriptContractTests 等)と同じく
    // ソースを直接走査する。対象は自分たちが書いた既知の形だけで、想定外の形なら黙って
    // 空を返さず失敗させる(空を返すと「対象 0 件」で検査が素通りしてしまう)
    private static IReadOnlyList<string> ReadGroupPatterns(string groupName, string key)
    {
        // dependabot.yml の絶対パスを組み立てる
        var path = Path.Combine(FindRepositoryRoot(), ".github", "dependabot.yml");
        // 設定ファイルの存在を確認する
        Assert.True(File.Exists(path), $"{path} が見つかりません。");
        // 行単位で読み込む(インデントで入れ子を判断するため)
        var lines = File.ReadAllLines(path);

        // 目的のグループ名が現れた行の位置(見つかるまで -1)
        var groupLine = Array.FindIndex(lines, line => line.TrimEnd().EndsWith($"{groupName}:", StringComparison.Ordinal));
        // グループが消えている＝束ねが外れているので、その事実を明示して落とす
        Assert.True(groupLine >= 0,
            $"dependabot.yml に {groupName} グループが見つかりません。"
            + "EF Core 系をまとめて更新する設定が外れると、プロバイダごとに単独の major PR が作られます。");

        // グループのインデント幅(この幅以下の行が現れたらグループの範囲を抜けたと判断する)
        var groupIndent = IndentOf(lines[groupLine]);
        // 読み取った値を溜める入れ物
        var values = new List<string>();
        // 目的のキー(patterns / exclude-patterns)配下を読んでいる最中かどうか
        var insideKey = false;

        // グループ行の次の行から順に走査する
        for (var i = groupLine + 1; i < lines.Length; i++)
        {
            // 現在行を取り出す
            var line = lines[i];
            // 空行とコメント行は入れ子の判断材料にならないので読み飛ばす
            if (line.Trim().Length == 0 || line.TrimStart().StartsWith('#')) continue;
            // グループと同じかそれより浅いインデントに戻ったらグループの範囲は終わり
            if (IndentOf(line) <= groupIndent) break;
            // 目的のキーの開始行なら、以降の箇条書きを読み取る状態へ移る
            if (line.Trim() == $"{key}:")
            {
                // 読み取り開始
                insideKey = true;
                // この行自体には値が無いので次の行へ
                continue;
            }
            // キーの外側にいる間は何もしない
            if (!insideKey) continue;
            // 箇条書き("- ...")でなくなったら、そのキーの一覧は終わり
            if (!line.TrimStart().StartsWith("- ", StringComparison.Ordinal)) break;
            // ダブルクォートで囲まれた値だけを取り出す(行末のコメントは含めない)
            var quoted = Regex.Match(line, @"-\s*""(?<value>[^""]*)""");
            // 想定した書式(引用符付き)でなければ、読み飛ばさず異常として落とす
            Assert.True(quoted.Success, $"dependabot.yml の {groupName}.{key} に想定外の記述があります: {line.Trim()}");
            // 取り出したパターン文字列を記録する
            values.Add(quoted.Groups["value"].Value);
        }

        // 値が 1 つも無いのは設定が壊れている(または書式が変わった)状態なので失敗させる
        Assert.True(values.Count > 0, $"dependabot.yml の {groupName}.{key} から値を読み取れませんでした。");
        // 読み取ったパターン一覧を返す
        return values;
    }

    // 行頭の空白文字数(インデントの深さ)を返す
    private static int IndentOf(string line) =>
        // 先頭から空白でない文字が現れるまでの長さを数える
        line.Length - line.TrimStart().Length;

    // テスト実行ディレクトリから上へ辿り、リポジトリルート(src/IncidentInsight.Web と .github を
    // 併せ持つ階層)を見つける。既存テストは Web プロジェクトだけを探すが、本テストは
    // .github/dependabot.yml と tests/ 配下も読むためルートまで遡る必要がある
    private static string FindRepositoryRoot()
    {
        // ビルド出力ディレクトリを起点にする
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        // ルートに達するまで親を遡る
        while (dir != null)
        {
            // Web プロジェクトと .github の両方を持つ階層がリポジトリルート
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "IncidentInsight.Web"))
                && Directory.Exists(Path.Combine(dir.FullName, ".github")))
            {
                // 見つかったのでその絶対パスを返す
                return dir.FullName;
            }
            // 1 つ上の階層へ移動する
            dir = dir.Parent;
        }
        // 見つからない場合はテスト環境の異常として失敗させる(fail-closed)
        throw new DirectoryNotFoundException("リポジトリルート(src/IncidentInsight.Web と .github を持つ階層)がテスト実行位置から見つかりません。");
    }
}
