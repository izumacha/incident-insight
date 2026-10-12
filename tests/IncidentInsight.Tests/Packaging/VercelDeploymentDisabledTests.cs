// vercel.json を JSON として読むために取り込む
using System.Text.Json;

// リポジトリ内のパスを引く共有ヘルパーを使うために取り込む
using IncidentInsight.Tests.Helpers;

// このテストクラスが属する名前空間
namespace IncidentInsight.Tests.Packaging;

// Guard-rail test: リポジトリ側で Vercel の自動デプロイを止めている設定が、黙って外れないようにする。
//
// 【発端】このリポジトリは ASP.NET Core なので Vercel ではビルドできない(プロジェクトは framework: null、
// 最新デプロイは readyState: "ERROR")。にもかかわらず GitHub 連携を張った Vercel プロジェクトが 2 つ
// 残っており、push ごとに必ず赤い signal が 2 本立っていた(issue #193)。vercel.json の
// git.deploymentEnabled: false がそれを止めている。
//
// 【なぜ検査が要るか】vercel.json はどの csproj の glob にも入らず、どの本番コードも読まない。
// つまりこのファイルを削除する差分も、フラグを true へ反転する差分も、dotnet build と
// dotnet test は 1 件も落とさずに通る(実測)。しかも復活する赤は check run ではなく
// 旧来の commit status なので、check-runs API だけを見たレビュアーには「全チェック緑」と映る
// (CLAUDE.md §3 の該当節が同じことを記録している)。退行が差分からもテスト件数からも読み取れないため、
// ここで機械的に落とす。
//
// 【この検査で閉じられる範囲】「ファイルが消えた」「フラグが反転した」までで、
// Vercel 側の Root Directory が別フォルダへ設定されて vercel.json が読まれなくなる形は
// 原理的に見えない(API の応答にその項目が現れないので、テストからも実測できない)。
// そちらは「PR に Vercel の status が立たないこと」を人が確かめる形で守る。
public class VercelDeploymentDisabledTests
{
    // vercel.json の「git」オブジェクトのキー名(Vercel の設定スキーマ側の綴り)
    private const string GitSectionKey = "git";

    // 自動デプロイの可否を表すキー名(Vercel の設定スキーマ側の綴り)
    private const string DeploymentEnabledKey = "deploymentEnabled";

    // Vercel CLI がリンク情報を書き出すディレクトリ(プロジェクト ID と組織 ID を含む)
    private const string VercelLinkDirectoryEntry = ".vercel/";

    [Fact]
    public void VercelJson_DisablesAutomaticGitDeployments()
    {
        // リポジトリ直下の vercel.json のパスを組み立てる
        var path = Path.Combine(RepositoryPaths.Root, "vercel.json");

        // ファイルが存在することを先に確かめる(削除する差分をここで落とす)
        Assert.True(
            File.Exists(path),
            $"vercel.json が見つかりません ({path})。これは Vercel の自動デプロイを止めている唯一の設定で、"
                + "消すと push ごとに赤い commit status が 2 本復活します(issue #193)。消す場合は Vercel 側の"
                + "プロジェクト削除か連携解除を同じ変更セットで行い、この検査も一緒に外してください。");

        // JSON として読み込む(壊れた JSON は Vercel 側でも読めないので、ここで例外になって構わない)
        using var document = JsonDocument.Parse(File.ReadAllText(path));

        // 「git」セクションが存在することを確かめる
        Assert.True(
            document.RootElement.TryGetProperty(GitSectionKey, out var git),
            $"vercel.json に \"{GitSectionKey}\" セクションがありません。"
                + $"\"{GitSectionKey}\": {{ \"{DeploymentEnabledKey}\": false }} を書いてください。");

        // 「deploymentEnabled」キーが存在することを確かめる
        Assert.True(
            git.TryGetProperty(DeploymentEnabledKey, out var deploymentEnabled),
            $"vercel.json の \"{GitSectionKey}\" に \"{DeploymentEnabledKey}\" がありません。"
                + "これが無いと Vercel は既定どおり push ごとにデプロイを試み、必ず失敗します(issue #193)。");

        // 値が JSON の真偽値 false そのものであることを確かめる
        // (文字列の "false" は Vercel 側で真偽値として解釈されないため、型まで固定する)
        Assert.Equal(JsonValueKind.False, deploymentEnabled.ValueKind);
    }

    [Theory]
    [InlineData(".gitignore")]
    [InlineData(".dockerignore")]
    public void VercelLinkDirectory_IsExcludedFrom(string ignoreFileName)
    {
        // 対象の除外設定ファイルのパスを組み立てる
        var path = Path.Combine(RepositoryPaths.Root, ignoreFileName);

        // ファイルが存在することを確かめる(前提が崩れたら黙って緑にせず落とす)
        Assert.True(File.Exists(path), $"{ignoreFileName} が見つかりません ({path})。");

        // 行ごとに読み、コメント(#)と空行を落としてから前後の空白を取り除く
        var entries = File.ReadAllLines(path)
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToArray();

        // .vercel/ の除外エントリが実在することを確かめる
        Assert.Contains(VercelLinkDirectoryEntry, entries);
    }
}
