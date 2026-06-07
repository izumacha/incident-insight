// 認可関連の型(Policies / Requirement / Handler)を使う
using IncidentInsight.Web.Authorization;
// DbContext / 監査インターセプタ / Seeder を使う
using IncidentInsight.Web.Data;
// ApplicationUser / AppRoles を使う
using IncidentInsight.Web.Models;
// AuditOptions(監査ログ用設定)を使う
using IncidentInsight.Web.Models.Auditing;
// 時刻源 / 再発サービスを使う
using IncidentInsight.Web.Services;
// IAuthorizationHandler インタフェース
using Microsoft.AspNetCore.Authorization;
// リバースプロキシの転送ヘッダ復元(ForwardedHeaders / ForwardedHeadersOptions)
using Microsoft.AspNetCore.HttpOverrides;
// ASP.NET Core Identity(認証・ユーザー管理)
using Microsoft.AspNetCore.Identity;
// EF Core(UseSqlite / UseSqlServer / UseNpgsql 等)
using Microsoft.EntityFrameworkCore;
// IPAddress(信頼するプロキシ IP の解析に使用)
using System.Net;

// WebApplication のビルダを作成(コマンドライン引数を受け取る)
var builder = WebApplication.CreateBuilder(args);

// Add services
// HttpContext を DI 経由で取れるようにする(監査ログ等で使用)
builder.Services.AddHttpContextAccessor();
// 時刻源を Singleton として登録(アプリ全体で 1 インスタンス)
builder.Services.AddSingleton<IClock, SystemClock>();
// 監査ログ設定(Audit セクション)を Options パターンで束縛。
// HashSalt は User Secrets / 環境変数で渡す(コミット禁止)
builder.Services.Configure<AuditOptions>(
    builder.Configuration.GetSection(AuditOptions.SectionName));

// 本番では HashSalt(監査ログの個人名ハッシュに使う秘密鍵)が空だと、
// 弱い決定的ハッシュになり PHI(患者・職員の氏名)の擬似匿名化が破れる(issue #61)。
// 誤って未設定のまま本番投入されるのを防ぐため、起動時に検査して空なら停止する(fail-fast)。
if (builder.Environment.IsProduction())
{
    // Audit:HashSalt の設定値を直接読み取る(環境変数 Audit__HashSalt / User Secrets 由来)
    var auditSalt = builder.Configuration[$"{AuditOptions.SectionName}:HashSalt"];
    // 値が無い・空白のみなら構成不備として例外を投げ、サーバ起動を中止する(fail-closed)
    if (string.IsNullOrWhiteSpace(auditSalt))
    {
        // 起動を止めて、空 salt のまま PHI ハッシュが弱くなる事故を未然に防ぐ
        throw new InvalidOperationException(
            "Audit:HashSalt is required in Production. Set it via the environment variable " +
            "Audit__HashSalt or User Secrets. An empty salt makes audit-log person-name " +
            "pseudonymization trivially reversible (issue #61).");
    }
}
// 監査インターセプタを Scoped で登録(DbContext と同じスコープ)
builder.Services.AddScoped<AuditSaveChangesInterceptor>();

// リバースプロキシ(ロードバランサ等)配下で動かす場合に、転送ヘッダ
// X-Forwarded-For / X-Forwarded-Proto を信頼してクライアント IP と
// スキーム(https 判定)を正しく復元する(issue #64)。
// 既定は無効で、設定 ForwardedHeaders:Enabled=true のときだけ有効化する。
// 全許可にすると X-Forwarded-* を偽装されるため、信頼するプロキシは
// 設定 ForwardedHeaders:KnownProxies(カンマ区切り IP)で明示的に与える。
var forwardedHeadersEnabled = builder.Configuration.GetValue<bool>("ForwardedHeaders:Enabled");
if (forwardedHeadersEnabled)
{
    // 転送ヘッダの取り扱いを設定する
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        // 復元するヘッダを限定する(For=クライアント IP / Proto=元のスキーム)
        options.ForwardedHeaders =
            ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        // 設定で渡された信頼プロキシ IP(カンマ区切り)を読み取る
        var knownProxies = builder.Configuration["ForwardedHeaders:KnownProxies"];
        // 値があれば 1 件ずつ解析して KnownProxies に登録する
        if (!string.IsNullOrWhiteSpace(knownProxies))
        {
            // カンマで分割し、空白除去しつつ各 IP を処理する
            foreach (var ip in knownProxies.Split(
                ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                // 正しい IP 形式のものだけ信頼プロキシとして追加する
                if (IPAddress.TryParse(ip, out var address))
                {
                    options.KnownProxies.Add(address);
                }
            }
        }
    });
}

// DbContext を DI 登録。Database:Provider 設定で SQLite / SQL Server / PostgreSQL を切り替える
builder.Services.AddDbContext<ApplicationDbContext>((sp, options) =>
{
    // 設定値を取得(既定は sqlite)。大文字小文字を吸収するため小文字化
    var provider = (builder.Configuration.GetValue<string>("Database:Provider") ?? "sqlite")
        .ToLowerInvariant();
    // DB 接続文字列を取得
    var conn = builder.Configuration.GetConnectionString("DefaultConnection");

    // プロバイダ名に応じて EF Core の対応メソッドを呼び分け
    switch (provider)
    {
        case "sqlserver":
            // SQL Server を使用
            options.UseSqlServer(conn);
            break;
        case "postgres":
        case "postgresql":
            // PostgreSQL(Npgsql)を使用
            options.UseNpgsql(conn);
            break;
        default:
            // 既定は単一ファイル DB の SQLite
            options.UseSqlite(conn);
            break;
    }

    // 監査インターセプタを DbContext にアタッチ(SaveChanges 前後でフックされる)
    options.AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>());
});

// ASP.NET Core Identity
// Identity を登録し、パスワードポリシーやロックアウトを開発/本番で切り替える
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        // 開発環境かどうか
        var isDevelopment = builder.Environment.IsDevelopment();

        // パスワードに数字を必須にする
        options.Password.RequireDigit = true;
        // パスワードの最小長(開発は 8 文字、本番は 12 文字)
        options.Password.RequiredLength = isDevelopment ? 8 : 12;
        // 本番のみ記号必須(開発は緩和)
        options.Password.RequireNonAlphanumeric = !isDevelopment;
        // 大文字必須
        options.Password.RequireUppercase = true;
        // 小文字必須
        options.Password.RequireLowercase = true;
        // 本番のみメール確認を必須化
        options.SignIn.RequireConfirmedAccount = !isDevelopment;
        // 連続 5 回失敗でロックアウト
        options.Lockout.MaxFailedAccessAttempts = 5;
        // ロックアウト時間(15 分)
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    // ユーザー情報の永続化に EF Core の ApplicationDbContext を使う
    .AddEntityFrameworkStores<ApplicationDbContext>()
    // パスワードリセット等のトークンプロバイダを追加
    .AddDefaultTokenProviders()
    // Claims に Department を注入するファクトリを差し替える
    .AddClaimsPrincipalFactory<ApplicationUserClaimsPrincipalFactory>();

// 認可ポリシー: 部署スコープ + ロールベース
builder.Services.AddAuthorization(options =>
{
    // 分析画面は管理者/リスクマネージャーのみ
    options.AddPolicy(Policies.CanViewAnalytics,
        p => p.RequireRole(AppRoles.Admin, AppRoles.RiskManager));
    // 監査ログ閲覧は管理者のみ(規制対応 + 最小権限の原則)
    options.AddPolicy(Policies.CanViewAuditLog,
        p => p.RequireRole(AppRoles.Admin));
    // 削除権限は管理者/リスクマネージャーのみ
    options.AddPolicy(Policies.CanDeleteIncident,
        p => p.RequireRole(AppRoles.Admin, AppRoles.RiskManager));
    // 編集権限は部署一致要件を満たすこと
    options.AddPolicy(Policies.CanEditIncident,
        p => p.AddRequirements(new SameDepartmentRequirement()));
    // 閲覧権限も部署一致要件を満たすこと
    options.AddPolicy(Policies.CanViewIncident,
        p => p.AddRequirements(new SameDepartmentRequirement()));
});
// 部署一致要件の判定ハンドラを DI に登録
builder.Services.AddScoped<IAuthorizationHandler, SameDepartmentHandler>();
// 再発検出サービスを DI に登録
builder.Services.AddScoped<IRecurrenceService, RecurrenceService>();

// 認証クッキーの挙動を設定
builder.Services.ConfigureApplicationCookie(options =>
{
    // 未認証時のログイン画面パス
    options.LoginPath = "/Account/Login";
    // 権限不足時の画面パス
    options.AccessDeniedPath = "/Account/AccessDenied";
    // アクセスのたびに有効期限を伸ばすスライディング方式
    options.SlidingExpiration = true;
    // セッション有効時間(8 時間)
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    // JS からアクセスできないようにする(XSS 対策)
    options.Cookie.HttpOnly = true;
    // クロスサイト送信を禁止(CSRF 対策)
    options.Cookie.SameSite = SameSiteMode.Strict;
    // 開発は HTTP でも OK、本番は HTTPS 必須
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
});

// CSRF 対策トークン用クッキーの設定
builder.Services.AddAntiforgery(options =>
{
    // JS からアクセス不可
    options.Cookie.HttpOnly = true;
    // クロスサイト送信不可
    options.Cookie.SameSite = SameSiteMode.Strict;
    // 本番は HTTPS 必須
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
});

// HSTS(HTTPS の強制)の設定
builder.Services.AddHsts(options =>
{
    // ブラウザ プリロードリストへの登録可
    options.Preload = true;
    // サブドメインも HTTPS 必須
    options.IncludeSubDomains = true;
    // 有効期間 1 年
    options.MaxAge = TimeSpan.FromDays(365);
});

// MVC のコントローラ+ビューを有効化
builder.Services.AddControllersWithViews();

// /health は認証不要で DB 接続確認を行う。コンテナ/ロードバランサの liveness/readiness 用。
builder.Services.AddHealthChecks()
    .AddDbContextCheck<ApplicationDbContext>("database");

// ここまでで DI 登録完了。アプリケーションを構築する
var app = builder.Build();

// 転送ヘッダの復元は、HSTS / HTTPS リダイレクト / 認証より「前」に行う必要がある
// (これらが正しいスキーム・クライアント IP を見るため)。有効時のみ挿入する(issue #64)。
if (forwardedHeadersEnabled)
{
    // X-Forwarded-* を読み取り、Request.Scheme / RemoteIpAddress を復元する
    app.UseForwardedHeaders();
    // 信頼プロキシ(KnownProxies)を 1 件も設定せずに有効化すると、直接接続してきた
    // クライアントが X-Forwarded-For を偽装できる(またはプロキシ配下でも転送ヘッダが
    // 信頼されない)設定ミスになる。値を発明できないため起動は止めず、AllowedHosts と
    // 同様に運用者へ Warning で気づかせる(issue #64)。
    if (string.IsNullOrWhiteSpace(app.Configuration["ForwardedHeaders:KnownProxies"]))
    {
        // 信頼プロキシ未設定のまま転送ヘッダを有効化している旨を警告する
        app.Logger.LogWarning(
            "ForwardedHeaders:Enabled=true but ForwardedHeaders:KnownProxies is empty. " +
            "X-Forwarded-For/Proto could be spoofed by a direct client (or will not be trusted " +
            "from your reverse proxy). Set ForwardedHeaders:KnownProxies to the trusted proxy " +
            "IP(s) (comma-separated) (issue #64).");
    }
}

// Configure pipeline
// 本番のみグローバルエラーハンドラ + HTTPS 強制を有効化
if (!app.Environment.IsDevelopment())
{
    // 例外発生時に /Home/Error へ遷移
    app.UseExceptionHandler("/Home/Error");
    // HSTS ヘッダを付与
    app.UseHsts();
    // HTTP → HTTPS リダイレクト
    app.UseHttpsRedirection();

    // 本番で AllowedHosts が "*"(全ホスト許可)のままだと、Host ヘッダ偽装
    // (キャッシュ汚染・パスワード再設定リンク汚染等)の余地が残る(issue #64)。
    // 値を発明できないため起動は止めず、運用者に実ホスト名へ絞るよう警告する。
    var allowedHosts = app.Configuration["AllowedHosts"];
    // 未設定・空・ワイルドカードのいずれかなら警告ログを出す
    if (string.IsNullOrWhiteSpace(allowedHosts) || allowedHosts.Trim() == "*")
    {
        // 運用者が気づけるよう Warning レベルで通知する
        app.Logger.LogWarning(
            "AllowedHosts is '*' in Production. Set it to the real hostname(s) via the " +
            "AllowedHosts setting or environment variable (semicolon-separated) to prevent " +
            "Host-header spoofing, especially behind a reverse proxy (issue #64).");
    }
}

// 静的ファイル(wwwroot)配信を有効化
app.UseStaticFiles();
// ルーティング機能を有効化
app.UseRouting();
// 認証(クッキーから ClaimsPrincipal を構築)を有効化
app.UseAuthentication();
// 認可(Policy / ロール評価)を有効化
app.UseAuthorization();

// 既定ルート(/Home/Index)をマップ
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// ヘルスチェック用エンドポイントを /health にマップ
app.MapHealthChecks("/health");

// Initialize DB, seed roles + admin, then seed data
// 起動時にマイグレーション適用 + 初期データ投入を行う
using (var scope = app.Services.CreateScope())
{
    // DbContext を取得
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try
    {
        // マイグレーションを適用(DB 作成 + スキーマ更新)
        db.Database.Migrate();
    }
    catch (Exception ex) when (!string.Equals(
        db.Database.ProviderName,
        "Microsoft.EntityFrameworkCore.Sqlite",
        StringComparison.Ordinal))
    {
        // 同梱されているマイグレーションは SQLite 用のみ。
        // SQL Server / PostgreSQL に切り替える場合は、対象プロバイダで
        // マイグレーションを再生成する必要がある(CLAUDE.md 参照)。
        // SQLite 以外で失敗した場合は、開発者に手順を示すエラーへ変換して再スロー
        throw new InvalidOperationException(
            $"Database migration failed for provider '{db.Database.ProviderName}'. " +
            "The committed migrations target SQLite only. When switching to SQL Server or PostgreSQL, " +
            "regenerate migrations against that provider: delete src/IncidentInsight.Web/Migrations/, " +
            "set Database__Provider and ConnectionStrings__DefaultConnection to the target, " +
            "then run `dotnet ef migrations add InitialCreate --project src/IncidentInsight.Web`. " +
            "See CLAUDE.md for details.",
            ex);
    }
    // 原因カテゴリ + サンプルインシデントを投入(冪等)
    DbSeeder.Seed(db, scope.ServiceProvider.GetRequiredService<IClock>());

    // ロール管理用マネージャーを取得
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    // ユーザー管理用マネージャーを取得
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    // シーダー専用のロガーを作成
    var seederLogger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
        .CreateLogger("IdentitySeeder");
    // ロール・開発用デモアカウントを投入(Development + SeedAccounts 設定がある場合のみ)
    await IdentitySeeder.SeedAsync(roleManager, userManager, app.Configuration, seederLogger);
}

// アプリを起動(リクエスト待受開始)
app.Run();
