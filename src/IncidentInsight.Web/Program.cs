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
// ASP.NET Core Identity(認証・ユーザー管理)
using Microsoft.AspNetCore.Identity;
// EF Core(UseSqlite / UseSqlServer / UseNpgsql 等)
using Microsoft.EntityFrameworkCore;

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
// 監査インターセプタを Scoped で登録(DbContext と同じスコープ)
builder.Services.AddScoped<AuditSaveChangesInterceptor>();

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
