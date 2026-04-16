using IncidentInsight.Web.Data;
using IncidentInsight.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditSaveChangesInterceptor>();

builder.Services.AddDbContext<ApplicationDbContext>((sp, options) =>
{
    var provider = (builder.Configuration.GetValue<string>("Database:Provider") ?? "sqlite")
        .ToLowerInvariant();
    var conn = builder.Configuration.GetConnectionString("DefaultConnection");

    switch (provider)
    {
        case "sqlserver":
            options.UseSqlServer(conn);
            break;
        case "postgres":
        case "postgresql":
            options.UseNpgsql(conn);
            break;
        default:
            options.UseSqlite(conn);
            break;
    }

    options.AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>());
});

// ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        var isDevelopment = builder.Environment.IsDevelopment();

        options.Password.RequireDigit = true;
        options.Password.RequiredLength = isDevelopment ? 8 : 12;
        options.Password.RequireNonAlphanumeric = !isDevelopment;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.SignIn.RequireConfirmedAccount = !isDevelopment;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
});

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
});

builder.Services.AddHsts(options =>
{
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Initialize DB, seed roles + admin, then seed data
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    try
    {
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
        throw new InvalidOperationException(
            $"Database migration failed for provider '{db.Database.ProviderName}'. " +
            "The committed migrations target SQLite only. When switching to SQL Server or PostgreSQL, " +
            "regenerate migrations against that provider: delete src/IncidentInsight.Web/Migrations/, " +
            "set Database__Provider and ConnectionStrings__DefaultConnection to the target, " +
            "then run `dotnet ef migrations add InitialCreate --project src/IncidentInsight.Web`. " +
            "See CLAUDE.md for details.",
            ex);
    }
    DbSeeder.Seed(db);

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var seederLogger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
        .CreateLogger("IdentitySeeder");
    await IdentitySeeder.SeedAsync(roleManager, userManager, app.Configuration, seederLogger);
}

app.Run();
