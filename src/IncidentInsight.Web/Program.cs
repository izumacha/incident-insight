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
});

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
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
    db.Database.Migrate();
    DbSeeder.Seed(db);

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var seederLogger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
        .CreateLogger("IdentitySeeder");
    await IdentitySeeder.SeedAsync(roleManager, userManager, app.Configuration, seederLogger);
}

app.Run();
