using CyberSOC.Web.Hubs;
using Serilog;
using Serilog.Events;

// ── Bootstrap Serilog as early as possible so startup errors are captured ──
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .Enrich.WithEnvironmentName()
    .Enrich.WithThreadId()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        path: "logs/cybersoc-dashboard-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] ({SourceContext}) {Message:lj}{NewLine}{Exception}")
    .CreateBootstrapLogger();   // replaced by full config after host build

try
{
    Log.Information("CyberSOC Dashboard starting up");

    var builder = WebApplication.CreateBuilder(args);

    // ── Replace bootstrap logger with full host-aware Serilog ──────────────
    builder.Host.UseSerilog((context, services, config) => config
        .ReadFrom.Configuration(context.Configuration)   // honours appsettings.json Serilog section
        .ReadFrom.Services(services)
        .Enrich.FromLogContext()
        .Enrich.WithEnvironmentName()
        .Enrich.WithThreadId()
        .WriteTo.Console(
            outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
        .WriteTo.File(
            path: "logs/cybersoc-dashboard-.log",
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 14,
            outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] ({SourceContext}) {Message:lj}{NewLine}{Exception}"));

    builder.Services.AddControllersWithViews();
    builder.Services.AddSignalR();

    var app = builder.Build();

    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Home/Error");
        app.UseHsts();
    }

    // ── Serilog HTTP request logging (replaces default IIS/Kestrel access log) ──
    app.UseSerilogRequestLogging(options =>
    {
        options.MessageTemplate =
            "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
        // Downgrade health-check and static-file noise to Verbose
        options.GetLevel = (httpContext, elapsed, ex) =>
            httpContext.Request.Path.StartsWithSegments("/healthz") ||
            httpContext.Request.Path.StartsWithSegments("/favicon")
                ? LogEventLevel.Verbose
                : LogEventLevel.Information;
    });

    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    app.MapHub<AlertsHub>("/hubs/alerts");

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "CyberSOC Dashboard terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
