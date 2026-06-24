using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Infrastructure;
using CyberSOC.Persistence;
using CyberSOC.Shared.Behaviors;
using CyberSOC.Shared.Cqrs;
using CyberSOC.WebApi.Endpoints;
using CyberSOC.WebApi.Hubs;
using CyberSOC.WebApi.Notifications;
using FluentValidation;
using Serilog;
using System.Reflection;

var builder = WebApplication.CreateBuilder(args);

// --- Serilog (free, structured logging) ---
builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console());

// --- Application layer wiring: Dispatcher + handlers + pipeline behaviors ---
var applicationAssembly = Assembly.Load("CyberSOC.Application");
builder.Services.AddCyberSocDispatcher(applicationAssembly);
builder.Services.AddValidatorsFromAssembly(applicationAssembly);

// Behavior order = execution order: Logging wraps Validation wraps the handler.
builder.Services.AddCyberSocPipelineBehavior(typeof(LoggingBehavior<,>));
builder.Services.AddCyberSocPipelineBehavior(typeof(ValidationBehavior<,>));

// --- Infrastructure & Persistence ---
// --- Infrastructure & Persistence ---
builder.Services.AddCyberSocInfrastructure(builder.Configuration);
builder.Services.AddCyberSocPersistence(builder.Configuration);
// --- Real-time push to the dashboard (free, built into ASP.NET Core) ---
builder.Services.AddSignalR();
builder.Services.AddScoped<IAlertBroadcaster, SignalRAlertBroadcaster>();
// Dashboard runs on a different origin during local dev (e.g. React on :3000);
// SignalR needs credentials allowed explicitly rather than a wildcard origin.
var dashboardOrigins = builder.Configuration.GetSection("Cors:DashboardOrigins").Get<string[]>()
    ?? new[] { "https://localhost:7297" };
builder.Services.AddCors(options =>
{
    options.AddPolicy("Dashboard", policy => policy
        .WithOrigins(dashboardOrigins)
        .AllowAnyHeader()
        .AllowAnyMethod()
        .AllowCredentials());
});

// --- API plumbing ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "CyberSOC Command Center API",
        Version = "v1",
        Description = "Ingestion, Detection, and Alerting API for the Cybersecurity Command Center."
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSerilogRequestLogging();
app.UseCors("Dashboard");
app.MapIngestionEndpoints();
app.MapThreatIntelEndpoints();
app.MapAlertsEndpoints();
app.MapHub<AlertsHub>("/hubs/alerts");
app.Run();

// Needed so WebApplicationFactory<Program> works in integration tests.
public partial class Program { }
