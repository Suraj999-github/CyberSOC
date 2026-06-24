using CyberSOC.Infrastructure;
using CyberSOC.Persistence;
using CyberSOC.Shared.Behaviors;
using CyberSOC.Shared.Cqrs;
using CyberSOC.WebApi.Endpoints;
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
builder.Services.AddCyberSocInfrastructure();
builder.Services.AddCyberSocPersistence(builder.Configuration);

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

app.MapIngestionEndpoints();

app.Run();

// Needed so WebApplicationFactory<Program> works in integration tests.
public partial class Program { }
