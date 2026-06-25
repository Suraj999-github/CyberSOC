using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Infrastructure;
using CyberSOC.Persistence;
using CyberSOC.Persistence.Identity;
using CyberSOC.Shared.Behaviors;
using CyberSOC.Shared.Cqrs;
using CyberSOC.WebApi.Endpoints;
using CyberSOC.WebApi.Hubs;
using CyberSOC.WebApi.Identity;
using CyberSOC.WebApi.Notifications;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Reflection;
using System.Text;

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

// --- Identity (free, built into ASP.NET Core) + JWT bearer auth ---
builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        // Reasonable defaults for an internal SOC tool; tighten per your org's policy.
        options.Password.RequiredLength = 10;
        options.Password.RequireNonAlphanumeric = true;
        options.User.RequireUniqueEmail = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<CyberSocDbContext>()
    .AddSignInManager();

builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
var jwtSection = builder.Configuration.GetSection("Jwt");
var jwtSigningKey = jwtSection["SigningKey"]
    ?? throw new InvalidOperationException("Jwt:SigningKey is not configured.");
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSection["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwtSection["Audience"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSigningKey)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        // SignalR clients (browsers) can't set an Authorization header on the
        // WebSocket handshake — the JS client sends the token as a query
        // string param instead, so read it from there for hub requests only.
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                var accessToken = context.Request.Query["access_token"];
                var path = context.HttpContext.Request.Path;
                if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/hubs/alerts"))
                {
                    context.Token = accessToken;
                }
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

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

    // Lets you click "Authorize" in Swagger UI and paste a Bearer token.
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter: Bearer {your JWT}"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
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

app.UseAuthentication();
app.UseAuthorization();

await IdentitySeeder.SeedAsync(app.Services);

app.MapAuthEndpoints();
app.MapUserEndpoints();      // /api/users  — CRUD + activate/deactivate + roles
app.MapPasswordEndpoints();  // /api/password/change, /api/users/{id}/password/*
app.MapAccountEndpoints();   // /api/users/{id}/lockout/*, /api/me

app.MapIngestionEndpoints();
app.MapThreatIntelEndpoints();
app.MapAlertsEndpoints();
app.MapHub<AlertsHub>("/hubs/alerts");

app.Run();

// Needed so WebApplicationFactory<Program> works in integration tests.
public partial class Program { }
