using CyberSOC.Persistence;
using Microsoft.EntityFrameworkCore;

namespace CyberSOC.WebApi.Endpoints
{
    public static class AlertsEndpoints
    {
        public static IEndpointRouteBuilder MapAlertsEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/alerts").WithTags("Alerts");

            group.MapGet("/", async (CyberSocDbContext db, string? sourceIp, int take) =>
            {
                var query = db.Alerts.AsNoTracking().OrderByDescending(a => a.RaisedAt);

                var filtered = string.IsNullOrWhiteSpace(sourceIp)
                    ? query
                    : query.Where(a => a.SourceIp == sourceIp);

                var results = await filtered
                    .Take(take <= 0 ? 50 : take)
                    .Select(a => new
                    {
                        a.Id,
                        a.AlertType,
                        a.Severity,
                        a.Status,
                        a.Title,
                        a.Reason,
                        a.SourceIp,
                        a.RaisedAt
                    })
                    .ToListAsync();

                return Results.Ok(results);
            })
            .WithName("GetAlerts")
            .WithSummary("List recent alerts, optionally filtered by source IP — useful for verifying detection without SSMS.")
            .Produces(200);

            return app;
        }
    }

}
