using CyberSOC.Application.ThreatIntel.UpsertIndicator;
using CyberSOC.Domain.ThreatIntel;
using CyberSOC.Shared.Cqrs;

namespace CyberSOC.WebApi.Endpoints
{
    public static class ThreatIntelEndpoints
    {
        public static IEndpointRouteBuilder MapThreatIntelEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/threat-intel/indicators").WithTags("ThreatIntel");

            group.MapPost("/", async (UpsertIndicatorRequest request, IDispatcher dispatcher, CancellationToken ct) =>
            {
                var command = new UpsertIndicatorCommand(
                    Type: request.Type,
                    Value: request.Value,
                    Source: request.Source,
                    Confidence: request.Confidence,
                    Tags: request.Tags);

                var result = await dispatcher.Send(command, ct);

                return result.IsSuccess
                    ? Results.Ok(new { indicatorId = result.Value })
                    : Results.BadRequest(new { errors = result.Errors });
            })
            .WithName("UpsertIndicator")
            .WithSummary("Add or refresh a threat indicator (IOC). This is the same operation a " +
                         "scheduled free-feed sync job (AbuseIPDB/OTX/abuse.ch) calls per indicator.")
            .Produces(200)
            .Produces(400);

            return app;
        }
    }

    public sealed record UpsertIndicatorRequest(
        IndicatorType Type,
        string Value,
        string Source,
        int Confidence,
        string? Tags);
}
