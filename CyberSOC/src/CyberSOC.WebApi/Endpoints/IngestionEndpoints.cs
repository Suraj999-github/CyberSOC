using CyberSOC.Application.Ingestion.Commands.IngestSecurityEvent;
using CyberSOC.Domain.Enums;
using CyberSOC.Shared.Cqrs;

namespace CyberSOC.WebApi.Endpoints
{
    public static class IngestionEndpoints
    {
        public static IEndpointRouteBuilder MapIngestionEndpoints(this IEndpointRouteBuilder app)
        {
            var group = app.MapGroup("/api/events").WithTags("Ingestion");

            group.MapPost("/", async (IngestEventRequest request, IDispatcher dispatcher, CancellationToken ct) =>
            {
                var command = new IngestSecurityEventCommand(
                    EventType: request.EventType,
                    Source: request.Source,
                    IpAddress: request.IpAddress,
                    UserId: request.UserId,
                    TargetResource: request.TargetResource,
                    Outcome: request.Outcome,
                    RawPayload: request.RawPayload ?? "{}",
                    Attributes: request.Attributes);

                var result = await dispatcher.Send(command, ct);

                return result.IsSuccess
                    ? Results.Created($"/api/events/{result.Value}", new { eventId = result.Value })
                    : Results.BadRequest(new { errors = result.Errors });
            })
            .WithName("IngestSecurityEvent")
            .WithSummary("Ingest a normalized security event (API call, login attempt, firewall log, etc.)")
            .Produces(201)
            .Produces(400);

            return app;
        }
    }

    /// <summary>Request DTO — kept separate from the Application Command so the wire
    /// contract can evolve independently of internal CQRS shapes.</summary>
    public sealed record IngestEventRequest(
        SecurityEventType EventType,
        string Source,
        string IpAddress,
        string? UserId,
        string TargetResource,
        EventOutcome Outcome,
        string? RawPayload,
        Dictionary<string, string>? Attributes);

}
