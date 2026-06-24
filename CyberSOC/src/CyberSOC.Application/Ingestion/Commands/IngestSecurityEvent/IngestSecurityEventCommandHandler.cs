using CyberSOC.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberSOC.Application.Ingestion.Commands.IngestSecurityEvent
{
    /// <summary>
    /// Handles UC-01/UC-03 ingestion: normalizes the incoming payload into a
    /// SecurityEvent, persists it, then re-evaluates the active detection rules
    /// for that actor's recent activity window. In Phase 2 this inline evaluation
    /// moves to a queue consumer (CyberSOC.Workers) for horizontal scale — the
    /// handler logic itself does not change, only what calls it.
    /// </summary>
    public sealed class IngestSecurityEventCommandHandler
        : IRequestHandler<IngestSecurityEventCommand, Result<Guid>>
    {
        private readonly ISecurityEventRepository _eventRepository;
        private readonly IAlertRepository _alertRepository;
        private readonly IEnumerable<IDetectionRule> _detectionRules;

        public IngestSecurityEventCommandHandler(
            ISecurityEventRepository eventRepository,
            IAlertRepository alertRepository,
            IEnumerable<IDetectionRule> detectionRules)
        {
            _eventRepository = eventRepository;
            _alertRepository = alertRepository;
            _detectionRules = detectionRules;
        }

        public async Task<Result<Guid>> Handle(IngestSecurityEventCommand request, CancellationToken cancellationToken)
        {
            var actor = new NetworkActor(request.IpAddress, request.UserId);

            var securityEvent = SecurityEvent.Create(
                eventType: request.EventType,
                source: request.Source,
                actor: actor,
                targetResource: request.TargetResource,
                outcome: request.Outcome,
                rawPayload: request.RawPayload,
                attributes: request.Attributes);

            await _eventRepository.AddAsync(securityEvent, cancellationToken);
            await _eventRepository.SaveChangesAsync(cancellationToken);

            // Re-evaluate detection rules against this actor's recent window.
            var recentEvents = await _eventRepository.GetRecentByIpAsync(
                request.IpAddress, TimeSpan.FromMinutes(5), cancellationToken);

            foreach (var rule in _detectionRules)
            {
                var newAlerts = rule.Evaluate(recentEvents);
                foreach (var alert in newAlerts)
                {
                    await _alertRepository.AddAsync(alert, cancellationToken);
                }
            }

            await _alertRepository.SaveChangesAsync(cancellationToken);

            return Result.Success(securityEvent.Id);
        }
    }

}
