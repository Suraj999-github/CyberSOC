using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Domain.Detection;
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.ValueObjects;
using CyberSOC.Shared.Common;
using CyberSOC.Shared.Cqrs;
using Microsoft.Extensions.Logging;

namespace CyberSOC.Application.Ingestion.Commands.IngestSecurityEvent
{
    /// <summary>
    /// Handles UC-01/UC-03 ingestion: normalizes the incoming payload into a
    /// SecurityEvent, persists it, then re-evaluates the active detection rules
    /// for that actor's recent activity window. Logging is intentionally verbose
    /// at each stage (event counts, rule outcomes, broadcast confirmation) so a
    /// "why didn't an alert fire" question can be answered from Serilog/Seq output
    /// instead of guesswork.
    /// </summary>
    public sealed class IngestSecurityEventCommandHandler
        : IRequestHandler<IngestSecurityEventCommand, Result<Guid>>
    {
        private readonly ISecurityEventRepository _eventRepository;
        private readonly IAlertRepository _alertRepository;
        private readonly IEnumerable<IDetectionRule> _detectionRules;
        private readonly IAlertBroadcaster _alertBroadcaster;
        private readonly IIndicatorRepository _indicatorRepository;
        private readonly ILogger<IngestSecurityEventCommandHandler> _logger;

        public IngestSecurityEventCommandHandler(
            ISecurityEventRepository eventRepository,
            IAlertRepository alertRepository,
            IEnumerable<IDetectionRule> detectionRules,
            IAlertBroadcaster alertBroadcaster,
            IIndicatorRepository indicatorRepository,
            ILogger<IngestSecurityEventCommandHandler> logger)
        {
            _eventRepository = eventRepository;
            _alertRepository = alertRepository;
            _detectionRules = detectionRules;
            _alertBroadcaster = alertBroadcaster;
            _indicatorRepository = indicatorRepository;
            _logger = logger;
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

            _logger.LogInformation(
                "Ingested SecurityEvent {EventId} EventType={EventType} Outcome={Outcome} Ip={Ip} Target={Target}",
                securityEvent.Id, request.EventType, request.Outcome, request.IpAddress, request.TargetResource);

            // Re-evaluate detection rules against this actor's recent window.
            var recentEvents = await _eventRepository.GetRecentByIpAsync(
                request.IpAddress, TimeSpan.FromMinutes(5), cancellationToken);

            _logger.LogInformation(
                "Loaded {Count} recent events for Ip={Ip} (lookback 5m) to evaluate {RuleCount} rule(s)",
                recentEvents.Count, request.IpAddress, _detectionRules.Count());

            var newlyRaisedAlerts = new List<Alert>();
            foreach (var rule in _detectionRules)
            {
                var newAlerts = rule.Evaluate(recentEvents);

                _logger.LogInformation(
                    "Rule {RuleName} evaluated {EventCount} events for Ip={Ip} -> {AlertCount} alert(s)",
                    rule.RuleName, recentEvents.Count, request.IpAddress, newAlerts.Count);

                foreach (var alert in newAlerts)
                {
                    // UC-02: check the source IP against known-bad indicators before
                    // persisting — enrichment happens once, at creation time, so the
                    // dashboard never shows an un-enriched alert that later "changes."
                    var matchedIndicator = await _indicatorRepository.FindByValueAsync(
                        Domain.ThreatIntel.IndicatorType.IpAddress, alert.SourceIp, cancellationToken);

                    if (matchedIndicator is not null)
                    {
                        alert.EnrichWithThreatIntelContext(
                            $"{matchedIndicator.Source} reports this IP with {matchedIndicator.Confidence}% confidence" +
                            (matchedIndicator.Tags is null ? "." : $" (tags: {matchedIndicator.Tags})."));
                    }

                    await _alertRepository.AddAsync(alert, cancellationToken);
                    newlyRaisedAlerts.Add(alert);
                }
            }

            await _alertRepository.SaveChangesAsync(cancellationToken);

            _logger.LogInformation(
                "Persisted {AlertCount} new alert(s) for Ip={Ip}; broadcasting now",
                newlyRaisedAlerts.Count, request.IpAddress);

            // Broadcast only after the alert is durably persisted — the dashboard
            // should never show an alert that a refresh wouldn't also find.
            foreach (var alert in newlyRaisedAlerts)
            {
                var notification = new AlertNotification(
                    AlertId: alert.Id,
                    AlertType: alert.AlertType.ToString(),
                    Severity: alert.Severity.ToString(),
                    Title: alert.Title,
                    Reason: alert.Reason,
                    SourceIp: alert.SourceIp,
                    RaisedAt: alert.RaisedAt);

                await _alertBroadcaster.BroadcastAlertRaised(notification, cancellationToken);

                _logger.LogInformation(
                    "Broadcasted AlertRaised for AlertId={AlertId} Type={AlertType} Severity={Severity}",
                    alert.Id, alert.AlertType, alert.Severity);
            }

            return Result.Success(securityEvent.Id);
        }
    }


}
