// ── EmailEvent = 18 ───────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects Business Email Compromise (BEC) and bulk-phishing patterns:
    /// a user auto-forwarding mail to external addresses, or sending a burst
    /// of outbound messages to many distinct recipients (spray campaign).
    /// The 3-forward-in-5-minute rule is the Microsoft 365 Defender default.
    /// </summary>
    public sealed class EmailPhishingRule : SlidingWindowRule
    {
        public EmailPhishingRule(int forwardThreshold = 3, TimeSpan? window = null)
            : base(forwardThreshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "EmailPhishing";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.EmailEvent
                        && e.Outcome == EventOutcome.Success);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var recipients = burst.Select(e => e.TargetResource).Distinct().ToList();
            var externalCount = recipients.Count(r =>
                !r.Contains("@internal", StringComparison.OrdinalIgnoreCase));

            return Alert.Raise(
                alertType: AlertType.PhishingOrBec,
                severity: externalCount > 0 ? Severity.High : Severity.Medium,
                title: $"Suspicious email activity by '{groupKey}'",
                reason: $"{burst.Count} email events by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"to {recipients.Count} recipient(s) " +
                                  (externalCount > 0
                                      ? $"— {externalCount} external address(es) detected. Possible BEC/forward rule."
                                      : "."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}