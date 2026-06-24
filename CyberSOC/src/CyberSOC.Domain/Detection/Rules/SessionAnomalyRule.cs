using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── SessionEvent = 4 ──────────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects session hijacking / token-abuse patterns: multiple distinct
    /// sessions opened by the same userId from different IPs within a tight
    /// window, or a burst of token-refresh calls suggesting stolen OAuth tokens.
    /// Covers SSO abuse (enterprise), agent-portal session theft (remittance),
    /// and online-banking session fixation (banking).
    /// </summary>
    public sealed class SessionAnomalyRule : SlidingWindowRule
    {
        public SessionAnomalyRule(int threshold = 5, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "SessionAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.SessionEvent);

        // Group by userId — distributed IPs on the same account is the signal.
        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var distinctIps = burst.Select(e => e.Actor.IpAddress).Distinct().ToList();
            var isMultiIp = distinctIps.Count > 1;

            return Alert.Raise(
                alertType: AlertType.SessionHijack,
                severity: isMultiIp ? Severity.High : Severity.Medium,
                title: $"Session anomaly detected for '{groupKey}'",
                reason: $"{burst.Count} session events for '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"across {distinctIps.Count} IP(s): {string.Join(", ", distinctIps)}. " +
                                  (isMultiIp ? "Concurrent sessions from multiple IPs suggest token theft or hijack." : ""),
                sourceIp: distinctIps.First(),
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}
