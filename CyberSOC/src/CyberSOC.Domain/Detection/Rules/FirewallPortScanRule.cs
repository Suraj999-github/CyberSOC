using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── UC-03  FirewallLog ────────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects rapid port scanning or C2 beaconing: many DENY hits from one
    /// source IP in a tight window. Critical for banking core-network perimeter
    /// and remittance settlement corridors.
    /// </summary>
    public sealed class FirewallPortScanRule : SlidingWindowRule
    {
        public FirewallPortScanRule(int denyThreshold = 15, TimeSpan? window = null)
            : base(denyThreshold, window ?? TimeSpan.FromMinutes(2)) { }

        public override string RuleName => "FirewallPortScan";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.FirewallLog
                        && e.Outcome == EventOutcome.Failure);   // Failure = DENY

        protected override string GroupKey(SecurityEvent e) => e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var targetPorts = burst.Select(e => e.TargetResource).Distinct().ToList();
            var isWideSpread = targetPorts.Count > threshold / 2;

            return Alert.Raise(
                alertType: AlertType.FirewallAnomaly,
                severity: isWideSpread ? Severity.High : Severity.Medium,
                title: $"Port scan / firewall sweep detected from {groupKey}",
                reason: $"{burst.Count} denied connections from {groupKey} across " +
                                  $"{targetPorts.Count} unique target(s) in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s.",
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}
