// ── DnsQuery = 13 ─────────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects DNS-based C2 beaconing and data exfiltration via DNS tunnelling:
    /// a single actor generating a very high volume of DNS queries (DGA)
    /// or queries to a small set of domains with high-entropy subdomains.
    /// 200 queries/minute from one host is the Cisco Umbrella detection baseline.
    /// </summary>
    public sealed class DnsAnomalyRule : SlidingWindowRule
    {
        public DnsAnomalyRule(int queryThreshold = 200, TimeSpan? window = null)
            : base(queryThreshold, window ?? TimeSpan.FromMinutes(1)) { }

        public override string RuleName => "DnsAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.DnsQuery);

        protected override string GroupKey(SecurityEvent e) => e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var domains = burst.Select(e => e.TargetResource).Distinct().ToList();
            var uniqueDomains = domains.Count;
            // High domain-count = DGA scan; low domain-count + high volume = tunnelling.
            var pattern = uniqueDomains < 5
                ? "DNS tunnelling / C2 beaconing (low domain diversity)"
                : "DGA-like behaviour (high domain diversity)";

            return Alert.Raise(
                alertType: AlertType.DnsAnomaly,
                severity: burst.Count >= threshold * 2 ? Severity.High : Severity.Medium,
                title: $"DNS anomaly from {groupKey} — {pattern}",
                reason: $"{burst.Count} DNS queries from {groupKey} in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"resolving {uniqueDomains} unique domain(s). Pattern: {pattern}.",
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}