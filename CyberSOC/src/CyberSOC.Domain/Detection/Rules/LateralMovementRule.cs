// ── NetworkConnection = 14 ────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects lateral movement: one internal actor connecting to an abnormally
    /// large number of distinct internal hosts in a short window. Separating
    /// this from FirewallLog ensures raw flow data (NetFlow/Zeek) is also covered.
    /// The 5-hop-in-5-minute threshold aligns with SANS lateral-movement baselines.
    /// </summary>
    public sealed class LateralMovementRule : SlidingWindowRule
    {
        public LateralMovementRule(int hopThreshold = 5, TimeSpan? window = null)
            : base(hopThreshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "LateralMovement";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.NetworkConnection);

        protected override string GroupKey(SecurityEvent e) => e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var destinations = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.LateralMovement,
                severity: destinations.Count >= threshold * 2 ? Severity.Critical : Severity.High,
                title: $"Lateral movement detected from {groupKey}",
                reason: $"{groupKey} made connections to {destinations.Count} distinct destination(s) in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s: " +
                                  $"{string.Join(", ", destinations)}.",
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}