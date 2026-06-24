using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── UC-05  TransactionEvent (new) ─────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects transaction velocity anomalies: too many payment events from
    /// one actor in a window. Catches structuring, round-tripping, account
    /// mules, and card-not-present fraud across remittance and banking.
    /// </summary>
    public sealed class TransactionVelocityRule : SlidingWindowRule
    {
        public TransactionVelocityRule(int txThreshold = 20, TimeSpan? window = null)
            : base(txThreshold, window ?? TimeSpan.FromMinutes(15)) { }

        public override string RuleName => "TransactionVelocity";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.TransactionEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var channels = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.TransactionAnomaly,
                severity: burst.Count >= threshold * 2 ? Severity.Critical : Severity.High,
                title: $"Transaction velocity breach for actor '{groupKey}'",
                reason: $"{burst.Count} transactions by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"across channel(s): {string.Join(", ", channels)}. " +
                                  "Possible structuring, mule activity, or CNP fraud.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}
