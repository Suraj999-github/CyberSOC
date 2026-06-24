// ── AccountChange = 6 ─────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects bulk account manipulation: rapid create/disable/delete/unlock
    /// operations by a single actor. Classic signal for an attacker planting
    /// shadow accounts or an insider disabling colleagues before exfiltration.
    /// </summary>
    public sealed class AccountManipulationRule : SlidingWindowRule
    {
        public AccountManipulationRule(int threshold = 5, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "AccountManipulation";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.AccountChange);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var targets = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.AccountManipulation,
                severity: burst.Count >= threshold * 2 ? Severity.Critical : Severity.High,
                title: $"Bulk account manipulation by '{groupKey}'",
                reason: $"{burst.Count} account-change operations by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"affecting account(s): {string.Join(", ", targets)}.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}