using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── PrivilegeChange = 5 ───────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects rapid privilege escalations by a single actor: sudo grants,
    /// IAM role assumptions, AD group membership changes. Any burst signals
    /// insider threat or a compromised admin account.
    /// Fires on both Success and Failure — success IS the threat for privilege abuse.
    /// </summary>
    public sealed class PrivilegeEscalationRule : SlidingWindowRule
    {
        public PrivilegeEscalationRule(int threshold = 3, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(10)) { }

        public override string RuleName => "PrivilegeEscalation";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.PrivilegeChange);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var resources = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.PrivilegeEscalation,
                severity: burst.Count >= threshold * 2 ? Severity.Critical : Severity.High,
                title: $"Privilege escalation burst by '{groupKey}'",
                reason: $"{burst.Count} privilege-change events by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"on resource(s): {string.Join(", ", resources)}.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}