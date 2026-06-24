using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── UC-04  SystemAudit ────────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects abnormal audit-trail activity: rapid bursts of privileged
    /// config changes by one user. Covers SOX/PCI insider threat, AML rule
    /// bypass in remittance platforms, and ledger manipulation in banking.
    /// </summary>
    public sealed class AuditTamperingRule : SlidingWindowRule
    {
        public AuditTamperingRule(int changeThreshold = 8, TimeSpan? window = null)
            : base(changeThreshold, window ?? TimeSpan.FromMinutes(10)) { }

        public override string RuleName => "AuditTampering";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.SystemAudit);
        // Any outcome counts — success IS the threat for privilege abuse.

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var resources = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.AuditTampering,
                severity: burst.Count >= threshold * 2 ? Severity.Critical : Severity.High,
                title: $"Abnormal audit activity by '{groupKey}'",
                reason: $"{burst.Count} privileged system changes by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"across resource(s): {string.Join(", ", resources)}.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}