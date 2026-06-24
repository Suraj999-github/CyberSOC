using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

// ── UC-02  LoginAttempt ───────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects account-takeover attempts: repeated failed logins per userId
    /// within a window. Relevant to enterprise SSO, remittance agent portals,
    /// and online banking — all high-value ATO targets.
    /// </summary>
    public sealed class LoginBruteForceRule : SlidingWindowRule
    {
        public LoginBruteForceRule(int failureThreshold = 5, TimeSpan? window = null)
            : base(failureThreshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "LoginBruteForce";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.LoginAttempt
                        && e.Outcome == EventOutcome.Failure);

        // Group by userId so distributed IPs still trigger on the same account.
        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var distinctIps = burst.Select(e => e.Actor.IpAddress).Distinct().ToList();
            var isDistributed = distinctIps.Count > 1;

            return Alert.Raise(
                alertType: AlertType.LoginAnomaly,
                severity: isDistributed ? Severity.High : Severity.Medium,
                title: $"{(isDistributed ? "Distributed " : "")}login brute-force on account '{groupKey}'",
                reason: $"{burst.Count} failed logins for '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"from {distinctIps.Count} IP(s): {string.Join(", ", distinctIps)}.",
                sourceIp: distinctIps.First(),
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}
