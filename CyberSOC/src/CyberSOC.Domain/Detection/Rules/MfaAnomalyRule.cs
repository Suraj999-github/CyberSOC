// ── MfaEvent = 7 ──────────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects MFA-bypass attempts: repeated MFA failures or a sudden burst
    /// of MFA prompts pushed to a single user (prompt-bombing / MFA fatigue).
    /// A threshold of 3 failed MFA challenges in 2 minutes is the industry
    /// benchmark for prompt-bomb detection.
    /// </summary>
    public sealed class MfaAnomalyRule : SlidingWindowRule
    {
        public MfaAnomalyRule(int bypassThreshold = 3, TimeSpan? window = null)
            : base(bypassThreshold, window ?? TimeSpan.FromMinutes(2)) { }

        public override string RuleName => "MfaAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.MfaEvent
                        && e.Outcome == EventOutcome.Failure);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            return Alert.Raise(
                alertType: AlertType.MfaAnomaly,
                severity: burst.Count >= threshold * 3 ? Severity.Critical : Severity.High,
                title: $"MFA prompt-bomb / bypass attempt on account '{groupKey}'",
                reason: $"{burst.Count} failed MFA challenges for '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  "Pattern consistent with MFA fatigue or OTP interception.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}