// ── CertificateEvent = 34 ─────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects certificate anomalies: self-signed certs, expired TLS, rogue CA
    /// installation, or multiple cert-revocation events in a window. Covers
    /// MitM attack preparation and SSL inspection bypass attempts.
    /// Even a single rogue-CA install raises Critical immediately.
    /// </summary>
    public sealed class CertificateAnomalyRule : SlidingWindowRule
    {
        private static readonly HashSet<string> CriticalCertActions = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "RootCaInstalled", "SelfSignedDetected",
            "CertPinningBypassed", "WildcardMismatch",
            "RevocationCheckFailed", "UnknownIssuer"
        };

        public CertificateAnomalyRule(int threshold = 2, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromHours(1)) { }

        public override string RuleName => "CertificateAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.CertificateEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var actions = burst.Select(e => e.TargetResource).Distinct().ToList();
            var critHits = actions.Where(a =>
                CriticalCertActions.Contains(a)).ToList();

            return Alert.Raise(
                alertType: AlertType.CertificateAnomaly,
                severity: critHits.Count > 0 ? Severity.Critical : Severity.High,
                title: $"Certificate anomaly detected from {groupKey}",
                reason: $"{burst.Count} certificate event(s) from {groupKey} in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (critHits.Count > 0
                                      ? $"Critical indicator(s): {string.Join(", ", critHits)}."
                                      : $"Action(s): {string.Join(", ", actions)}."),
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}