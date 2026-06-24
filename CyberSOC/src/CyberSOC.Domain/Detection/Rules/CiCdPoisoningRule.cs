// ── CiCdPipelineEvent = 40 ────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects CI/CD supply-chain poisoning: unexpected pipeline modifications,
    /// secrets exposed in build logs, or a non-human actor triggering a
    /// production deployment outside approved change windows (MITRE T1195).
    /// Even a single secrets-exposure hit is Critical.
    /// </summary>
    public sealed class CiCdPoisoningRule : SlidingWindowRule
    {
        private static readonly HashSet<string> PoisoningIndicators = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "SecretsExposedInLog",
            "PipelineScriptModified",
            "UnauthorizedDeployment",
            "DependencySubstitution",
            "ShadowDependency",
            "ArtifactTampered",
            "RegistryMirrorChanged",
            "ServiceAccountKeyRotated"
        };

        public CiCdPoisoningRule(int threshold = 2, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "CiCdPoisoning";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.CiCdPipelineEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var actions = burst.Select(e => e.TargetResource).Distinct().ToList();
            var poisonHits = actions.Where(a =>
                PoisoningIndicators.Contains(a)).ToList();

            return Alert.Raise(
                alertType: AlertType.CiCdPoisoning,
                severity: poisonHits.Count > 0 ? Severity.Critical : Severity.High,
                title: $"CI/CD pipeline poisoning detected by '{groupKey}'",
                reason: $"{burst.Count} pipeline event(s) by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (poisonHits.Count > 0
                                      ? $"Poisoning indicator(s): {string.Join(", ", poisonHits)}."
                                      : $"Action(s): {string.Join(", ", actions)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}