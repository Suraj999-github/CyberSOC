// ── IdentityProviderEvent = 23 ────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects IdP-level attacks: federation trust modifications, conditional-
    /// access policy weakening, persistent refresh-token grants, or SSO bypass
    /// attempts in Entra ID / Okta / Ping (MITRE T1556, T1550.001).
    /// Even a single federation-trust change warrants High severity.
    /// </summary>
    public sealed class IdentityProviderAnomalyRule : SlidingWindowRule
    {
        private static readonly HashSet<string> SensitiveIdpActions = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "Set federation settings on domain",
            "Update domain",
            "Add trusted CA",
            "Update conditional access policy",
            "Set DirSyncEnabled",
            "application.oauth2PermissionGrant.create"
        };

        public IdentityProviderAnomalyRule(int threshold = 5, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "IdentityProviderAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.IdentityProviderEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var actions = burst.Select(e => e.TargetResource).Distinct().ToList();
            var sensitiveHit = actions.Any(a =>
                SensitiveIdpActions.Any(s =>
                    a.Contains(s, StringComparison.OrdinalIgnoreCase)));

            return Alert.Raise(
                alertType: AlertType.AccountManipulation,
                severity: sensitiveHit ? Severity.Critical : Severity.High,
                title: $"Identity provider anomaly by '{groupKey}'",
                reason: $"{burst.Count} IdP event(s) by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (sensitiveHit
                                      ? $"Sensitive federation/CA/CAP action(s) detected: {string.Join(", ", actions)}."
                                      : $"Action(s): {string.Join(", ", actions)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}