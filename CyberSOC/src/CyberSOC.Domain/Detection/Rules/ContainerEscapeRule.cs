// ── ContainerEvent = 39 ───────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects container escape and Kubernetes privilege-abuse: a burst of
    /// privileged container starts, host-path mounts, or namespace-breakout
    /// actions by a single actor. One confirmed escape attempt → Critical.
    /// TargetResource carries the K8s resource path or Docker event type.
    /// </summary>
    public sealed class ContainerEscapeRule : SlidingWindowRule
    {
        private static readonly HashSet<string> EscapeIndicators = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "privileged:true",
            "hostPID:true",
            "hostNetwork:true",
            "hostPath:/",
            "hostPath:/etc",
            "hostPath:/var/run/docker.sock",
            "capabilities:SYS_ADMIN",
            "capabilities:NET_ADMIN",
            "nsenter",
            "docker.sock"
        };

        public ContainerEscapeRule(int threshold = 1, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(1)) { }

        public override string RuleName => "ContainerEscape";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.ContainerEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var resources = burst.Select(e => e.TargetResource).Distinct().ToList();
            var escapeHits = resources.Where(r =>
                EscapeIndicators.Any(i =>
                    r.Contains(i, StringComparison.OrdinalIgnoreCase))).ToList();

            return Alert.Raise(
                alertType: AlertType.ContainerEscape,
                severity: escapeHits.Count > 0 ? Severity.Critical : Severity.High,
                title: $"Container escape / K8s privilege abuse by '{groupKey}'",
                reason: $"{burst.Count} container event(s) by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (escapeHits.Count > 0
                                      ? $"Escape indicator(s): {string.Join(", ", escapeHits)}."
                                      : $"Resource(s): {string.Join(", ", resources)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}