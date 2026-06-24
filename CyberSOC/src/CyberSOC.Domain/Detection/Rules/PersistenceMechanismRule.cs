// ── RegistryEvent = 10  +  ServiceEvent = 12 ─────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects persistence-mechanism installation: a burst of registry writes
    /// to run-keys / boot keys (T1547) OR rapid service installs (T1543),
    /// both classic post-exploitation persistence vectors.
    /// A single rule handles both EventTypes because the detection logic and
    /// alert type are identical — only the filter differs.
    /// </summary>
    public sealed class PersistenceMechanismRule : SlidingWindowRule
    {
        private static readonly HashSet<string> PersistenceKeywords = new(
            StringComparer.OrdinalIgnoreCase)
        {
            // Registry run keys
            "CurrentVersion\\Run", "CurrentVersion\\RunOnce",
            "Winlogon",            "AppInit_DLLs",
            "Image File Execution Options",
            // Service / driver paths
            "SYSTEM\\CurrentControlSet\\Services"
        };

        public PersistenceMechanismRule(int threshold = 2, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "PersistenceMechanism";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e =>
                (e.EventType == SecurityEventType.RegistryEvent ||
                 e.EventType == SecurityEventType.ServiceEvent ||
                 e.EventType == SecurityEventType.DriverLoad)
                && e.Outcome == EventOutcome.Success);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var targets = burst.Select(e => e.TargetResource).Distinct().ToList();
            var known = targets.Where(t =>
                PersistenceKeywords.Any(k =>
                    t.Contains(k, StringComparison.OrdinalIgnoreCase))).ToList();

            return Alert.Raise(
                alertType: AlertType.PersistenceMechanism,
                severity: known.Count > 0 ? Severity.Critical : Severity.High,
                title: $"Persistence mechanism installed by '{groupKey}'",
                reason: $"{burst.Count} registry/service/driver events by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (known.Count > 0
                                      ? $"Known persistence location(s): {string.Join(", ", known)}."
                                      : $"Target(s): {string.Join(", ", targets)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}