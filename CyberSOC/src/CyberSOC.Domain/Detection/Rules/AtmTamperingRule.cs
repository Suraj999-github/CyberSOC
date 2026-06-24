// ── AtmKioskEvent = 32 ────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects ATM/kiosk tampering: any burst of anomalous XFS (eXtensions for
    /// Financial Services) events from a single terminal — e.g. dispenser unit
    /// messages without a corresponding transaction, card-reader status changes
    /// outside business hours, or repeated CDM/CIM errors (jackpotting pattern).
    ///
    /// Even a single known jackpot-pattern event raises Critical immediately.
    /// TargetResource is expected to carry the XFS command / device class.
    /// </summary>
    public sealed class AtmTamperingRule : SlidingWindowRule
    {
        private static readonly HashSet<string> JackpotIndicators = new(
            StringComparer.OrdinalIgnoreCase)
        {
            // XFS WFS_CMD_CDM_DISPENSE outside transaction context
            "WFS_CMD_CDM_DISPENSE",
            "WFS_CMD_CDM_RESET",
            "WFS_CMD_PIN_IMPORT_KEY",
            // Generic indicators
            "DispenseWithoutTransaction",
            "HardDriveReplaced",
            "MaintenanceDoorOpen",
            "CardReaderTamper",
            "SkimmerDetected"
        };

        public AtmTamperingRule(int eventThreshold = 3, TimeSpan? window = null)
            : base(eventThreshold, window ?? TimeSpan.FromMinutes(1)) { }

        public override string RuleName => "AtmTampering";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.AtmKioskEvent);

        // Group by terminal ID (stored in IpAddress for ATMs) or userId for
        // operator-level events.
        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var commands = burst.Select(e => e.TargetResource).Distinct().ToList();
            var jackpotHits = commands.Where(c =>
                JackpotIndicators.Contains(c)).ToList();

            return Alert.Raise(
                alertType: AlertType.AtmTampering,
                severity: jackpotHits.Count > 0 ? Severity.Critical : Severity.High,
                title: $"ATM/kiosk tampering detected on terminal {groupKey}",
                reason: $"{burst.Count} anomalous XFS/kiosk event(s) on terminal {groupKey} in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (jackpotHits.Count > 0
                                      ? $"Known jackpotting indicator(s): {string.Join(", ", jackpotHits)}."
                                      : $"Command(s): {string.Join(", ", commands)}."),
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}