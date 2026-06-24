// ── DlpEvent = 37 ─────────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects DLP policy violations: any event where sensitive data
    /// (PII, PAN, SWIFT message, IBAN) crosses a boundary enforced by a
    /// DLP engine. Even a single confirmed violation is High severity;
    /// a burst of violations in a window escalates to Critical.
    /// </summary>
    public sealed class DlpViolationRule : SlidingWindowRule
    {
        private static readonly HashSet<string> CriticalDataTypes = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "PAN", "CardNumber", "SSN", "NationalId",
            "SWIFT", "IBAN", "BankAccountNumber",
            "Passport", "DriversLicense", "MedicalRecord"
        };

        public DlpViolationRule(int threshold = 1, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(5)) { }

        public override string RuleName => "DlpViolation";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.DlpEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var dataTypes = burst.Select(e => e.TargetResource).Distinct().ToList();
            var critHits = dataTypes.Where(d =>
                CriticalDataTypes.Contains(d)).ToList();

            return Alert.Raise(
                alertType: AlertType.DlpViolation,
                severity: critHits.Count > 0 ? Severity.Critical : Severity.High,
                title: $"DLP violation by '{groupKey}'",
                reason: $"{burst.Count} DLP policy breach(es) by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (critHits.Count > 0
                                      ? $"Regulated data type(s) detected: {string.Join(", ", critHits)}."
                                      : $"Data classification(s): {string.Join(", ", dataTypes)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}