using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;
// ── UC-06  DataAccessEvent (new) ──────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects bulk-data exfiltration patterns: abnormally many read/export
    /// events against sensitive resources by one user in a window.
    /// Maps to GDPR breach risk (enterprise), KYC-doc theft (remittance),
    /// and account-holder PII leakage (banking).
    /// </summary>
    public sealed class DataExfiltrationRule : SlidingWindowRule
    {
        public DataExfiltrationRule(int readThreshold = 50, TimeSpan? window = null)
            : base(readThreshold, window ?? TimeSpan.FromMinutes(10)) { }

        public override string RuleName => "DataExfiltration";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.DataAccessEvent
                        && e.Outcome == EventOutcome.Success); // successful reads are the signal

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var datasets = burst.Select(e => e.TargetResource).Distinct().ToList();
            return Alert.Raise(
                alertType: AlertType.DataExfiltration,
                severity: datasets.Count > 3 ? Severity.Critical : Severity.High,
                title: $"Possible data exfiltration by '{groupKey}'",
                reason: $"{burst.Count} successful data-access events by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"across {datasets.Count} resource(s): {string.Join(", ", datasets)}.",
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}