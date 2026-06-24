// ── DatabaseEvent = 26 ────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects database abuse: a burst of DDL/DML operations, stored-procedure
    /// mutations, or an abnormal read rate suggestive of SQLi tooling (sqlmap
    /// fires ~500 queries/minute). Covers core-banking ledger manipulation,
    /// AML-table tampering, and KYC data scraping.
    /// </summary>
    public sealed class DatabaseAnomalyRule : SlidingWindowRule
    {
        private static readonly HashSet<string> HighRiskStatements = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "DROP", "TRUNCATE", "ALTER", "CREATE USER",
            "GRANT",  "EXEC",   "EXECUTE", "xp_cmdshell",
            "INTO OUTFILE", "LOAD_FILE"
        };

        public DatabaseAnomalyRule(int queryThreshold = 500, TimeSpan? window = null)
            : base(queryThreshold, window ?? TimeSpan.FromMinutes(1)) { }

        public override string RuleName => "DatabaseAnomaly";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.DatabaseEvent);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var statements = burst.Select(e => e.TargetResource).Distinct().ToList();
            var riskyMatches = statements.Where(s =>
                HighRiskStatements.Any(r =>
                    s.Contains(r, StringComparison.OrdinalIgnoreCase))).ToList();

            return Alert.Raise(
                alertType: AlertType.DataExfiltration,
                severity: riskyMatches.Count > 0 ? Severity.Critical : Severity.High,
                title: $"Database anomaly detected for actor '{groupKey}'",
                reason: $"{burst.Count} database operations by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (riskyMatches.Count > 0
                                      ? $"High-risk statement(s): {string.Join(", ", riskyMatches)}."
                                      : "Volume exceeds normal query rate."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}