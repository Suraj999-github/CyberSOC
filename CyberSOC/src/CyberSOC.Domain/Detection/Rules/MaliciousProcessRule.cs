// ── ProcessCreation = 8 ───────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects process-spawn bursts indicative of script-based lateral movement
    /// or post-exploitation tooling (MITRE T1059). A single actor spawning many
    /// child processes rapidly — e.g. a compromised service account running
    /// PowerShell, cmd.exe, or Python — is the primary signal.
    /// TargetResource is expected to carry the spawned process name / path.
    /// </summary>
    public sealed class MaliciousProcessRule : SlidingWindowRule
    {
        private static readonly HashSet<string> HighRiskProcesses = new(
            StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
            "cscript.exe",   "mshta.exe", "regsvr32.exe", "rundll32.exe",
            "certutil.exe",  "bitsadmin.exe", "python.exe", "python3",
            "bash",          "sh",  "nc",  "ncat", "netcat"
        };

        public MaliciousProcessRule(int threshold = 10, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(1)) { }

        public override string RuleName => "MaliciousProcess";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.ProcessCreation);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var processes = burst.Select(e => e.TargetResource).Distinct().ToList();
            var riskyMatches = processes
                .Where(p => HighRiskProcesses.Contains(
                    System.IO.Path.GetFileName(p) ?? p))
                .ToList();

            var severity = riskyMatches.Count > 0
                ? (burst.Count >= threshold * 2 ? Severity.Critical : Severity.High)
                : Severity.Medium;

            return Alert.Raise(
                alertType: AlertType.MaliciousProcess,
                severity: severity,
                title: $"Suspicious process-spawn burst by '{groupKey}'",
                reason: $"{burst.Count} process-creation events by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (riskyMatches.Count > 0
                                      ? $"High-risk processes detected: {string.Join(", ", riskyMatches)}."
                                      : $"Processes: {string.Join(", ", processes)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}