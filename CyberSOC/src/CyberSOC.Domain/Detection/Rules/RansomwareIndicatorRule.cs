// ── FileSystemEvent = 9 ───────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects ransomware staging and exfil preparation: a rapid burst of
    /// file-write or file-rename operations by one actor across many paths.
    /// 100 writes in 30 seconds is the canonical ransomware encryption rate
    /// threshold used by CrowdStrike and SentinelOne behavioural engines.
    /// </summary>
    public sealed class RansomwareIndicatorRule : SlidingWindowRule
    {
        private static readonly HashSet<string> RansomExtensions = new(
            StringComparer.OrdinalIgnoreCase)
        {
            ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
            ".locky",  ".zzzzz",    ".zepto", ".cerber",  ".wallet"
        };

        public RansomwareIndicatorRule(int fileWriteThreshold = 100, TimeSpan? window = null)
            : base(fileWriteThreshold, window ?? TimeSpan.FromSeconds(30)) { }

        public override string RuleName => "RansomwareIndicator";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.FileSystemEvent
                        && e.Outcome == EventOutcome.Success);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var paths = burst.Select(e => e.TargetResource).Distinct().ToList();
            var hasRansomExt = paths.Any(p =>
                RansomExtensions.Contains(System.IO.Path.GetExtension(p)));

            return Alert.Raise(
                alertType: AlertType.RansomwareIndicator,
                severity: hasRansomExt ? Severity.Critical : Severity.High,
                title: $"Ransomware-like file-write burst by '{groupKey}'",
                reason: $"{burst.Count} file-system writes by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"across {paths.Count} path(s)." +
                                  (hasRansomExt ? " Known ransomware extension(s) detected." : ""),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}