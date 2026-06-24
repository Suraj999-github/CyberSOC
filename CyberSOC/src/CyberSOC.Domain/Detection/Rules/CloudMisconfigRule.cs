// ── CloudApiCall = 20  +  CloudConfigChange = 21 ─────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects cloud misconfiguration attacks: rapid IAM policy changes,
    /// security-group opens, or public-bucket exposures by a single actor
    /// (AWS CloudTrail / Azure Activity / GCP Audit log source).
    /// A single public-exposure change scores Critical immediately.
    /// </summary>
    public sealed class CloudMisconfigRule : SlidingWindowRule
    {
        private static readonly HashSet<string> CriticalActions = new(
            StringComparer.OrdinalIgnoreCase)
        {
            // AWS
            "s3:PutBucketAcl", "ec2:AuthorizeSecurityGroupIngress",
            "iam:CreateAccessKey", "iam:AttachUserPolicy",
            // Azure
            "Microsoft.Storage/storageAccounts/write",
            "Microsoft.Network/networkSecurityGroups/securityRules/write",
            // GCP
            "storage.buckets.setIamPolicy", "compute.firewalls.insert"
        };

        public CloudMisconfigRule(int threshold = 3, TimeSpan? window = null)
            : base(threshold, window ?? TimeSpan.FromMinutes(10)) { }

        public override string RuleName => "CloudMisconfig";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e =>
                (e.EventType == SecurityEventType.CloudApiCall ||
                 e.EventType == SecurityEventType.CloudConfigChange)
                && e.Outcome == EventOutcome.Success);

        protected override string GroupKey(SecurityEvent e) =>
            e.Actor.UserId ?? e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var actions = burst.Select(e => e.TargetResource).Distinct().ToList();
            var critical = actions.Where(a =>
                CriticalActions.Contains(a)).ToList();

            return Alert.Raise(
                alertType: AlertType.CloudMisconfiguration,
                severity: critical.Count > 0 ? Severity.Critical : Severity.High,
                title: $"Cloud misconfiguration / IAM abuse by '{groupKey}'",
                reason: $"{burst.Count} cloud config-change event(s) by '{groupKey}' in " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s. " +
                                  (critical.Count > 0
                                      ? $"Critical action(s) detected: {string.Join(", ", critical)}."
                                      : $"Action(s): {string.Join(", ", actions)}."),
                sourceIp: burst.First().Actor.IpAddress,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}