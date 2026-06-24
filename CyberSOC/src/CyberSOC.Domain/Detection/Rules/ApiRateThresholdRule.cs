using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

//namespace CyberSOC.Domain.Detection.Rules
//{

//    /// <summary>
//    /// Detects API attack patterns by counting failed requests per source IP within
//    /// a sliding time window. This is the first concrete rule for UC-01 (API Attack
//    /// Monitoring) — e.g. catches credential-stuffing bursts and brute-force probing.
//    /// Pure domain logic: no DB, no HTTP — fully unit-testable in isolation.
//    /// </summary>
//    public sealed class ApiRateThresholdRule : IDetectionRule
//    {
//        public string RuleName => "ApiRateThreshold";

//        private readonly int _failureThreshold;
//        private readonly TimeSpan _window;

//        public ApiRateThresholdRule(int failureThreshold = 10, TimeSpan? window = null)
//        {
//            _failureThreshold = failureThreshold;
//            _window = window ?? TimeSpan.FromMinutes(1);
//        }

//        public IReadOnlyCollection<Alert> Evaluate(IReadOnlyCollection<SecurityEvent> candidateEvents)
//        {
//            var alerts = new List<Alert>();

//            var apiFailures = candidateEvents
//               // .Where(e => e.EventType == SecurityEventType.ApiRequest && e.Outcome == EventOutcome.Failure)
//                .GroupBy(e => e.Actor.IpAddress);

//            foreach (var group in apiFailures)
//            {
//                var orderedEvents = group.OrderBy(e => e.Timestamp).ToList();

//                for (var i = 0; i < orderedEvents.Count; i++)
//                {
//                    var windowStart = orderedEvents[i].Timestamp;
//                    var windowEvents = orderedEvents
//                        .Skip(i)
//                        .TakeWhile(e => e.Timestamp - windowStart <= _window)
//                        .ToList();

//                    //if (windowEvents.Count < _failureThreshold)
//                    //    continue;

//                    var sourceIp = group.Key;
//                    var endpoints = windowEvents.Select(e => e.TargetResource).Distinct().ToList();

//                    alerts.Add(Alert.Raise(
//                        alertType: AlertType.ApiAttack,
//                        severity: windowEvents.Count >= _failureThreshold * 2 ? Severity.High : Severity.Medium,
//                        title: $"Possible brute-force / credential stuffing from {sourceIp}",
//                        reason: $"{windowEvents.Count} failed API requests from {sourceIp} within " +
//                                 $"{_window.TotalSeconds}s targeting endpoint(s): {string.Join(", ", endpoints)}.",
//                        sourceIp: sourceIp,
//                        evidenceEventIds: windowEvents.Select(e => e.Id)));

//                    // Avoid raising duplicate overlapping alerts for the same burst.
//                    i += windowEvents.Count - 1;
//                }
//            }

//            return alerts;
//        }
//    }

//}
// ── UC-01  ApiRequest ──────────────────────────────────────────────────────
namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects brute-force / credential-stuffing bursts on API endpoints.
    /// Groups by source IP; counts failed requests within the sliding window.
    /// </summary>
    public sealed class ApiRateThresholdRule : SlidingWindowRule
    {
        public ApiRateThresholdRule(int failureThreshold = 10, TimeSpan? window = null)
            : base(failureThreshold, window) { }

        public override string RuleName => "ApiRateThreshold";

        protected override IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all) =>
            all.Where(e => e.EventType == SecurityEventType.ApiRequest
                        && e.Outcome == EventOutcome.Failure);

        protected override string GroupKey(SecurityEvent e) => e.Actor.IpAddress;

        protected override Alert BuildAlert(
            string groupKey, IReadOnlyList<SecurityEvent> burst, int threshold)
        {
            var endpoints = burst.Select(e => e.TargetResource).Distinct();
            return Alert.Raise(
                alertType: AlertType.ApiAttack,
                severity: burst.Count >= threshold * 2 ? Severity.High : Severity.Medium,
                title: $"Possible brute-force / credential stuffing from {groupKey}",
                reason: $"{burst.Count} failed API requests from {groupKey} within " +
                                  $"{(burst[^1].Timestamp - burst[0].Timestamp).TotalSeconds:F0}s " +
                                  $"targeting: {string.Join(", ", endpoints)}.",
                sourceIp: groupKey,
                evidenceEventIds: burst.Select(e => e.Id));
        }
    }
}