using CyberSOC.Domain.Entities;

// CyberSOC.Domain.Detection.Rules — generic base
// All concrete rules inherit this; only the filter + alert wording differ.

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Reusable sliding-window counter. Subclasses provide:
    ///   • which events qualify  (FilterEvents)
    ///   • how to group them     (GroupKey)
    ///   • how to build an alert (BuildAlert)
    /// The burst-detection loop (skip-ahead after a hit) lives here once.
    /// </summary>
    public abstract class SlidingWindowRule : IDetectionRule
    {
        private readonly int _threshold;
        private readonly TimeSpan _window;

        protected SlidingWindowRule(int threshold, TimeSpan? window)
        {
            _threshold = threshold;
            _window = window ?? TimeSpan.FromMinutes(1);
        }

        public abstract string RuleName { get; }

        /// <summary>Pre-filter: only events relevant to this rule.</summary>
        protected abstract IEnumerable<SecurityEvent> FilterEvents(
            IReadOnlyCollection<SecurityEvent> all);

        /// <summary>Grouping key for the sliding window (IP, userId, …).</summary>
        protected abstract string GroupKey(SecurityEvent e);

        /// <summary>Build the alert once a threshold-breaching burst is found.</summary>
        protected abstract Alert BuildAlert(
            string groupKey,
            IReadOnlyList<SecurityEvent> burstEvents,
            int threshold);

        public IReadOnlyCollection<Alert> Evaluate(
            IReadOnlyCollection<SecurityEvent> candidateEvents)
        {
            var alerts = new List<Alert>();
            var filtered = FilterEvents(candidateEvents)
                           .GroupBy(GroupKey);

            foreach (var group in filtered)
            {
                var ordered = group.OrderBy(e => e.Timestamp).ToList();

                for (var i = 0; i < ordered.Count; i++)
                {
                    var windowStart = ordered[i].Timestamp;
                    var burst = ordered
                        .Skip(i)
                        .TakeWhile(e => e.Timestamp - windowStart <= _window)
                        .ToList();

                    if (burst.Count < _threshold) continue;

                    alerts.Add(BuildAlert(group.Key, burst, _threshold));
                    i += burst.Count - 1; // skip past this burst
                }
            }

            return alerts;
        }
    }
}