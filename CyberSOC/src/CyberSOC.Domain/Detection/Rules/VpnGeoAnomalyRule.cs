// ── VpnEvent = 16 ─────────────────────────────────────────────────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// Detects impossible-travel: a user authenticating via VPN from a location
    /// that is geographically impossible given their previous session's location
    /// and the elapsed time. Speed threshold of 900 km/h exceeds any commercial
    /// aircraft (≈ 800–850 km/h cruise) to eliminate false positives.
    ///
    /// Requires that SecurityEvent.Attributes contains:
    ///   "latitude"  (double, decimal degrees)
    ///   "longitude" (double, decimal degrees)
    ///
    /// This rule cannot use the sliding-window base because the detection is
    /// pair-wise (two events, not a count), so it overrides Evaluate directly.
    /// </summary>
    public sealed class VpnGeoAnomalyRule : IDetectionRule
    {
        public string RuleName => "VpnGeoAnomaly";

        private readonly double _maxSpeedKmh;

        public VpnGeoAnomalyRule(double maxSpeedKmh = 900)
        {
            _maxSpeedKmh = maxSpeedKmh;
        }

        public IReadOnlyCollection<Alert> Evaluate(
            IReadOnlyCollection<SecurityEvent> candidateEvents)
        {
            var alerts = new List<Alert>();

            var vpnEvents = candidateEvents
                .Where(e => e.EventType == SecurityEventType.VpnEvent
                         && e.Outcome == EventOutcome.Success
                         && HasGeo(e))
                .GroupBy(e => e.Actor.UserId ?? e.Actor.IpAddress)
                .ToList();

            foreach (var group in vpnEvents)
            {
                var ordered = group.OrderBy(e => e.Timestamp).ToList();

                for (var i = 1; i < ordered.Count; i++)
                {
                    var prev = ordered[i - 1];
                    var curr = ordered[i];

                    var distanceKm = HaversineKm(
                        GetLat(prev), GetLon(prev),
                        GetLat(curr), GetLon(curr));

                    var elapsedHours = (curr.Timestamp - prev.Timestamp).TotalHours;
                    if (elapsedHours <= 0) continue;

                    var impliedSpeedKmh = distanceKm / elapsedHours;
                    if (impliedSpeedKmh <= _maxSpeedKmh) continue;

                    alerts.Add(Alert.Raise(
                        alertType: AlertType.UebaAnomaly,
                        severity: Severity.High,
                        title: $"Impossible travel detected for '{group.Key}'",
                        reason: $"VPN login from location A at {prev.Timestamp:u} " +
                                          $"then location B at {curr.Timestamp:u} — " +
                                          $"{distanceKm:F0} km apart in {elapsedHours * 60:F0} min " +
                                          $"implies {impliedSpeedKmh:F0} km/h (threshold: {_maxSpeedKmh} km/h).",
                        sourceIp: curr.Actor.IpAddress,
                        evidenceEventIds: new[] { prev.Id, curr.Id }));
                }
            }

            return alerts;
        }

        // ── Geo helpers ───────────────────────────────────────────────────
        private static bool HasGeo(SecurityEvent e) =>
            e.Attributes is not null
            && e.Attributes.ContainsKey("latitude")
            && e.Attributes.ContainsKey("longitude");

        private static double GetLat(SecurityEvent e) =>
            Convert.ToDouble(e.Attributes!["latitude"]);

        private static double GetLon(SecurityEvent e) =>
            Convert.ToDouble(e.Attributes!["longitude"]);

        private static double HaversineKm(
            double lat1, double lon1, double lat2, double lon2)
        {
            const double R = 6371.0;
            var dLat = ToRad(lat2 - lat1);
            var dLon = ToRad(lon2 - lon1);
            var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2)
                     + Math.Cos(ToRad(lat1)) * Math.Cos(ToRad(lat2))
                     * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
            return R * 2 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1 - a));
        }

        private static double ToRad(double deg) => deg * Math.PI / 180.0;
    }
}