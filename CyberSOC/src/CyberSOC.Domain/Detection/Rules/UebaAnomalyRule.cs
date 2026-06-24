// ── UserBehaviorAnomaly = 41  +  EntityBehaviorAnomaly = 42 ──────────────
using CyberSOC.Domain.Entities;
using CyberSOC.Domain.Enums;

namespace CyberSOC.Domain.Detection.Rules
{
    /// <summary>
    /// UEBA (User and Entity Behaviour Analytics) anomaly rule.
    ///
    /// This rule operates differently from every other rule in the system:
    /// it does NOT count raw events. Instead it expects that an upstream
    /// UEBA engine (e.g. Microsoft Sentinel UEBA, Elastic ML, or a custom
    /// anomaly scorer) has already computed a risk/deviation score and has
    /// ingested the result as a SecurityEvent whose RawPayload contains
    /// a JSON object with a "riskScore" field (0.0–100.0) and optional
    /// "riskFactors" array.
    ///
    ///   { "riskScore": 87.4, "riskFactors": ["off-hours","geo-leap","peer-deviation"] }
    ///
    /// This rule evaluates every UEBA event individually — no sliding window
    /// needed — and raises an alert when riskScore ≥ the configured sigma
    /// threshold (default 3 sigma → ~75 on a 0–100 normalised scale).
    ///
    /// Covers: impossible travel (already caught by VpnGeoAnomalyRule for raw
    /// VPN events, but UEBA may catch it on app-layer events too), off-hours
    /// access, peer-group deviation, non-human identity (NHI) abuse, and any
    /// pattern the ML model surfaces that a rule-based system would miss.
    /// </summary>
    public sealed class UebaAnomalyRule : IDetectionRule
    {
        public string RuleName => "UebaAnomaly";

        // 3.0 sigma → normalised threshold ≈ 75 on a 0–100 scale.
        // Configurable so ops can tighten (lower) or relax (higher) per env.
        private readonly double _deviationSigma;
        private readonly double _scoreThreshold;

        public UebaAnomalyRule(double deviationSigma = 3.0)
        {
            _deviationSigma = deviationSigma;
            // Linear mapping: 1σ = 25, 3σ = 75, 4σ = 100 (capped).
            _scoreThreshold = Math.Min(deviationSigma * 25.0, 100.0);
        }

        public IReadOnlyCollection<Alert> Evaluate(
            IReadOnlyCollection<SecurityEvent> candidateEvents)
        {
            var alerts = new List<Alert>();

            var uebaEvents = candidateEvents.Where(e =>
                e.EventType == SecurityEventType.UserBehaviorAnomaly ||
                e.EventType == SecurityEventType.EntityBehaviorAnomaly);

            foreach (var e in uebaEvents)
            {
                var (score, factors) = ParseUebaPayload(e.RawPayload);
                if (score < _scoreThreshold) continue;

                var isEntity = e.EventType == SecurityEventType.EntityBehaviorAnomaly;
                var actorLabel = isEntity
                    ? $"entity '{e.Actor.UserId ?? e.Actor.IpAddress}'"
                    : $"user '{e.Actor.UserId ?? e.Actor.IpAddress}'";

                alerts.Add(Alert.Raise(
                    alertType: AlertType.UebaAnomaly,
                    severity: ScoreToSeverity(score),
                    title: $"UEBA anomaly detected for {actorLabel}",
                    reason: $"Risk score {score:F1}/100 (threshold {_scoreThreshold:F1} " +
                                      $"at {_deviationSigma}σ) for {actorLabel}. " +
                                      (factors.Count > 0
                                          ? $"Contributing factor(s): {string.Join(", ", factors)}."
                                          : "No factor breakdown available."),
                    sourceIp: e.Actor.IpAddress,
                    evidenceEventIds: new[] { e.Id }));
            }

            return alerts;
        }

        // ── Helpers ───────────────────────────────────────────────────────

        private static (double Score, List<string> Factors) ParseUebaPayload(
            string? rawPayload)
        {
            if (string.IsNullOrWhiteSpace(rawPayload))
                return (0, new List<string>());

            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(rawPayload);
                var root = doc.RootElement;
                var score = root.TryGetProperty("riskScore", out var s)
                                      ? s.GetDouble() : 0.0;
                var factors = new List<string>();

                if (root.TryGetProperty("riskFactors", out var arr)
                    && arr.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var item in arr.EnumerateArray())
                        factors.Add(item.GetString() ?? "");
                }

                return (score, factors);
            }
            catch
            {
                return (0, new List<string>());
            }
        }

        private static Severity ScoreToSeverity(double score) => score switch
        {
            >= 95 => Severity.Critical,
            >= 80 => Severity.High,
            >= 60 => Severity.Medium,
            _ => Severity.Low
        };
    }
}