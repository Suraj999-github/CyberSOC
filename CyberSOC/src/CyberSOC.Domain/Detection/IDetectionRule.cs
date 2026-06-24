using CyberSOC.Domain.Entities;

namespace CyberSOC.Domain.Detection
{
    /// <summary>
    /// Contract every detection rule implements — API attack signatures, SIEM
    /// correlation rules, and (later) login anomaly scoring all plug into the same
    /// pipeline via this interface. Infrastructure wires up the registry; Domain
    /// only knows the shape.
    /// </summary>
    public interface IDetectionRule
    {
        /// <summary>Unique, stable name used in rule configuration and audit logs.</summary>
        string RuleName { get; }

        /// <summary>
        /// Evaluate a window of recent events for this rule's actor/scope and
        /// return zero or more Alerts. Implementations decide their own windowing
        /// (e.g. "last 5 minutes for this IP") — the caller just supplies candidates.
        /// </summary>
        IReadOnlyCollection<Alert> Evaluate(IReadOnlyCollection<SecurityEvent> candidateEvents);
    }

}
