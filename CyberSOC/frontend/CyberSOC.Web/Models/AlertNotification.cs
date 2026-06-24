namespace CyberSOC.Web.Models
{
    /// <summary>
    /// Mirrors the alert payload pushed by AlertsHub to all connected clients.
    /// Property names are camelCase so they serialise cleanly to the JS SignalR client.
    /// </summary>
    public class AlertNotification
    {
        public Guid AlertId { get; set; } = Guid.NewGuid();
        public string Severity { get; set; } = "Informational"; // Critical | High | Medium | Low | Informational
        public string AlertType { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public DateTime RaisedAt { get; set; } = DateTime.UtcNow;
    }

}
