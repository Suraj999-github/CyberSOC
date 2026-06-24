namespace CyberSOC.Application.Common.Interfaces
{
    /// <summary>
    /// Defined in Application, implemented in WebApi using SignalR. Application
    /// never references SignalR/ASP.NET Core types directly — it just knows it
    /// can broadcast an alert notification to whoever is listening (the dashboard).
    /// </summary>
    public interface IAlertBroadcaster
    {
        Task BroadcastAlertRaised(AlertNotification notification, CancellationToken cancellationToken);
    }

    /// <summary>Lightweight DTO sent over the wire — deliberately not the full Alert entity.</summary>
    public sealed record AlertNotification(
        Guid AlertId,
        string AlertType,
        string Severity,
        string Title,
        string Reason,
        string SourceIp,
        DateTimeOffset RaisedAt);
}
