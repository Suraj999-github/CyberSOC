using CyberSOC.Web.Models;
using Microsoft.AspNetCore.SignalR;

namespace CyberSOC.Web.Hubs
{
    /// <summary>
    /// SignalR hub that receives alerts from backend services and fans them out
    /// to every connected SOC dashboard client in real-time.
    ///
    /// Usage (from a background service or controller):
    ///   await _hubContext.Clients.All.SendAsync("AlertRaised", notification);
    /// </summary>
    public class AlertsHub : Hub
    {
        /// <summary>
        /// Called by backend services to broadcast a new alert to all clients.
        /// The method name "AlertRaised" must match the client-side listener:
        ///   connection.on("AlertRaised", handler)
        /// </summary>
        public async Task BroadcastAlert(AlertNotification notification)
        {
            await Clients.All.SendAsync("AlertRaised", notification);
        }
    }

}
