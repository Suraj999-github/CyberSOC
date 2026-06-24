using Microsoft.AspNetCore.SignalR;

namespace CyberSOC.WebApi.Hubs
{
    /// <summary>
    /// Dashboard clients connect to this hub (path: /hubs/alerts) and listen for
    /// the "AlertRaised" server-to-client method. No client-to-server methods are
    /// needed yet — this hub is push-only for v1. Authorization will be added once
    /// the IdentityAccess module (RBAC) lands, so only authenticated SOC roles can
    /// subscribe.
    /// </summary>
    public sealed class AlertsHub : Hub
    {
        public override Task OnConnectedAsync()
        {
            // Placeholder for group-based subscriptions later (e.g. per business
            // unit, for the Risk Heatmap module) — for now everyone is in the
            // implicit "all connections" broadcast group.
            return base.OnConnectedAsync();
        }
    }

}
