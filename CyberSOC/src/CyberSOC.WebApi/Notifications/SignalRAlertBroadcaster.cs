using CyberSOC.Application.Common.Interfaces;
using CyberSOC.WebApi.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace CyberSOC.WebApi.Notifications
{
    public sealed class SignalRAlertBroadcaster : IAlertBroadcaster
    {
        private readonly IHubContext<AlertsHub> _hubContext;
        private const string ClientMethodName = "AlertRaised";

        public SignalRAlertBroadcaster(IHubContext<AlertsHub> hubContext)
        {
            _hubContext = hubContext;
        }

        public Task BroadcastAlertRaised(AlertNotification notification, CancellationToken cancellationToken)
        {
            return _hubContext.Clients.All.SendAsync(ClientMethodName, notification, cancellationToken);
        }
    }

}
