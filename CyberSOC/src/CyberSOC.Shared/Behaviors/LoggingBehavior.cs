using CyberSOC.Shared.Cqrs;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace CyberSOC.Shared.Behaviors
{
    /// <summary>
    /// Logs request name, duration, and outcome for every Command/Query.
    /// Flags any handler over 1 second as a slow-request warning — useful once the
    /// Detection engine is processing real event volume.
    /// </summary>
    public sealed class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
        where TRequest : IRequest<TResponse>
    {
        private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;
        private const int SlowRequestThresholdMs = 1000;

        public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
        {
            _logger = logger;
        }

        public async Task<TResponse> Handle(
            TRequest request,
            Func<Task<TResponse>> next,
            CancellationToken cancellationToken)
        {
            var requestName = typeof(TRequest).Name;
            var stopwatch = Stopwatch.StartNew();

            _logger.LogInformation("Handling {RequestName}", requestName);

            try
            {
                var response = await next();
                stopwatch.Stop();

                if (stopwatch.ElapsedMilliseconds > SlowRequestThresholdMs)
                {
                    _logger.LogWarning(
                        "Slow request: {RequestName} took {ElapsedMs}ms",
                        requestName, stopwatch.ElapsedMilliseconds);
                }
                else
                {
                    _logger.LogInformation(
                        "Handled {RequestName} in {ElapsedMs}ms",
                        requestName, stopwatch.ElapsedMilliseconds);
                }

                return response;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex,
                    "{RequestName} failed after {ElapsedMs}ms",
                    requestName, stopwatch.ElapsedMilliseconds);
                throw;
            }
        }
    }

}
