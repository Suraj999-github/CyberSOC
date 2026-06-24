using Microsoft.Extensions.DependencyInjection;

namespace CyberSOC.Shared.Cqrs
{
    public interface IDispatcher
    {
        Task<TResponse> Send<TResponse>(IRequest<TResponse> request, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Free, in-house replacement for MediatR's ISender/IMediator.
    /// Resolves the handler for a request, then wraps execution with every
    /// registered IPipelineBehavior&lt;TRequest,TResponse&gt; (validation, logging, etc.)
    /// in the order they were registered in DI.
    /// </summary>
    public sealed class Dispatcher : IDispatcher
    {
        private readonly IServiceProvider _serviceProvider;

        public Dispatcher(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task<TResponse> Send<TResponse>(
            IRequest<TResponse> request,
            CancellationToken cancellationToken = default)
        {
            var requestType = request.GetType();

            var handlerType = typeof(IRequestHandler<,>).MakeGenericType(requestType, typeof(TResponse));
            var handler = _serviceProvider.GetRequiredService(handlerType);

            var behaviorType = typeof(IPipelineBehavior<,>).MakeGenericType(requestType, typeof(TResponse));
            // Behaviors registered last-in-first-wraps; reverse so first-registered runs outermost.
            var behaviors = _serviceProvider.GetServices(behaviorType).Reverse().ToList();

            // The innermost delegate actually invokes the handler.
            Func<Task<TResponse>> pipeline = () =>
            {
                var handleMethod = handlerType.GetMethod("Handle")!;
                return (Task<TResponse>)handleMethod.Invoke(handler, new object[] { request, cancellationToken })!;
            };

            foreach (var behavior in behaviors)
            {
                var next = pipeline;
                var behaviorHandleMethod = behaviorType.GetMethod("Handle")!;
                pipeline = () => (Task<TResponse>)behaviorHandleMethod.Invoke(
                    behavior,
                    new object[] { request, next, cancellationToken })!;
            }

            return await pipeline();
        }
    }
}
