namespace CyberSOC.Shared.Cqrs
{
    /// <summary>
    /// Marker for a Command or Query that returns TResponse.
    /// Equivalent to MediatR's IRequest&lt;TResponse&gt; — defined in-house so the
    /// Application layer has zero dependency on any licensed third-party package.
    /// </summary>
    public interface IRequest<TResponse> { }

    /// <summary>Marks a request as a write operation (Command) for logging/audit purposes.</summary>
    public interface ICommand<TResponse> : IRequest<TResponse> { }

    /// <summary>Marks a request as a read operation (Query) for logging/audit purposes.</summary>
    public interface IQuery<TResponse> : IRequest<TResponse> { }

    public interface IRequestHandler<in TRequest, TResponse> where TRequest : IRequest<TResponse>
    {
        Task<TResponse> Handle(TRequest request, CancellationToken cancellationToken);
    }

    /// <summary>
    /// Pipeline behavior, analogous to MediatR's IPipelineBehavior.
    /// Behaviors are resolved in DI registration order and wrap the handler call —
    /// used for validation, logging, performance timing, and audit capture.
    /// </summary>
    public interface IPipelineBehavior<TRequest, TResponse> where TRequest : IRequest<TResponse>
    {
        Task<TResponse> Handle(
            TRequest request,
            Func<Task<TResponse>> next,
            CancellationToken cancellationToken);
    }

}
