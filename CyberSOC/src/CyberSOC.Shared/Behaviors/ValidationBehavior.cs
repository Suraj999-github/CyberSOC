using CyberSOC.Shared.Common;
using CyberSOC.Shared.Cqrs;
using FluentValidation;
using ValidationException = FluentValidation.ValidationException;

namespace CyberSOC.Shared.Behaviors
{
    /// <summary>
    /// Runs all registered FluentValidation validators for TRequest before invoking
    /// the handler. If TResponse is a Result/Result&lt;T&gt;, validation failures are
    /// returned as Result.Failure(...) instead of throwing — keeping failure handling
    /// uniform across the Application layer.
    /// </summary>
    public sealed class ValidationBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
        where TRequest : IRequest<TResponse>
    {
        private readonly IEnumerable<IValidator<TRequest>> _validators;

        public ValidationBehavior(IEnumerable<IValidator<TRequest>> validators)
        {
            _validators = validators;
        }

        public async Task<TResponse> Handle(
            TRequest request,
            Func<Task<TResponse>> next,
            CancellationToken cancellationToken)
        {
            if (!_validators.Any())
            {
                return await next();
            }

            var failures = new List<string>();
            foreach (var validator in _validators)
            {
                var result = await validator.ValidateAsync(request, cancellationToken);
                if (!result.IsValid)
                {
                    failures.AddRange(result.Errors.Select(e => e.ErrorMessage));
                }
            }

            if (failures.Count == 0)
            {
                return await next();
            }

            // Uniform handling: if the handler returns Result or Result<T>, short-circuit
            // with a failure result instead of throwing — avoids exceptions-as-control-flow.
            var responseType = typeof(TResponse);
            if (responseType == typeof(Result))
            {
                return (TResponse)(object)Result.Failure(failures);
            }
            if (responseType.IsGenericType && responseType.GetGenericTypeDefinition() == typeof(Result<>))
            {
                var failureMethod = responseType.GetMethod(nameof(Result.Failure), new[] { typeof(IEnumerable<string>) })!;
                return (TResponse)failureMethod.Invoke(null, new object[] { failures })!;
            }

            throw new ValidationException(string.Join("; ", failures));
        }
    }

}
