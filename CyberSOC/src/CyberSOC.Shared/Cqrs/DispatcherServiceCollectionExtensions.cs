using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

namespace CyberSOC.Shared.Cqrs
{
    public static class DispatcherServiceCollectionExtensions
    {
        /// <summary>
        /// Scans the given assembly for IRequestHandler&lt;,&gt; implementations and
        /// registers them, plus the Dispatcher itself. This is the free equivalent
        /// of services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(...)).
        /// </summary>
        public static IServiceCollection AddCyberSocDispatcher(this IServiceCollection services, Assembly assembly)
        {
            services.AddScoped<IDispatcher, Dispatcher>();

            var handlerInterfaceType = typeof(IRequestHandler<,>);

            var handlerTypes = assembly.GetTypes()
                .Where(t => !t.IsAbstract && !t.IsInterface)
                .SelectMany(t => t.GetInterfaces()
                    .Where(i => i.IsGenericType && i.GetGenericTypeDefinition() == handlerInterfaceType)
                    .Select(i => new { Interface = i, Implementation = t }));

            foreach (var match in handlerTypes)
            {
                services.AddScoped(match.Interface, match.Implementation);
            }

            return services;
        }

        /// <summary>
        /// Registers a pipeline behavior (open generic) so it applies to every request,
        /// e.g. services.AddCyberSocPipelineBehavior(typeof(ValidationBehavior&lt;,&gt;)).
        /// Register order = execution order (outermost first).
        /// </summary>
        public static IServiceCollection AddCyberSocPipelineBehavior(this IServiceCollection services, Type openGenericBehaviorType)
        {
            services.AddScoped(typeof(IPipelineBehavior<,>), openGenericBehaviorType);
            return services;
        }
    }

}
