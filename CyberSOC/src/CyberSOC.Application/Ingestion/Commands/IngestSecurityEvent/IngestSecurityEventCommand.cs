using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CyberSOC.Application.Ingestion.Commands.IngestSecurityEvent
{
    public sealed record IngestSecurityEventCommand(
     SecurityEventType EventType,
     string Source,
     string IpAddress,
     string? UserId,
     string TargetResource,
     EventOutcome Outcome,
     string RawPayload,
     Dictionary<string, string>? Attributes
 ) : ICommand<Result<Guid>>;

    public sealed class IngestSecurityEventCommandValidator : AbstractValidator<IngestSecurityEventCommand>
    {
        public IngestSecurityEventCommandValidator()
        {
            RuleFor(x => x.Source).NotEmpty().MaximumLength(100);
            RuleFor(x => x.IpAddress).NotEmpty();
            RuleFor(x => x.TargetResource).NotEmpty().MaximumLength(500);
            RuleFor(x => x.RawPayload).NotNull();
        }
    }
}
