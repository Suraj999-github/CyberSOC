using CyberSOC.Application.Common.Interfaces;
using CyberSOC.Domain.ThreatIntel;
using CyberSOC.Shared.Common;
using CyberSOC.Shared.Cqrs;
using FluentValidation;

namespace CyberSOC.Application.ThreatIntel.UpsertIndicator
{
    public sealed record UpsertIndicatorCommand(
        IndicatorType Type,
        string Value,
        string Source,
        int Confidence,
        string? Tags
    ) : ICommand<Result<Guid>>;

    public sealed class UpsertIndicatorCommandValidator : AbstractValidator<UpsertIndicatorCommand>
    {
        public UpsertIndicatorCommandValidator()
        {
            RuleFor(x => x.Value).NotEmpty();
            RuleFor(x => x.Source).NotEmpty();
            RuleFor(x => x.Confidence).InclusiveBetween(0, 100);
        }
    }

    public sealed class UpsertIndicatorCommandHandler : IRequestHandler<UpsertIndicatorCommand, Result<Guid>>
    {
        private readonly IIndicatorRepository _indicatorRepository;

        public UpsertIndicatorCommandHandler(IIndicatorRepository indicatorRepository)
        {
            _indicatorRepository = indicatorRepository;
        }

        public async Task<Result<Guid>> Handle(UpsertIndicatorCommand request, CancellationToken cancellationToken)
        {
            var normalizedValue = IndicatorOfCompromise.NormalizeValue(request.Type, request.Value);

            var existing = await _indicatorRepository.FindByValueAsync(request.Type, normalizedValue, cancellationToken);

            if (existing is not null)
            {
                existing.Refresh(request.Confidence, request.Tags);
                await _indicatorRepository.SaveChangesAsync(cancellationToken);
                return Result.Success(existing.Id);
            }

            var indicator = IndicatorOfCompromise.Create(
                request.Type, request.Value, request.Source, request.Confidence, request.Tags);

            await _indicatorRepository.AddAsync(indicator, cancellationToken);
            await _indicatorRepository.SaveChangesAsync(cancellationToken);

            return Result.Success(indicator.Id);
        }
    }

}
