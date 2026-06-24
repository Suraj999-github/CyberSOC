namespace CyberSOC.Domain.Common
{
    public abstract class Entity<TId>
    {
        public TId Id { get; protected set; } = default!;

        private readonly List<IDomainEvent> _domainEvents = new();
        public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

        protected void RaiseDomainEvent(IDomainEvent domainEvent) => _domainEvents.Add(domainEvent);
        public void ClearDomainEvents() => _domainEvents.Clear();

        public override bool Equals(object? obj)
        {
            if (obj is not Entity<TId> other) return false;
            if (ReferenceEquals(this, other)) return true;
            return EqualityComparer<TId>.Default.Equals(Id, other.Id);
        }

        public override int GetHashCode() => Id?.GetHashCode() ?? 0;
    }
    public interface IDomainEvent
    {
        DateTimeOffset OccurredOn { get; }
    }

}
