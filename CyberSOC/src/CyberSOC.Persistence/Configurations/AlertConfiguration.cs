using CyberSOC.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;


namespace CyberSOC.Persistence.Configurations
{
    public sealed class AlertConfiguration : IEntityTypeConfiguration<Alert>
    {
        public void Configure(EntityTypeBuilder<Alert> builder)
        {
            builder.ToTable("Alerts");

            builder.HasKey(a => a.Id);

            builder.Property(a => a.AlertType).HasConversion<string>().HasMaxLength(50).IsRequired();
            builder.Property(a => a.Severity).HasConversion<string>().HasMaxLength(20).IsRequired();
            builder.Property(a => a.Status).HasConversion<string>().HasMaxLength(20).IsRequired();
            builder.Property(a => a.Title).HasMaxLength(300).IsRequired();
            builder.Property(a => a.Reason).HasColumnType("nvarchar(max)");
            builder.Property(a => a.RaisedAt).IsRequired();
            builder.Property(a => a.SourceIp).HasMaxLength(45);
            builder.Property(a => a.UserId).HasMaxLength(100);

            // SQL Server has no native array/uuid[] type (unlike Postgres). The
            // backing field is mapped through a ValueConverter to a single
            // comma-separated nvarchar(max) column, with a ValueComparer so EF
            // Core's change tracker compares contents correctly instead of
            // reference-comparing the List<Guid>.
            var evidenceConverter = new ValueConverter<List<Guid>, string>(
                v => string.Join(',', v),
                v => string.IsNullOrEmpty(v)
                    ? new List<Guid>()
                    : v.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Guid.Parse).ToList());

            var evidenceComparer = new ValueComparer<List<Guid>>(
                (a, b) => a!.SequenceEqual(b!),
                v => v.Aggregate(0, (hash, id) => HashCode.Combine(hash, id)),
                v => v.ToList());

            builder.Property<List<Guid>>("_evidenceEventIds")
                .HasColumnName("EvidenceEventIds")
                .HasColumnType("nvarchar(max)")
                .HasConversion(evidenceConverter, evidenceComparer);

            builder.Metadata
                .FindNavigation(nameof(Alert.EvidenceEventIds))
                ?.SetPropertyAccessMode(PropertyAccessMode.Field);

            builder.HasIndex(a => a.Status).HasDatabaseName("IX_Alerts_Status");
            builder.HasIndex(a => a.RaisedAt).HasDatabaseName("IX_Alerts_RaisedAt");
            builder.HasIndex(a => a.SourceIp).HasDatabaseName("IX_Alerts_SourceIp");

            builder.Ignore(a => a.DomainEvents);
        }
    }

}
