using CyberSOC.Domain.ThreatIntel;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CyberSOC.Persistence.Configurations
{
    public sealed class IndicatorOfCompromiseConfiguration : IEntityTypeConfiguration<IndicatorOfCompromise>
    {
        public void Configure(EntityTypeBuilder<IndicatorOfCompromise> builder)
        {
            builder.ToTable("Indicators");

            builder.HasKey(i => i.Id);

            builder.Property(i => i.Type).HasConversion<string>().HasMaxLength(20).IsRequired();
            builder.Property(i => i.Value).HasMaxLength(500).IsRequired();
            builder.Property(i => i.Source).HasMaxLength(100).IsRequired();
            builder.Property(i => i.Confidence).IsRequired();
            builder.Property(i => i.FirstSeen).IsRequired();
            builder.Property(i => i.LastSeen).IsRequired();
            builder.Property(i => i.Tags).HasMaxLength(500);

            // Lookups during enrichment are always "type + exact value" — unique
            // so a feed sync naturally upserts instead of duplicating.
            builder.HasIndex(i => new { i.Type, i.Value }).IsUnique()
                .HasDatabaseName("IX_Indicators_Type_Value");

            builder.Ignore(i => i.DomainEvents);
        }
    }

}
