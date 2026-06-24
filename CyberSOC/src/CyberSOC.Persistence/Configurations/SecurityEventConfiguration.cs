using CyberSOC.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;


namespace CyberSOC.Persistence.Configurations
{
    public sealed class SecurityEventConfiguration : IEntityTypeConfiguration<SecurityEvent>
    {
        public void Configure(EntityTypeBuilder<SecurityEvent> builder)
        {
            builder.ToTable("SecurityEvents");

            builder.HasKey(e => e.Id);

            builder.Property(e => e.EventType).HasConversion<string>().HasMaxLength(50).IsRequired();
            builder.Property(e => e.Timestamp).IsRequired();
            builder.Property(e => e.Source).HasMaxLength(100).IsRequired();
            builder.Property(e => e.TargetResource).HasMaxLength(500).IsRequired();
            builder.Property(e => e.Outcome).HasConversion<string>().HasMaxLength(20).IsRequired();

            // SQL Server has no native JSON column type — store as nvarchar(max).
            // SQL Server 2022+/Azure SQL can still query into it with JSON_VALUE()/
            // OPENJSON() if needed; SSMS just shows it as plain text either way.
            builder.Property(e => e.RawPayload).HasColumnType("nvarchar(max)");

            // NetworkActor is a value object — stored as owned columns on the same table
            // rather than a separate join, since it's always 1:1 with the event.
            builder.OwnsOne(e => e.Actor, actor =>
            {
                actor.Property(a => a.IpAddress).HasColumnName("ActorIp").HasMaxLength(45).IsRequired();
                actor.Property(a => a.UserId).HasColumnName("ActorUserId").HasMaxLength(100);
                actor.Property(a => a.CountryCode).HasColumnName("ActorCountryCode").HasMaxLength(2);
                actor.Property(a => a.DeviceFingerprint).HasColumnName("ActorDeviceFingerprint").HasMaxLength(200);
                actor.Property(a => a.UserAgent).HasColumnName("ActorUserAgent").HasMaxLength(500);
            });
            builder.Navigation(e => e.Actor).IsRequired();

            // Attributes dictionary serialized to a single nvarchar(max) column.
            builder.Property(e => e.Attributes)
                .HasColumnName("Attributes")
                .HasColumnType("nvarchar(max)")
                .HasConversion(
                    v => System.Text.Json.JsonSerializer.Serialize(v, (System.Text.Json.JsonSerializerOptions?)null),
                    v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, (System.Text.Json.JsonSerializerOptions?)null)
                         ?? new Dictionary<string, string>());

            // Hot-path indexes: detection rules query by IP + time window constantly.
            //builder.HasIndex("ActorIp", nameof(SecurityEvent.Timestamp))
            //    .HasDatabaseName("IX_SecurityEvents_ActorIp_Timestamp");
            builder.HasIndex(e => e.Timestamp)
                .HasDatabaseName("IX_SecurityEvents_Timestamp");

            builder.Ignore(e => e.DomainEvents);
        }
    }

}
