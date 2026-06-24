/*
after dotnet ef database update has created the SecurityEvents tabledotnet 

ef migrations remove
dotnet ef migrations add InitialCreate
dotnet ef database update

*/
/* ============================================================================
   STEP 1 - Verify table exists
   ============================================================================ */

IF OBJECT_ID('dbo.SecurityEvents', 'U') IS NULL
BEGIN
    THROW 50000, 'SecurityEvents table does not exist. Run EF migrations first.', 1;
END
GO


/* ============================================================================
   STEP 2 - Create index for Timestamp searches
   Equivalent to Timescale time-window optimization.
   ============================================================================ */

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_SecurityEvents_Timestamp'
      AND object_id = OBJECT_ID('dbo.SecurityEvents')
)
BEGIN
    CREATE NONCLUSTERED INDEX IX_SecurityEvents_Timestamp
    ON dbo.SecurityEvents ([Timestamp]);
END
GO


/* ============================================================================
   STEP 3 - Create composite index for ActorIp + Timestamp
   Equivalent to common SOC detection-rule lookups.
   ============================================================================ */

IF COL_LENGTH('dbo.SecurityEvents', 'ActorIp') IS NOT NULL
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM sys.indexes
        WHERE name = 'IX_SecurityEvents_ActorIp_Timestamp'
          AND object_id = OBJECT_ID('dbo.SecurityEvents')
    )
    BEGIN
        CREATE NONCLUSTERED INDEX IX_SecurityEvents_ActorIp_Timestamp
        ON dbo.SecurityEvents
        (
            ActorIp,
            [Timestamp]
        );
    END
END
GO


/* ============================================================================
   STEP 4 - Create Source + Timestamp index
   Useful for investigations and filtering by event source.
   ============================================================================ */

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'IX_SecurityEvents_Source_Timestamp'
      AND object_id = OBJECT_ID('dbo.SecurityEvents')
)
BEGIN
    CREATE NONCLUSTERED INDEX IX_SecurityEvents_Source_Timestamp
    ON dbo.SecurityEvents
    (
        Source,
        [Timestamp]
    );
END
GO


/* ============================================================================
   STEP 5 - Add Nonclustered Columnstore Index
   SQL Server equivalent for large-scale analytics.
   Similar benefit to Timescale compressed analytical scans.
   ============================================================================ */

IF NOT EXISTS (
    SELECT 1
    FROM sys.indexes
    WHERE name = 'NCCI_SecurityEvents'
      AND object_id = OBJECT_ID('dbo.SecurityEvents')
)
BEGIN
    CREATE NONCLUSTERED COLUMNSTORE INDEX NCCI_SecurityEvents
    ON dbo.SecurityEvents
    (
        [Timestamp],
        EventType,
        Outcome,
        Source
    );
END
GO


/* ============================================================================
   STEP 6 - Enable PAGE compression
   Similar goal as Timescale compression.
   ============================================================================ */

ALTER INDEX IX_SecurityEvents_Timestamp
ON dbo.SecurityEvents
REBUILD WITH (DATA_COMPRESSION = PAGE);

ALTER INDEX IX_SecurityEvents_ActorIp_Timestamp
ON dbo.SecurityEvents
REBUILD WITH (DATA_COMPRESSION = PAGE);

ALTER INDEX IX_SecurityEvents_Source_Timestamp
ON dbo.SecurityEvents
REBUILD WITH (DATA_COMPRESSION = PAGE);
/* ============================================================================
   STEP 7 - Create retention cleanup procedure
   Equivalent to Timescale retention policy (365 days).
   ============================================================================ */

CREATE OR ALTER PROCEDURE dbo.usp_CleanupSecurityEvents
AS
BEGIN
    SET NOCOUNT ON;

    DELETE FROM dbo.SecurityEvents
    WHERE [Timestamp] < DATEADD(DAY, -365, SYSUTCDATETIME());
END
GO


/* ============================================================================
   STEP 8 - Test retention cleanup manually
   ============================================================================ */

EXEC dbo.usp_CleanupSecurityEvents;
GO


/* ============================================================================
   STEP 9 - Verify created indexes
   ============================================================================ */

SELECT
    i.name,
    i.type_desc
FROM sys.indexes i
WHERE i.object_id = OBJECT_ID('dbo.SecurityEvents');
GO