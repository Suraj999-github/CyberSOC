# CyberSOC
Cybersecurity Command Center (CyberSOC)
```
CyberSOC/
├── src/
│   ├── CyberSOC.Domain/                 # Entities, ValueObjects, DomainEvents, Specifications
│   ├── CyberSOC.Application/            # Per-module: Commands, Queries, Handlers, Validators, DTOs
│   │   ├── Ingestion/
│   │   ├── ThreatIntel/
│   │   ├── Detection/
│   │   ├── IdentityAnomaly/
│   │   ├── Incident/
│   │   ├── AIInvestigation/
│   │   └── RiskScoring/
│   ├── CyberSOC.Infrastructure/         # EF Core, Repositories, External Clients, Quartz Jobs
│   ├── CyberSOC.Persistence/            # DbContext(s), Migrations
│   ├── CyberSOC.WebApi/                 # Controllers/Minimal APIs, SignalR Hubs, Swagger
│   ├── CyberSOC.Workers/                # Background ingestion/correlation workers (separate process)
│   └── CyberSOC.Shared/                 # Cross-cutting: Dispatcher, Result<T>, Constants
├── tests/
│   ├── CyberSOC.UnitTests/
│   ├── CyberSOC.IntegrationTests/       # Testcontainers (Postgres, RabbitMQ, Redis)
│   └── CyberSOC.ArchitectureTests/      # NetArchTest — enforce dependency rules
├── frontend/                            # React/Blazor dashboard
├── docker-compose.yml
└── docs/
    ├── ADRs/                            # Architecture Decision Records
    ├── ERD.png
    └── api-spec.yaml
```