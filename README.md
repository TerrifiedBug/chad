# CHAD - Cyber Hunting And Detection

A web-based Sigma rule management and alerting platform for OpenSearch. Replaces OpenSearch's built-in Security Analytics with a modern, feature-rich interface for security teams.

## Features

### Rule Management
- **YAML Editor** - Monaco-based editor with Sigma schema validation, syntax highlighting, and autocomplete
- **Field Validation** - Strict validation against OpenSearch index mappings before deployment
- **Version Control** - Full version history with diff view and one-click rollback
- **Testing** - Test rules against sample logs or historical data before deployment
- **SigmaHQ Integration** - Browse, search, and bulk import rules from SigmaHQ repository

### Alerting
- **Real-time Matching** - OpenSearch percolators match incoming logs against thousands of rules
- **Threshold Alerting** - Count-based aggregation (e.g., 10 failed logins in 5 minutes)
- **Webhook Notifications** - Global webhook with per-rule disable toggle
- **Jira Integration** - Automatically create tickets for alerts

### Enrichment
- **Threat Intelligence** - Enrich alerts with CrowdStrike, MISP, and open source APIs
- **IOC Extraction** - Automatic extraction of IPs, domains, hashes, and URLs

### Visibility
- **Dashboard** - Stats, recent alerts, system health at a glance
- **Alert Investigation** - Full log context with TI enrichment
- **MITRE ATT&CK Map** - Visualize detection coverage
- **Audit Log** - Complete history of all user actions

### Operations
- **Exception Rules** - Tune out false positives without disabling rules
- **Rule Snooze** - Temporarily disable rules during maintenance
- **Bulk Operations** - Enable/disable/delete multiple rules at once
- **Export/Backup** - Export rules as Sigma YAML, full config backup

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend (React + shadcn/ui)                 │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Backend (FastAPI + pySigma)                  │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│  PostgreSQL   │      │  OpenSearch   │      │   External    │
│  (Config)     │      │  (Percolators │      │   Services    │
│               │      │   & Alerts)   │      │               │
└───────────────┘      └───────────────┘      └───────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- OpenSearch cluster (existing)
- Fluentd configured to send logs

### Deployment

1. Clone the repository:
```bash
git clone https://github.com/your-org/chad.git
cd chad
```

2. Create environment file:
```bash
cp .env.example .env
# Edit .env with your PostgreSQL password and JWT secret
```

3. Start the platform:
```bash
docker compose up -d
```

4. Access the UI at `http://localhost:3000`

5. Complete the setup wizard:
   - Create admin account
   - Configure OpenSearch connection
   - Set up first index pattern

### Configure Fluentd

Add a store to your Fluentd match to send logs to the platform:

```xml
<match auditbeat.**>
  @type copy

  <!-- Your existing OpenSearch store -->
  <store>
    @type opensearch
    ...
  </store>

  <!-- Add this to send to CHAD -->
  <store>
    @type http
    endpoint http://chad:8000/logs/auditbeat
    serializer json
    <buffer>
      flush_interval 60s
      chunk_limit_records 1000
    </buffer>
  </store>
</match>
```

## Configuration

All configuration is managed through the web UI after initial setup. Environment variables are minimal:

```env
# Database (required)
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=chad
POSTGRES_PASSWORD=<secure-password>
POSTGRES_DB=chad

# App secret (required)
JWT_SECRET_KEY=<random-secret>
```

### GUI-Configurable Settings

- **OpenSearch** - Host, port, credentials, SSL settings
- **Authentication** - Local auth enable/disable, SSO (OIDC/SAML) configuration
- **Index Patterns** - Define log sources and percolator indices
- **ECS Mappings** - Field translation from Sigma to ECS format
- **Webhooks** - Global notification endpoint
- **Jira** - Cloud instance URL and API token
- **Threat Intel** - CrowdStrike, MISP, AbuseIPDB, VirusTotal API keys
- **AI Mapping** - Local (Ollama) or cloud (OpenAI/Anthropic) for ECS suggestions
- **Processing** - Batch size, queue thresholds, index prefixes

## Development

Development uses Docker for all commands to avoid polluting local environments:

```bash
# Start development environment
docker compose -f docker-compose.dev.yml up -d

# Run backend tests
docker compose -f docker-compose.dev.yml run --rm backend pytest

# Run frontend tests
docker compose -f docker-compose.dev.yml run --rm frontend npm test

# Run linting
docker compose -f docker-compose.dev.yml run --rm backend ruff check .
docker compose -f docker-compose.dev.yml run --rm frontend npm run lint

# Interactive shell
docker compose -f docker-compose.dev.yml exec backend bash
docker compose -f docker-compose.dev.yml exec frontend sh
```

## Roadmap

### v1.0 - Core Platform
- [ ] Rule CRUD with YAML editor
- [ ] Field validation
- [ ] Sample log testing
- [ ] Basic dashboard
- [ ] Local auth + SSO
- [ ] Webhook notifications
- [ ] Rule versioning
- [ ] Dark mode

### v1.1 - Rule Management
- [ ] SigmaHQ sync + bulk import
- [ ] Exception rules
- [ ] Bulk operations
- [ ] Rule comments
- [ ] Export/backup
- [ ] Audit log

### v1.2 - Detection Quality
- [ ] Historical dry-run testing
- [ ] Threshold alerting
- [ ] MITRE ATT&CK coverage map
- [ ] Per-index health monitoring

### v1.3 - Integrations
- [ ] Jira Cloud
- [ ] Threat intel enrichment
- [ ] Read-only REST API (user-scoped API keys)

### v2.0 - Scale & Intelligence
- [ ] AI-assisted ECS mapping
- [ ] Horizontal scaling (Celery + Redis)
- [ ] Time-based correlation rules

## License

[License details here]
