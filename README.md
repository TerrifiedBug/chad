# Sigma Alerting Platform

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
git clone https://github.com/your-org/sigma-alerting-platform.git
cd sigma-alerting-platform
```

2. Create environment file:
```bash
cp .env.example .env
# Edit .env with your PostgreSQL password and JWT secret
```

3. Start the platform:
```bash
docker-compose up -d
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

  <!-- Add this to send to Sigma platform -->
  <store>
    @type http
    endpoint http://sigma-platform:8000/logs/auditbeat
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
POSTGRES_USER=sigma
POSTGRES_PASSWORD=<secure-password>
POSTGRES_DB=sigma

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

## Usage

### Creating a Rule

1. Navigate to **Rules** → **New Rule**
2. Write Sigma YAML in the editor:
```yaml
title: Suspicious PowerShell Execution
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-encoded'
    condition: selection
level: high
```
3. Select target **Index Pattern** (e.g., winlogbeat)
4. Click **Validate** to check fields exist
5. Click **Test** with sample logs to verify detection
6. Click **Deploy** to activate the rule

### Investigating Alerts

1. Navigate to **Alerts**
2. Filter by severity, rule, time range
3. Click an alert to view:
   - Full matched log
   - Rule details
   - Threat intel enrichment
4. Actions: Create Jira ticket, create exception, snooze rule

### Importing from SigmaHQ

1. Navigate to **SigmaHQ**
2. Filter by product (windows, linux), category, tags
3. Search for specific rules
4. Select rules to import
5. Assign index pattern
6. Click **Import**

## API

### Read-Only External API

```bash
# List rules
GET /api/v1/rules

# Get alerts
GET /api/v1/alerts?since=2024-01-01&severity=high

# System stats
GET /api/v1/stats
```

### Internal API

See [API Documentation](docs/api.md) for full endpoint reference.

## Development

### Prerequisites

- Python 3.11+
- Node.js 20+
- PostgreSQL 16
- OpenSearch (or use testcontainers)

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Start development server
uvicorn main:app --reload
```

### Frontend Setup

```bash
cd frontend
npm install

# Run tests
npm test

# Start development server
npm run dev
```

### Running Tests

```bash
# Backend unit + integration tests
cd backend && pytest

# Frontend unit tests
cd frontend && npm test

# E2E tests
cd frontend && npm run test:e2e
```

## Roadmap

### v1.0 - Core Platform
- [x] Rule CRUD with YAML editor
- [x] Field validation
- [x] Sample log testing
- [x] Basic dashboard
- [x] Local auth + SSO
- [x] Webhook notifications
- [x] Rule versioning
- [x] Dark mode

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
- [ ] Read-only REST API

### v2.0 - Scale & Intelligence
- [ ] AI-assisted ECS mapping
- [ ] Horizontal scaling (Celery + Redis)
- [ ] Time-based correlation rules

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

[License details here]

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/sigma-alerting-platform/issues)
