# CHAD - Cyber Hunting And Detection

**CHAD** is a lightweight, Sigma-first detection engine designed for teams who store logs in **OpenSearch** but don't want the cost, complexity, or lock-in of a traditional SIEM.

It focuses on one thing and does it well:

> **Turn log events into high-quality security alerts using Sigma rules.**

CHAD is *not* a full SIEM. It intentionally fills the gap between cheap log storage and expensive, heavyweight SIEM platforms.

---

## Why CHAD Exists

Many security teams today:

- Already ship logs to OpenSearch or Elasticsearch
- Use it as a data lake because it's cheaper and more flexible
- Still need real detections, not just dashboards

Existing options usually fall into one of these traps:

| Approach | Problem |
|----------|---------|
| Full SIEMs (Splunk, Sentinel) | High cost, vendor lock-in |
| Scheduled query alerting | Noisy, hard to manage, delayed |
| Built-in "Security Analytics" | Immature, inflexible, limited Sigma support |

CHAD bridges that gap by providing a **dedicated detection engine** that sits on top of OpenSearch.

---

## What CHAD Is (and Isn't)

### CHAD **is**:

- A Sigma-native detection engine
- Designed for OpenSearch users
- Event-driven and near real-time
- API-first and automation-friendly
- Focused on alert quality and rule hygiene

### CHAD **is not**:

- A full SIEM
- A log storage platform
- A UEBA or SOAR system
- A replacement for dashboards or investigations

CHAD assumes your logs already exist in OpenSearch and focuses purely on detection.

---

## Core Concepts

### Sigma as the Source of Truth

All detections are authored in **Sigma** - the open, vendor-neutral detection format.

Sigma rules are:
- Portable across platforms
- Widely understood by security engineers
- Version-controlled like code

CHAD converts Sigma rules into OpenSearch query DSL using [pySigma](https://github.com/SigmaHQ/pySigma) and stores them as percolators.

### Percolator-Based Detection

CHAD uses **OpenSearch percolators** for detection - a reversal of normal search:

| Normal Search | Percolation |
|---------------|-------------|
| Store documents | Store queries (rules) |
| Run queries against them | Send a document (event) |
| Get matching documents | Get matching rules |

This is a natural fit for security detections.

**Why percolators?**
- No custom query engine to maintain
- Matching semantics identical to OpenSearch searches
- OpenSearch efficiently pre-filters candidate rules
- Rules are centrally stored and searchable
- CHAD remains stateless and easy to operate

---

## Architecture

```
                    ┌─────────────┐
                    │   Fluentd   │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               │
    ┌─────────────┐  ┌─────────────┐       │
    │  OpenSearch │  │    CHAD     │       │
    │  (storage)  │  │  (detect)   │       │
    └─────────────┘  └──────┬──────┘       │
                            │              │
                    ┌───────▼────────┐     │
                    │ Percolate API  │     │
                    └───────┬────────┘     │
                            │              │
                    ┌───────▼────────┐     │
                    │    Alerts      │◄────┘
                    │  (OpenSearch)  │
                    └───────┬────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         ┌────────┐   ┌─────────┐   ┌─────────┐
         │Webhooks│   │  Jira   │   │  Email  │
         └────────┘   └─────────┘   └─────────┘
```

### Detection Flow

1. **Fluentd ships logs** to both OpenSearch (storage) and CHAD (detection)
2. **CHAD authenticates** the request using per-index-pattern auth tokens
3. **CHAD percolates** each event against deployed rules
4. **Matching rules** generate alerts with full log context
5. **Alerts are enriched** with threat intelligence and GeoIP
6. **Notifications fire** via webhooks, Jira, or other integrations

---

## Features

### Rule Management
- **Monaco YAML Editor** with Sigma schema validation and autocomplete
- **Field Validation** against actual OpenSearch index mappings
- **Version History** with diff view and one-click rollback
- **SigmaHQ Integration** - browse, search, and bulk import community rules
- **Rule Testing** against sample logs before deployment

### Detection
- **Real-time Matching** via OpenSearch percolators
- **Threshold Alerting** - count-based aggregation (e.g., 10 failed logins in 5 minutes)
- **Correlation Rules** - multi-event detection patterns
- **Exception Rules** - tune out false positives without disabling rules

### Enrichment
- **Threat Intelligence** - CrowdStrike, MISP, VirusTotal, AbuseIPDB
- **IOC Extraction** - automatic extraction of IPs, domains, hashes, URLs
- **GeoIP Enrichment** - geographic context for IP addresses

### Operations
- **MITRE ATT&CK Coverage Map** - visualize detection gaps
- **Health Monitoring** - per-index-pattern latency and error tracking
- **Audit Log** - complete history of all user actions
- **Bulk Operations** - enable, disable, delete multiple rules at once

### Security
- **Role-Based Access Control** - Admin, Analyst, Viewer roles
- **SSO Support** - OIDC and SAML integration
- **Per-Index Auth Tokens** - secure log shipping authentication
- **IP Allowlists** - restrict which sources can send logs

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- An existing OpenSearch cluster
- A log shipper (Fluentd, Logstash, etc.)

### 1. Clone and Configure

```bash
git clone https://github.com/terrifiedbug/chad.git
cd chad
cp .env.example .env
```

Edit `.env` with secure values:

```bash
POSTGRES_PASSWORD=your-secure-password
JWT_SECRET_KEY=$(openssl rand -base64 32)
SESSION_SECRET_KEY=$(openssl rand -base64 32)
CHAD_ENCRYPTION_KEY=$(openssl rand -base64 32)
APP_URL=https://chad.example.com
```

### 2. Start CHAD

```bash
docker compose up -d
```

### 3. Complete Setup Wizard

Open `http://localhost` and complete:
1. **Create Admin Account**
2. **Configure OpenSearch Connection**
3. **Create First Index Pattern**

### 4. Configure Log Shipping

Logs must be sent to **both** CHAD (for detection) and OpenSearch (for storage).

**Fluentd Example:**

```xml
<match winlogbeat.**>
  @type copy

  <!-- Send to CHAD for real-time detection -->
  <store>
    @type http
    endpoint https://chad.example.com/api/logs/winlogbeat
    headers {"Authorization": "Bearer YOUR_INDEX_PATTERN_AUTH_TOKEN"}
    json_array true
    <buffer>
      @type memory
      flush_interval 1s
    </buffer>
  </store>

  <!-- Send to OpenSearch for storage -->
  <store>
    @type opensearch
    host opensearch.example.com
    port 9200
    index_name winlogbeat-%Y.%m.%d
  </store>
</match>
```

Get your auth token from: **Index Patterns → [Your Pattern] → Settings → Auth Token**

---

## Who CHAD Is For

| Good Fit | Not Ideal |
|----------|-----------|
| Security teams using OpenSearch | Teams wanting an all-in-one SIEM |
| Organizations priced out of traditional SIEMs | Environments without a log data lake |
| Engineers who want detection-as-code | Purely GUI-driven security operations |
| Teams that value Sigma portability | Teams needing built-in UEBA |

---

## Design Philosophy

- **Detection first** - one job, done well
- **Simple over clever** - easy to understand and operate
- **Sigma everywhere** - portable, vendor-neutral rules
- **OpenSearch as a partner** - leverage what it does best
- **Make the common case easy** - and the complex case possible

---

## Refactoring Rules
- NEVER remove comments that explain "why" — ordering constraints,
  external system behavior, non-obvious side effects, or business logic
- Only remove comments that merely restate what the code does
- When in doubt, keep the comment

---

## Configuration

Most settings are managed through the web UI after initial setup.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `POSTGRES_PASSWORD` | Yes | Database password |
| `JWT_SECRET_KEY` | Yes | JWT signing key |
| `SESSION_SECRET_KEY` | Yes | Session encryption key |
| `CHAD_ENCRYPTION_KEY` | Yes | Credential encryption key |
| `APP_URL` | Yes | Public URL for CSRF, SSO redirects |
| `CHAD_SSO_ONLY` | No | Set `true` to disable local login |
| `LOG_LEVEL` | No | Logging verbosity (default: `warning`) |

### GUI-Configurable Settings

- **OpenSearch** - connection, credentials, SSL
- **Index Patterns** - log sources, field mappings, auth tokens
- **Notifications** - webhooks, Jira integration
- **Threat Intelligence** - API keys for TI providers
- **Authentication** - SSO (OIDC/SAML) configuration
- **AI Mapping** - Ollama, OpenAI, or Anthropic for field mapping suggestions

---

## Development

```bash
# Start development environment
docker compose -f docker-compose.dev.yml up -d

# Run backend tests
docker compose -f docker-compose.dev.yml run --rm backend pytest

# Run frontend tests
docker compose -f docker-compose.dev.yml run --rm frontend npm test

# Linting
docker compose -f docker-compose.dev.yml run --rm backend ruff check .
docker compose -f docker-compose.dev.yml run --rm frontend npm run lint
```

---

## Documentation

Full documentation available at: **[docs.chad.terrifiedbug.com](https://docs.chad.terrifiedbug.com)**

- [Quick Start Guide](https://docs.chad.terrifiedbug.com/quickstart)
- [Architecture Overview](https://docs.chad.terrifiedbug.com/architecture)
- [Rule Management](https://docs.chad.terrifiedbug.com/guide/rules)
- [Field Mappings](https://docs.chad.terrifiedbug.com/guide/field-mappings)

---

## Status

CHAD is under active development. Contributions, feedback, and design discussions are welcome.

## License

MIT License - see [LICENSE](LICENSE) for details.
