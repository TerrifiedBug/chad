# Sigma Alerting Platform - Design Document

**Date:** 2026-01-20
**Updated:** 2026-01-22 (Phase 6 design)
**Status:** Approved
**Author:** Brainstorming session

---

## Overview

A web-based Sigma rule management and alerting platform for OpenSearch, replacing OpenSearch's built-in Security Analytics. The platform enables security teams to create, test, deploy, and monitor Sigma detection rules with a modern GUI instead of GitLab-based workflows.

### Goals

- Replace GitLab workflow with GUI-based rule management
- Provide real-time log matching using OpenSearch percolators
- Enable rule testing before deployment
- Deliver visibility into detection health and alert activity
- Support both security analysts (rule authoring) and engineers (system management)

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend                                 │
│                   React + shadcn/ui + Tailwind                  │
│         (Rule Editor, Dashboards, Settings, Dark Mode)          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Backend API                              │
│                     FastAPI (Python 3.11+)                       │
│    (Rule CRUD, pySigma Translation, Auth, Webhooks, API)        │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
│    PostgreSQL     │ │   OpenSearch    │ │  External Services  │
│  (Rules, Config,  │ │  (Percolators,  │ │ (SSO, Jira, TI APIs,│
│   Users, Audit)   │ │ Alerts, Logs)   │ │  MISP, Webhooks)    │
└───────────────────┘ └─────────────────┘ └─────────────────────┘
```

### Log Matching Flow

```
Fluentd → POST /logs/{index} → Match against percolators → Store alerts → Trigger webhooks
```

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Frontend | React 18+, shadcn/ui, Tailwind CSS, Monaco Editor |
| Backend | FastAPI, Python 3.11+, pySigma |
| Database | PostgreSQL 16 |
| Search/Alerting | OpenSearch (existing infrastructure) |
| Auth | JWT (local), OIDC/SAML (SSO) |
| Containerization | Docker, Docker Compose |

---

## Data Model (PostgreSQL)

### Core Tables

**rules**
- `id` (UUID), `title`, `description`, `yaml_content`, `severity`, `status` (enabled/disabled/snoozed)
- `index_pattern_id` (FK), `alert_enabled`, `snooze_until` (timestamp)
- `created_by`, `created_at`, `updated_at`

**rule_versions**
- `id`, `rule_id` (FK), `version_number`, `yaml_content`, `changed_by`, `created_at`

**rule_comments**
- `id`, `rule_id` (FK), `version_id` (FK, nullable), `user_id`, `content`, `created_at`

**rule_exceptions**
- `id`, `rule_id` (FK), `field`, `operator` (enum: equals/not_equals/contains/not_contains/starts_with/ends_with/regex/in_list), `value`, `reason`, `created_by`, `created_at`, `is_active`

**index_patterns**
- `id`, `name`, `pattern`, `percolator_index`, `description`

**ecs_field_mappings**
- `id`, `source_field`, `ecs_field`, `confidence`, `confirmed_by`, `created_at`

**users**
- `id`, `email`, `password_hash` (nullable for SSO), `role`, `auth_method` (local/sso), `created_at`

**api_keys**
- `id` (UUID), `user_id` (FK), `name`, `key_hash`, `prefix` (first 8 chars), `created_at`, `last_used_at`, `expires_at`

**audit_log**
- `id`, `user_id`, `action`, `resource_type`, `resource_id`, `details`, `created_at`

**settings**
- `key`, `value` (JSON), `updated_at`

**notification_history**
- `id`, `alert_id`, `webhook_url`, `status`, `response_code`, `created_at`

---

## API Structure

### Authentication
- `POST /auth/login` - Local auth
- `GET /auth/me` - Get current user info (includes auth_method)
- `GET /auth/sso/callback` - SSO callback
- `POST /auth/logout` - Invalidate session
- `POST /auth/change-password` - Change password (local users only)
- `GET /auth/api-keys` - List current user's API keys
- `POST /auth/api-keys` - Create new API key (returns key once)
- `DELETE /auth/api-keys/{id}` - Revoke API key

### Rules
- `GET /rules` - List rules (filter, paginate, search)
- `POST /rules` - Create rule
- `GET /rules/{id}` - Get rule with versions and comments
- `PUT /rules/{id}` - Update rule
- `DELETE /rules/{id}` - Delete rule
- `POST /rules/{id}/deploy` - Deploy to OpenSearch percolator
- `POST /rules/{id}/test` - Test against sample logs
- `POST /rules/{id}/test-historical` - Dry-run against historical data
- `POST /rules/{id}/snooze` - Snooze for duration
- `POST /rules/{id}/clone` - Clone rule
- `GET /rules/{id}/versions` - Version history
- `POST /rules/{id}/rollback/{version}` - Rollback
- `POST /rules/bulk` - Bulk operations

### Comments
- `POST /rules/{id}/comments` - Add comment
- `GET /rules/{id}/comments` - Get unified timeline

### Log Matching
- `POST /logs/{index_suffix}` - Receive logs from Fluentd

### SigmaHQ
- `GET /sigmahq/status` - Sync status, last updated, rule count
- `GET /sigmahq/rules` - Browse rules (tree structure + search)
- `GET /sigmahq/rules/{path}` - Get single rule content by path
- `POST /sigmahq/sync` - Trigger manual git pull
- `POST /sigmahq/import` - Import selected rules to CHAD

### Exceptions
- `GET /rules/{id}/exceptions` - List rule exceptions
- `POST /rules/{id}/exceptions` - Create exception
- `PATCH /rules/{id}/exceptions/{exc_id}` - Update exception (enable/disable)
- `DELETE /rules/{id}/exceptions/{exc_id}` - Remove exception

### Audit
- `GET /audit` - Audit log with filters (user, action, date range, pagination)

### Settings
- `GET /settings` - Get all settings
- `PUT /settings/{key}` - Update setting

### Read-only External API
- `GET /api/v1/rules` - List rules
- `GET /api/v1/alerts` - List alerts
- `GET /api/v1/stats` - System statistics

---

## Frontend Structure

### Pages

| Route | Description |
|-------|-------------|
| `/` | Dashboard - stats, recent alerts, system health |
| `/rules` | Rule list with filters, search, bulk actions |
| `/rules/new` | Create new rule |
| `/rules/{id}` | Rule editor with test panel, timeline |
| `/alerts` | Alert list with filters |
| `/alerts/{id}` | Alert detail with enrichment |
| `/sigmahq` | SigmaHQ browser and import |
| `/attack` | MITRE ATT&CK coverage map |
| `/settings` | All configuration |
| `/settings/users` | User management |
| `/settings/audit` | Audit log viewer |
| `/setup` | First-run wizard |

### Key Components

- **Monaco YAML Editor** - Sigma schema validation, autocomplete
- **Test Panel** - Sample log input, match results
- **Activity Timeline** - Versions + comments unified view
- **Health Dashboard** - Per-index queue monitoring
- **User Dropdown** - Profile, API keys, password change (local only), logout
- **Log Shipper Info** - Setup instructions for sending logs to CHAD
- **SigmaHQ Browser** - Category tree, rule preview, import workflow (v1.1)
- **Exception Editor** - Per-rule field-value filters for false positives (v1.1)
- **Audit Log Viewer** - Filterable table of user actions (v1.1)

---

## Rule Processing Flow

### Create/Update Rule

1. User writes Sigma YAML in editor
2. Frontend validates YAML syntax
3. POST to backend with YAML + index pattern
4. Backend:
   - Parse Sigma YAML with pySigma
   - Apply ECS renamer pipeline
   - Extract query fields
   - Fetch target index mapping from OpenSearch
   - Compare fields → reject if missing (strict validation)
   - Convert to OpenSearch DSL percolator query
   - Store rule + metadata in PostgreSQL
   - Create version record
   - Deploy percolator document to OpenSearch
   - Log to audit trail
5. Return success/errors

### Test Rule (Sample Logs)

1. User pastes sample log JSON
2. POST to test endpoint
3. Run percolate query with sample document
4. Return match result with highlighted fields

### Test Rule (Historical Dry-Run)

1. User selects time range
2. Translate rule to standard OpenSearch query
3. Run against target index with time filter
4. Return matching documents (limited)

---

## Log Matching & Alerting

### Real-time Matching

1. Fluentd sends logs → POST /logs/{index_suffix}
2. Parse incoming logs (NDJSON, configurable batch size)
3. Verify percolator index exists
4. Run percolate query
5. For each match:
   - Check rule enabled (not disabled/snoozed)
   - Check exception rules
   - Apply threshold logic
6. Store matches in alerts index
7. Trigger async enrichment
8. Send webhook notification with alert URL

### Webhook Payload

```json
{
  "alert_id": "abc-123",
  "alert_url": "https://chad.example.com/alerts/abc-123",
  "rule_id": "def-456",
  "rule_title": "Suspicious PowerShell Execution",
  "severity": "high",
  "status": "new",
  "created_at": "2026-01-22T12:00:00Z",
  "matched_log": { ... }
}
```

The `alert_url` field is included when APP_URL is configured in Settings. If not configured, the field is omitted.

### Configurable Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `batch_size` | 1000 | Logs per batch |
| `batch_timeout_ms` | 500 | Max wait for batch |
| `max_workers` | 4 | Uvicorn workers |
| `percolator_index_prefix` | `percolator-` | Percolator index naming |
| `alerts_index_prefix` | `sigma-alerts-` | Alerts index naming |
| `queue_warning_threshold` | 10000 | Queue depth warning |
| `queue_critical_threshold` | 100000 | Queue depth critical |

### Backpressure Handling

- Never drop logs
- Queue grows unbounded (within limits)
- Per-index queue depth monitoring
- Alert when thresholds exceeded
- Operator scales workers or increases batch size

---

## ECS Field Mapping

### Flow

1. Sigma rules use Sigma-standard field names (`CommandLine`, `Image`)
2. On deployment, pySigma ECS pipeline transforms to ECS fields
3. Percolator query uses ECS fields to match ECS-formatted logs

### Global ECS Config

- Pre-populated with standard Sigma → ECS mappings
- Users add custom mappings via GUI
- AI-assisted suggestions (v2.0)

### AI-Assisted Mapping (v2.0)

- Configurable: Local (Ollama) or Cloud (OpenAI/Anthropic)
- Data sharing policy: field names only to cloud, values allowed for local
- Suggestions validated against ECS schema (synced from elastic/ecs repo)
- Confirmed mappings stored for learning

---

## Threat Intelligence Enrichment

### Supported Sources

| Source | Type | Purpose |
|--------|------|---------|
| CrowdStrike | Commercial | Threat intel API |
| MISP | Self-hosted | Internal threat intel |
| AbuseIPDB | Open source | IP reputation |
| VirusTotal | Open source | Hash/domain lookup |

### Enrichment Flow

1. Alert created
2. Extract IOC fields (IPs, domains, hashes, URLs)
3. Query configured TI sources (async)
4. Store results with alert
5. Display in alert detail view

---

## Authentication & Authorization

### Methods

- **Local auth**: Username/password, JWT tokens, disable via GUI
- **SSO**: OIDC configured in GUI after initial setup

### Roles

| Role | Permissions |
|------|-------------|
| Admin | Full access, settings management, user management |
| Analyst | Create/edit rules, view alerts, create exceptions |
| Viewer | Read-only access |

### Role-Based UI Access

- Settings page link hidden for non-admins
- Direct navigation to `/settings` redirects non-admins to Dashboard
- API endpoints enforce role checks independently

### SSO Behavior

- **Auto-provisioning**: Always enabled. Any valid SSO user gets an account automatically.
- **Role mapping**: Configurable claim-based mapping from IdP groups to CHAD roles
  - Configure which claim contains roles (e.g., `groups`, `roles`)
  - Map claim values to admin/analyst/viewer
  - Default role applied when no claim matches
- **Role sync**: User roles updated on each SSO login based on current claims

### OIDC Role Mapping Configuration

```json
{
  "claim": "groups",
  "admin": "chad-admins",
  "analyst": "chad-analysts",
  "viewer": "chad-viewers",
  "default": "analyst"
}
```

### User Profile Features

- **API Keys**: Users can create/revoke API keys for external API access
- **Password Change**: Local auth users only (SSO users manage via IdP)
- **Auth Method Display**: UI shows whether user authenticated via local or SSO

### First-Run Setup

1. App detects no users exist
2. Redirect to `/setup`
3. Create admin account
4. Configure OpenSearch
5. Optional: SSO, webhooks, etc.

---

## SigmaHQ Integration

### Storage

- Clone location: `/data/sigmahq` (Docker volume)
- Repository: `https://github.com/SigmaHQ/sigma.git` (configurable)
- Sync method: `git clone` on first sync, `git pull` on subsequent
- Tracked: last sync timestamp, commit hash, rule count

### Auto-Sync Settings

| Setting | Options | Default |
|---------|---------|---------|
| `sigmahq_auto_sync` | disabled/daily/weekly/monthly | disabled |
| `sigmahq_repo_url` | URL | https://github.com/SigmaHQ/sigma.git |

### Browser UI

- Left panel: Category tree by folder structure (windows/, linux/, network/, cloud/)
- Right panel: Rule preview with full YAML, metadata, ATT&CK tags
- Search: Filter rules by keyword, severity, tags
- Import: Copy rule to CHAD with index pattern selection

### Import Flow

1. User clicks "Import to CHAD" on rule preview
2. Modal: Select target index pattern
3. Rule YAML copied, status set to disabled
4. Redirect to rule editor for review before deployment

---

## Exception Rules

### Purpose

Allow analysts to suppress false positives by defining field-value conditions that skip alert creation when matched.

### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `user.name equals "svc_backup"` |
| `not_equals` | Not exact match | `host.name not_equals "DC01"` |
| `contains` | Substring match | `process.command_line contains "backup"` |
| `not_contains` | No substring | `file.path not_contains "temp"` |
| `starts_with` | Prefix match | `process.executable starts_with "C:\\Windows"` |
| `ends_with` | Suffix match | `process.executable ends_with "\\agent.exe"` |
| `regex` | Regular expression | `user.name regex "^svc_.*"` |
| `in_list` | Value in list | `host.name in_list ["DC01","DC02"]` |

### Match-Time Logic

1. Log matches rule's percolator query
2. Load rule's active exceptions
3. For each exception: check if log field matches condition
4. If ANY exception matches → skip alert creation
5. Otherwise → create alert as normal

---

## Audit Logging

### Audited Actions

| Action | Details Captured |
|--------|------------------|
| `user.login` | Email, auth method |
| `user.logout` | Email |
| `user.create` | New user email, role |
| `user.delete` | Deleted user email |
| `rule.create` | Rule title, ID |
| `rule.update` | Rule ID, changed fields |
| `rule.delete` | Rule title, ID |
| `rule.deploy` | Rule ID, target index |
| `rule.undeploy` | Rule ID |
| `exception.create` | Rule ID, exception details |
| `exception.delete` | Rule ID, exception ID |
| `settings.update` | Setting key |
| `sigmahq.sync` | Manual/auto, rule count, commit |
| `sigmahq.import` | Rule paths, target index |

### Viewer Features

- Filter by: user, action type, date range
- Pagination for large datasets
- Detail modal showing full JSON

### OpenSearch Mirroring (Optional)

- Toggle in Settings: "Mirror audit logs to OpenSearch"
- When enabled, writes to `chad-audit-logs` index in addition to PostgreSQL
- PostgreSQL remains source of truth
- Enables integration with existing SIEM, advanced search, custom retention policies

---

## Log Shipping Authentication

### Shared Secret

The `/logs/{index}` endpoint requires authentication via a shared secret configured in Settings.

**Configuration:**
- Settings → System → Log Shipping Secret
- Generate or set a secret token
- Provide to Fluentd/log shipper configuration

**Request Format:**
```
POST /api/logs/windows-sysmon
Authorization: Bearer <log-shipping-secret>
Content-Type: application/x-ndjson

{"@timestamp": "...", "event": {...}}
{"@timestamp": "...", "event": {...}}
```

**Validation:**
- If secret not configured: endpoint disabled, returns 503
- If secret configured but not provided: returns 401
- If secret incorrect: returns 401

**TLS:** Handled by reverse proxy (nginx, AWS ALB, etc.) - no CHAD code changes needed.

---

## User Management Enhancements

### Admin Edit Capabilities

| Field | Local Users | SSO Users |
|-------|-------------|-----------|
| Role | ✅ Editable | ❌ Managed by OIDC claims |
| Password | ✅ Reset to temporary | ❌ Managed by IdP |
| Active status | ✅ Enable/Disable | ✅ Enable/Disable |

### UI Changes

**Users page - Edit button per row:**
- Opens modal with editable fields based on auth_method
- Password reset generates temporary password, sets `must_change_password=true`
- Disable removes access but preserves audit trail

**Delete confirmation:**
- Styled modal instead of browser `confirm()`
- Shows user email prominently
- Requires explicit Cancel/Delete click

---

## Rate Limiting & Brute Force Protection

### Account Lockout

| Setting | Default | Description |
|---------|---------|-------------|
| `lockout_attempts` | 5 | Failed attempts before lockout |
| `lockout_duration_minutes` | 15 | Lockout duration |

**Behavior:**
- Track failed login attempts per email in Redis/memory
- After N failures: lock account for X minutes
- Successful login resets counter
- Lockout applies to local auth only (SSO handled by IdP)

### IP Rate Limiting

| Setting | Default | Description |
|---------|---------|-------------|
| `login_rate_limit` | 10/minute | Max login attempts per IP |

**Behavior:**
- Track login attempts per IP address
- Reject with 429 when limit exceeded
- Protects against credential stuffing across accounts

### Configuration

Settings → Security → Brute Force Protection
- Enable/disable account lockout
- Configure attempts and duration
- Enable/disable IP rate limiting
- Configure rate limit

---

## Role Permissions

### Configurable Permissions per Role

Instead of hardcoded permissions, admins can toggle what each fixed role can do.

**Settings → Security → Role Permissions:**

```
┌─────────────────────────────────────────────────────────────────┐
│ Role Permissions                                                 │
├─────────────────────────────────────────────────────────────────┤
│                        │ Admin │ Analyst │ Viewer │             │
│ ───────────────────────┼───────┼─────────┼────────┤             │
│ View rules             │  ✅   │   ✅    │   ✅   │             │
│ Create rules           │  ✅   │   ✅    │   ☐    │             │
│ Edit own rules         │  ✅   │   ✅    │   ☐    │             │
│ Edit all rules         │  ✅   │   ☐     │   ☐    │             │
│ Delete rules           │  ✅   │   ☐     │   ☐    │             │
│ Deploy/undeploy rules  │  ✅   │   ✅    │   ☐    │             │
│ Manage exceptions      │  ✅   │   ✅    │   ☐    │             │
│ View alerts            │  ✅   │   ✅    │   ✅   │             │
│ Update alert status    │  ✅   │   ✅    │   ☐    │             │
│ Import from SigmaHQ    │  ✅   │   ✅    │   ☐    │             │
│ View audit log         │  ✅   │   ☐     │   ☐    │             │
│ Manage settings        │  ✅   │   ☐     │   ☐    │             │
│ Manage users           │  ✅   │   ☐     │   ☐    │             │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation:**
- Permissions stored in `settings` table as JSON
- Default permissions match current hardcoded behavior
- Backend checks permissions on each endpoint
- Frontend shows/hides UI elements based on permissions

---

## Rules List Redesign

### SigmaHQ Browser Style

Replace flat table with tree-based browser matching SigmaHQ layout:

```
┌──────────────────────┬──────────────────────────────────────────────────┐
│ Index Patterns       │ Rule Preview                                     │
├──────────────────────┼──────────────────────────────────────────────────┤
│ 🔍 Search...         │ Suspicious PowerShell Execution                  │
│                      │                                                  │
│ ▼ windows-* (89)     │ ┌─────────────────────────────────────────────┐  │
│   ● Susp PS Exec     │ │ Severity: 🔴 High                           │  │
│   ● Mimikatz Use     │ │ Status: Deployed ✓                          │  │
│   ● LSASS Access     │ │ Version: v3                                  │  │
│ ▼ linux-* (42)       │ │ Index: windows-*                             │  │
│   ● SSH Brute Force  │ │ Last edited: admin@..., 2h ago              │  │
│ ▶ network-* (18)     │ │ Created: analyst@..., Jan 15                │  │
│ ▶ cloud-aws-* (7)    │ └─────────────────────────────────────────────┘  │
│                      │                                                  │
│ Filter by Status     │ title: Suspicious PowerShell Execution          │
│ ☑ Deployed           │ logsource:                                       │
│ ☑ Disabled           │   product: windows                               │
│ ☐ Snoozed            │ detection:                                       │
│                      │   selection:                                     │
│ Filter by Severity   │     CommandLine|contains: ['-enc', 'hidden']    │
│ ☑ Critical/High      │ ...                                              │
│ ☑ Medium             │                                                  │
│ ☐ Low/Info           │ [Edit Rule] [Deploy] [Disable] [Snooze ▼]       │
└──────────────────────┴──────────────────────────────────────────────────┘
```

**Features:**
- Left panel: Tree organized by index pattern with rule counts
- Search: Filter rules by keyword within selected index pattern
- Filters: Status (deployed/disabled/snoozed), Severity
- Right panel: Rule preview with CHAD metadata + full YAML
- Action buttons: Edit, Deploy/Undeploy, Disable, Snooze
- Consistent layout with SigmaHQ browser page

---

## Deployment

### Docker Images

**Separate images for frontend and backend:**
- `ghcr.io/<org>/sigma-frontend:latest` - React app served by nginx
- `ghcr.io/<org>/sigma-backend:latest` - FastAPI application

**Rationale:**
- Independent scaling
- Independent deploys (frontend changes don't require backend rebuild)
- Smaller image sizes
- Clearer separation of concerns

### Docker Compose (v1.0)

```yaml
services:
  frontend:
    image: ghcr.io/<org>/sigma-frontend:latest
    ports: ["3000:80"]
    depends_on: [backend]

  backend:
    image: ghcr.io/<org>/sigma-backend:latest
    ports: ["8000:8000"]
    environment:
      - POSTGRES_HOST=postgres
    depends_on: [postgres]

  postgres:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=sigma
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=sigma

volumes:
  pgdata:
```

### CI/CD Workflow

**Branch strategy:**
- `main` - Production releases, auto-tagged from version
- `release/v*` - Pre-release testing, builds `-rc` tags
- Feature branches - No Docker builds

**GitHub Actions:**
- Tests must pass before build
- Separate workflows for frontend/backend (or matrix build)
- Auto-create GitHub release with changelog on main
- Push to ghcr.io with semver tags

### Environment Variables (Minimal)

```env
# Database
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=sigma
POSTGRES_PASSWORD=<secure-password>
POSTGRES_DB=sigma

# App secret
JWT_SECRET_KEY=<random-secret>

# Encryption (for sensitive settings storage)
CHAD_ENCRYPTION_KEY=<random-secret>
```

All other configuration managed in GUI:
- OpenSearch connection
- APP_URL (required for SSO redirects and webhook alert links)
- SSO/OIDC settings
- Webhooks
- Session timeout

---

## Testing Strategy

### Backend

- **Unit tests**: pySigma translation, field validation, threshold logic
- **Integration tests**: OpenSearch CRUD, API endpoints, webhooks
- **Tools**: pytest, pytest-asyncio, testcontainers, httpx

### Frontend

- **Unit tests**: Components, forms, state
- **E2E tests**: Rule creation, alert investigation, settings
- **Tools**: Vitest, React Testing Library, Playwright

### CI Pipeline

1. Lint (ruff, eslint)
2. Unit tests
3. Integration tests
4. Build Docker images
5. E2E tests
6. Push to registry

---

## Release Phases

### v1.0 - Core Platform

- Rule CRUD with YAML editor, validation, field checking
- Explicit index pattern assignment
- Deploy to OpenSearch percolator
- Log matching endpoint with setup instructions
- Alerts stored in OpenSearch
- Basic dashboard with OpenSearch health status
- Sample log testing
- Local auth + SSO with OIDC role mapping
- Global webhook notifications with alert URLs
- Per-rule disable/snooze
- Rule versioning with rollback
- Dark mode
- First-run setup wizard
- User dropdown with profile features
- API keys for external API access
- Password change (local users)
- APP_URL configuration via GUI

### v1.1 - Rule Management & UX Completion

**Phase 6 (SigmaHQ + Exceptions + Audit + Quick Wins):**
- SigmaHQ integration: Git clone, category browser, rule preview, import to CHAD
- Auto-sync: Configurable scheduled pulls (daily/weekly/monthly)
- Exception rules: Per-rule field-value filters for false positive tuning
- Audit log viewer: Filterable UI for compliance
- Snooze UI: Snooze rule for X hours from rule editor
- HTTP Auth for log shipping: Shared secret header for `/logs/{index}` endpoint
- Edit local users: Admin can change role, reset password, disable/enable users
- External API alerts: Implement OpenSearch query for `/external/alerts`
- Better delete confirmation: Styled modal instead of browser confirm()

**Phase 7 (UX Polish + Security + Quality of Life):**
- Version history UI: Activity panel with diff view, rollback, and comments timeline
- Rules list redesign: Tree view by index pattern + table view toggle, filters, bulk actions
- Rate limiting: Per-account lockout (configurable attempts/duration), all failed logins audited
- Role permissions: 7 configurable permissions per role (admin/analyst/viewer)
- Audit to OpenSearch: Optional dual-write to `chad-audit-logs` index
- Bulk operations: Multi-select enable/disable/delete/deploy/undeploy with shift+click
- Rule comments: Unified activity timeline with versions, deploys, and comments
- Export/backup: Single rule YAML, bulk ZIP, config JSON (no secrets)
- OIDC role management: Allow role changes when OIDC role mapping disabled
- YAML auto-formatting: Format button using ruamel.yaml (preserves comments)
- Dialog standards: All modals use Tailwind/shadcn, errors shown within dialogs
- Audit logging gaps: Review and add missing audit events (settings changes, etc.)

### v1.2 - Detection Quality

- Historical dry-run testing
- Threshold-based alerting
- MITRE ATT&CK coverage map
- System health dashboard (per-index queues)

### v1.3 - Integrations

- Jira Cloud integration
- Threat intel enrichment

### v2.0 - Scale & Intelligence

- ECS AI-assisted mapping
- Celery + Redis (horizontal scaling)
- Time-based correlation rules

---

## Future Considerations

Documented for potential future releases:

- Horizontal scaling with Celery + Redis workers
- Message queue architecture (Kafka/Redis) for high-volume ingestion
- Full CRUD REST API
- Alert deduplication
- Review reminders
- Rule approval workflows
- Notification testing
- Log sample library
- Rule health scoring
- SigmaHQ update detection

---

## Appendix: Feature Summary

| Feature | Release | Description |
|---------|---------|-------------|
| YAML rule editor | v1.0 | Monaco editor with Sigma validation |
| Field validation | v1.0 | Strict - block deploy if fields missing |
| Rule versioning | v1.0 | Full history with rollback |
| Sample log testing | v1.0 | Paste logs, see matches |
| Dark mode | v1.0 | Theme toggle |
| User dropdown | v1.0 | Profile, API keys, password, logout |
| API keys | v1.0 | User-scoped keys for external API |
| Password change | v1.0 | Local auth users only |
| OIDC role mapping | v1.0 | Map IdP claims to CHAD roles |
| Webhook alert URLs | v1.0 | Direct links in notifications |
| OpenSearch status | v1.0 | Connection indicator in settings |
| Log shipper setup | v1.0 | Configuration instructions for index patterns |
| APP_URL setting | v1.0 | GUI-configured application URL |
| SigmaHQ browser | v1.1 | Git clone, category tree, rule preview, import |
| SigmaHQ auto-sync | v1.1 | Scheduled daily/weekly/monthly git pulls |
| Exception rules | v1.1 | Per-rule field-value filters for false positives |
| Audit log viewer | v1.1 | Filterable UI for compliance |
| Snooze UI | v1.1 | Snooze rule for X hours from rule editor |
| Log shipping auth | v1.1 | Shared secret header for log ingestion endpoint |
| Edit local users | v1.1 | Admin can change role, reset password, disable |
| External API alerts | v1.1 | OpenSearch query for /external/alerts endpoint |
| Delete confirmation | v1.1 | Styled modal instead of browser confirm() |
| Version history UI | v1.1+ | Activity panel with diff view, rollback, comments (Phase 7) |
| Rules list redesign | v1.1+ | Tree/table view toggle, filters, bulk selection (Phase 7) |
| Rate limiting | v1.1+ | Per-account lockout, configurable, all attempts audited (Phase 7) |
| Role permissions | v1.1+ | 7 configurable permissions per role (Phase 7) |
| Audit to OpenSearch | v1.1+ | Optional dual-write to chad-audit-logs (Phase 7) |
| Bulk operations | v1.1+ | Enable/disable/delete/deploy/undeploy with shift+click (Phase 7) |
| Rule comments | v1.1+ | Activity timeline with versions, deploys, comments (Phase 7) |
| Export/backup | v1.1+ | Single YAML, bulk ZIP, config JSON (Phase 7) |
| OIDC role management | v1.1+ | Edit roles when OIDC mapping disabled (Phase 7) |
| YAML auto-format | v1.1+ | Format button using ruamel.yaml (Phase 7) |
| Dialog standards | v1.1+ | All Tailwind modals, errors in dialogs (Phase 7) |
| Audit logging gaps | v1.1+ | All settings changes audited (Phase 7) |
| Historical dry-run | v1.2 | Test against time range |
| Threshold alerting | v1.2 | Count-based aggregation |
| ATT&CK map | v1.2 | Basic coverage visualization |
| Per-index health | v1.2 | Queue depth monitoring |
| Jira integration | v1.3 | Create tickets from alerts |
| TI enrichment | v1.3 | CrowdStrike, MISP, open source |
| AI field mapping | v2.0 | Assisted ECS suggestions |
| Horizontal scaling | v2.0 | Celery + Redis workers |
| Correlation rules | v2.0 | Time-based cross-rule detection |

---

## Changelog

### 2026-01-22 (Phase 6 & 7 Design)

Added v1.1 Phase 6 feature designs:

- **SigmaHQ Integration**: Git clone storage, category browser UI, rule preview, import workflow, configurable auto-sync (daily/weekly/monthly)
- **Exception Rules**: Per-rule field-value filters with operators (equals, contains, regex, in_list, etc.), match-time logic for alert suppression
- **Audit Log Viewer**: Filterable UI for compliance, actions tracked (login, rule CRUD, deploy, settings, etc.)
- **New sections**: SigmaHQ Integration, Exception Rules, Audit Logging
- **New API endpoints**: `/sigmahq/*`, `/rules/{id}/exceptions/*`, `/audit`
- **Updated schema**: `rule_exceptions` table with operator enum and is_active flag

Phase 6 quick wins added:

- **Snooze UI**: Snooze rule for X hours from rule editor
- **Log Shipping Auth**: Shared secret header for `/logs/{index}` endpoint
- **Edit Local Users**: Admin can change role, reset password, disable/enable
- **External API Alerts**: Implement OpenSearch query for `/external/alerts`
- **Delete Confirmation**: Styled modal instead of browser confirm()

Phase 7 designs added (12 features):

**Core Features:**
- **Rate Limiting**: Per-account lockout with PostgreSQL storage, configurable max_attempts (default 5) and lockout_minutes (default 15), all failed logins + lockout events audited
- **Bulk Operations**: Enable/disable/delete/deploy/undeploy selected rules, checkbox + shift+click selection, floating action bar
- **Version History UI**: Renamed to "Activity" panel, unified timeline with versions (inline diff), deploy events, and comments, restore creates new version
- **Export/Backup**: Single rule YAML download, bulk rules ZIP, config JSON backup (index patterns, webhooks, settings, role permissions - no secrets)
- **Audit to OpenSearch**: Setting toggle for dual-write to `chad-audit-logs` index, same schema as PostgreSQL
- **Role Permissions**: 7 permissions (manage_users, manage_rules, deploy_rules, manage_settings, manage_api_keys, view_audit, manage_sigmahq), configurable per role in Settings
- **Rules List Redesign**: Tree view (by index pattern) + table view toggle, filters (index pattern, severity, status, sigma status, deployed), remember last view preference
- **Rule Comments**: Stored in `rule_comments` table, displayed in Activity panel timeline, no edit/delete for audit integrity

**Quality of Life:**
- **OIDC Role Management**: Allow admin to change OIDC user roles when role mapping is disabled
- **YAML Auto-formatting**: Format button in rule editor using ruamel.yaml (preserves comments)
- **Dialog Standards**: All delete confirmations use DeleteConfirmModal, no browser confirm()/alert(), errors displayed within dialogs using local state
- **Audit Logging Gaps**: Review all endpoints, ensure all settings changes are audited

New tables: `login_attempts`, `rule_comments`, `role_permissions`

### 2026-01-22 (Phase 5)

Consolidated user features and enhancements design:

- **Added to v1.0**: API keys, user dropdown, password change, OIDC role mapping, webhook alert URLs, OpenSearch status indicator, log shipper setup info, APP_URL GUI setting
- **Moved from v1.3**: API keys and read-only external API
- **New tables**: `api_keys`
- **New endpoints**: `/auth/me`, `/auth/api-keys`, `/auth/change-password`
- **Updated**: Authentication section with SSO behavior, role mapping configuration
- **Updated**: Environment variables to include encryption key
- **Updated**: Webhook payload to include `alert_url` field
