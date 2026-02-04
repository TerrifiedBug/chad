# CHAD Development Tools

This directory contains utility scripts and mock servers for development and testing.

## Mock Enrichment Webhook Server

A FastAPI server that simulates external enrichment endpoints for testing CHAD's custom enrichment webhook feature.

### Quick Start

```bash
# Start the mock server using docker compose
docker compose -f docker-compose.dev.yml --profile testing up mock-webhook

# Or run directly in the backend container
docker compose -f docker-compose.dev.yml run --rm -p 8888:8888 backend \
    python /app/tools/mock_enrichment_webhook.py
```

The server runs on port 8888.

### Available Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /enrich/user` | Mock Entra ID / Active Directory user lookup |
| `POST /enrich/asset` | Mock CMDB asset lookup |
| `POST /enrich/hr` | Mock HR system lookup |
| `POST /enrich/slow` | Returns after 15s (for timeout testing) |
| `POST /enrich/error` | Always returns 500 (for circuit breaker testing) |
| `POST /enrich/echo` | Echoes request back (for debugging) |
| `POST /enrich/conditional` | Different response based on alert severity |

### Authentication

All endpoints require:
```
Authorization: Bearer test-webhook-token
```

### Mock Data

**Users** (lookup by username):
- `jsmith` - Regular user in Engineering
- `admin` - Privileged IT admin
- `test_user` - QA team member

**Assets** (lookup by hostname):
- `WORKSTATION-001` - Developer workstation
- `SERVER-DB-01` - Production database server

### Setting Up in CHAD

1. Start the mock server (see Quick Start above)

2. In CHAD Settings → Enrichment → Custom Webhooks, add:
   - **Name**: Mock User Lookup
   - **Namespace**: `mock_user`
   - **URL**: `http://mock-webhook:8888/enrich/user` (or `http://host.docker.internal:8888/enrich/user` if running locally)
   - **Auth Header Name**: `Authorization`
   - **Auth Header Value**: `Bearer test-webhook-token`

3. Assign the webhook to an index pattern:
   - Go to Index Patterns → select a pattern → Webhooks tab
   - Enable the webhook
   - Set "Field to Send" to `user.name` (or appropriate field)

4. Trigger an alert and check the alert detail page for enrichment data

### Example Request/Response

**Request:**
```json
POST /enrich/user
Authorization: Bearer test-webhook-token
Content-Type: application/json

{
  "alert_id": "abc123",
  "rule_id": "sigma-rule-uuid",
  "rule_title": "Suspicious Activity",
  "severity": "high",
  "lookup_field": "user.name",
  "lookup_value": "jsmith",
  "log_document": {...}
}
```

**Response:**
```json
{
  "display_name": "John Smith",
  "email": "john.smith@example.com",
  "department": "Engineering",
  "title": "Senior Software Engineer",
  "manager": "Jane Doe",
  "is_privileged": false
}
```
