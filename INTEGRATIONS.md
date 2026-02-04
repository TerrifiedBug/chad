# CHAD Integration Guide

This document describes how external systems can integrate with CHAD through webhooks.

## Custom Enrichment Webhooks

Custom enrichment webhooks allow you to enrich alerts with data from your internal systems (Entra ID, CMDB, HR systems, asset databases, etc.).

### How It Works

1. Configure a webhook endpoint in CHAD Settings → Enrichment
2. Assign the webhook to index patterns with a field to use for lookup
3. When an alert is created, CHAD calls your webhook with alert context
4. Your endpoint returns enrichment data that gets attached to the alert

### Request Format

CHAD sends a `POST` (or `GET`) request to your endpoint with the following JSON payload:

```json
{
  "alert_id": "abc123-def456-...",
  "rule_id": "sigma-rule-uuid",
  "rule_title": "Suspicious PowerShell Execution",
  "severity": "high",
  "lookup_field": "user.name",
  "lookup_value": "jsmith",
  "log_document": {
    "user": {
      "name": "jsmith",
      "domain": "CORP"
    },
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell -enc ..."
    },
    "@timestamp": "2026-02-04T10:30:00Z"
  }
}
```

#### Request Fields

| Field | Type | Description |
|-------|------|-------------|
| `alert_id` | string | Unique identifier for the alert |
| `rule_id` | string | UUID of the Sigma rule that triggered (or `"ioc-detection"` for IOC alerts) |
| `rule_title` | string | Human-readable rule name |
| `severity` | string | Alert severity: `informational`, `low`, `medium`, `high`, `critical` |
| `lookup_field` | string | The field path configured for this webhook (e.g., `user.name`) |
| `lookup_value` | string | The value extracted from the log document to use for lookup |
| `log_document` | object | The full log event that triggered the alert |

### Response Format

Your endpoint should return a JSON object with enrichment data:

```json
{
  "display_name": "John Smith",
  "email": "john.smith@example.com",
  "department": "Engineering",
  "manager": "Jane Doe",
  "title": "Software Engineer",
  "is_privileged": false,
  "risk_score": 25
}
```

#### Response Rules

1. **Must be a JSON object** - Arrays and primitives are not accepted
2. **Fields are stored under your namespace** - If your webhook namespace is `entra_id`, the data appears as `entra_id.display_name`, `entra_id.department`, etc.
3. **Nested objects are supported** - You can return complex structures
4. **Empty object is valid** - Return `{}` if no data is found for the lookup value

### HTTP Status Codes

| Status | CHAD Behavior |
|--------|---------------|
| `200 OK` | Parse JSON response as enrichment data |
| `204 No Content` | Success with no enrichment data |
| `404 Not Found` | Success with no enrichment data (lookup value not found) |
| `4xx/5xx` | Record failure, increment circuit breaker counter |

### Error Responses

For error responses (4xx/5xx), you can optionally include an error message:

```json
{
  "error": "User not found in directory"
}
```

The error message (truncated to 200 chars) will be recorded in the alert's enrichment status.

### Authentication

CHAD supports header-based authentication. Configure:
- **Header Name**: e.g., `Authorization`, `X-API-Key`
- **Header Value**: e.g., `Bearer your-token`, `your-api-key`

The header value is encrypted at rest and decrypted only when making requests.

### Caveats & Best Practices

#### Performance

- **Timeout**: Default 10 seconds. Configure based on your endpoint's response time.
- **Concurrency**: Default 5 concurrent calls. Increase if your endpoint can handle more.
- **Caching**: Configure cache TTL to reduce load. Same lookup values within TTL use cached results.

#### Circuit Breaker

CHAD implements a circuit breaker pattern to protect both CHAD and your endpoint:
- After **5 consecutive failures**, the circuit opens for **60 seconds**
- During this time, all calls to your webhook are skipped
- After 60 seconds, the circuit closes and calls resume

Failures that trigger the circuit breaker:
- HTTP 4xx/5xx responses
- Timeouts
- Connection errors

#### SSRF Protection

URLs are validated to prevent Server-Side Request Forgery:
- Only `http://` and `https://` schemes are allowed
- Internal/private IP ranges are blocked by default
- Localhost URLs are blocked

**For internal infrastructure or development**, set the environment variable:
```bash
ALLOW_INTERNAL_WEBHOOK_IPS=true
```

This allows webhooks to internal networks (10.x, 172.16.x, 192.168.x, localhost). Only enable this if you understand the security implications and trust your internal network.

#### Rate Limiting

The `max_concurrent_calls` setting limits parallel requests to your endpoint. This prevents overwhelming your service during alert storms.

#### Data in Alerts

Enrichment data is stored in the alert's `log_document` under your namespace:

```json
{
  "log_document": {
    "user": { "name": "jsmith" },
    "entra_id": {
      "display_name": "John Smith",
      "department": "Engineering"
    }
  },
  "enrichment_status": {
    "entra_id": {
      "status": "success",
      "completed_at": "2026-02-04T10:30:01Z"
    }
  }
}
```

### Example Implementations

#### Python (FastAPI)

```python
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI()

class EnrichmentRequest(BaseModel):
    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    lookup_field: str
    lookup_value: str
    log_document: dict

# Mock user database
USERS = {
    "jsmith": {
        "display_name": "John Smith",
        "email": "john.smith@example.com",
        "department": "Engineering",
    }
}

@app.post("/enrich/user")
async def enrich_user(
    request: EnrichmentRequest,
    authorization: str = Header(None)
):
    # Validate auth
    if authorization != "Bearer your-secret-token":
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Lookup user
    user = USERS.get(request.lookup_value)
    if not user:
        return {}  # Return empty object if not found

    return user
```

#### Node.js (Express)

```javascript
const express = require('express');
const app = express();
app.use(express.json());

const USERS = {
  'jsmith': {
    display_name: 'John Smith',
    email: 'john.smith@example.com',
    department: 'Engineering',
  }
};

app.post('/enrich/user', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader !== 'Bearer your-secret-token') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { lookup_value } = req.body;
  const user = USERS[lookup_value] || {};
  res.json(user);
});

app.listen(8080);
```

### Troubleshooting

| Issue | Check |
|-------|-------|
| Webhook not called | Is the webhook active? Is it assigned to the index pattern? |
| "Circuit open" status | Your endpoint had 5+ failures. Check endpoint health. |
| "SSRF protection" error | URL points to internal/private IP. Use public endpoint or configure allowed IPs. |
| "Invalid response" error | Endpoint returned non-JSON or non-object response. |
| No enrichment data | Endpoint returned `{}`, `204`, or `404` - this is normal for missing lookups. |
