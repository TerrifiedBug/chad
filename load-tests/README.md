# Load Tests

Performance testing for CHAD log ingestion.

## Running Tests

```bash
# Basic test
docker compose run k6 run /scripts/log-ingestion.js

# With custom settings
docker compose run -e BASE_URL=http://host.docker.internal:8000 \
  -e LOG_SHIPPING_SECRET=your-secret \
  k6 run /scripts/log-ingestion.js

# With metrics (InfluxDB + Grafana)
docker compose --profile metrics up -d
docker compose run k6 run /scripts/log-ingestion.js

# View Grafana at http://localhost:3001
```

## Test Scripts

| Script | Description |
|--------|-------------|
| `log-ingestion.js` | Main load test - ramps 10→50→100 VUs over 9 minutes |
| `baseline.js` | Steady-state test - 10 VUs for 5 minutes |
| `stress.js` | Stress test - ramps to 500 VUs to find breaking point |

## Metrics

Key metrics to monitor:
- `http_req_duration` - Request latency
- `http_reqs` - Requests per second
- `errors` - Error rate

## Thresholds

Default thresholds:
- P95 latency < 500ms
- Error rate < 1%

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | `http://localhost:8000` | Backend API URL |
| `LOG_SHIPPING_SECRET` | `test-secret` | Log shipping auth token |
| `INDEX_SUFFIX` | `windows-sysmon` | Index pattern suffix |

## Results

Results are saved to `./results/`:
- `results.json` - Raw k6 metrics
- `summary.json` - Summary statistics
