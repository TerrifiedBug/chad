# Load Tests

Performance testing for CHAD log ingestion.

## Quick Start (Recommended)

The `run-tests.sh` script handles fixture setup and cleanup automatically:

```bash
# Run from load-tests directory
cd load-tests

# Run baseline test (5 min, 10 VUs)
./run-tests.sh baseline

# Run log-ingestion test (9 min, up to 100 VUs)
./run-tests.sh log-ingestion

# Run stress test (17 min, up to 500 VUs)
./run-tests.sh stress

# Run all tests sequentially
./run-tests.sh all
```

**Prerequisites:**
- Backend must be running: `docker compose -f docker-compose.dev.yml up -d`
- The script creates a temporary index pattern with auth token `test-secret`

## Manual Testing

If you need to run tests manually (e.g., with custom settings):

```bash
# 1. Setup test fixtures first
docker compose -f ../docker-compose.dev.yml cp \
  scripts/setup-test-fixtures.py backend:/tmp/setup-test-fixtures.py
docker compose -f ../docker-compose.dev.yml exec backend \
  python /tmp/setup-test-fixtures.py setup

# 2. Run k6 test
docker compose run k6 run /scripts/log-ingestion.js

# 3. Cleanup when done
docker compose -f ../docker-compose.dev.yml exec backend \
  python /tmp/setup-test-fixtures.py teardown
```

### Custom Settings

```bash
# With custom base URL and secret
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
