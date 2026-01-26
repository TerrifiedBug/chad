import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const latencyTrend = new Trend('latency');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const LOG_SHIPPING_SECRET = __ENV.LOG_SHIPPING_SECRET || 'test-secret';
const INDEX_SUFFIX = __ENV.INDEX_SUFFIX || 'windows-sysmon';

// Test stages - ramp up, sustain, ramp down
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 VUs
    { duration: '2m', target: 10 },    // Stay at 10 VUs
    { duration: '30s', target: 50 },   // Ramp up to 50 VUs
    { duration: '2m', target: 50 },    // Stay at 50 VUs
    { duration: '30s', target: 100 },  // Ramp up to 100 VUs
    { duration: '2m', target: 100 },   // Stay at 100 VUs
    { duration: '1m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% of requests under 500ms
    errors: ['rate<0.01'],              // Less than 1% error rate
  },
};

// Generate a realistic sysmon log
function generateLog() {
  const now = new Date().toISOString();
  const processId = Math.floor(Math.random() * 65535);
  const parentProcessId = Math.floor(Math.random() * 65535);

  return {
    '@timestamp': now,
    event: {
      kind: 'event',
      category: ['process'],
      type: ['start'],
    },
    host: {
      name: `workstation-${Math.floor(Math.random() * 1000)}`,
      os: { platform: 'windows', version: '10.0' },
    },
    process: {
      pid: processId,
      name: 'powershell.exe',
      executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      command_line: 'powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0',
      parent: {
        pid: parentProcessId,
        name: 'cmd.exe',
      },
    },
    user: {
      name: 'admin',
      domain: 'CORP',
    },
    source: {
      ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
    },
  };
}

export default function () {
  // Generate batch of logs (NDJSON)
  const batchSize = 10;
  const logs = [];
  for (let i = 0; i < batchSize; i++) {
    logs.push(JSON.stringify(generateLog()));
  }
  const payload = logs.join('\n');

  const params = {
    headers: {
      'Content-Type': 'application/x-ndjson',
      'Authorization': `Bearer ${LOG_SHIPPING_SECRET}`,
    },
  };

  const startTime = Date.now();
  const response = http.post(
    `${BASE_URL}/api/logs/${INDEX_SUFFIX}`,
    payload,
    params
  );
  const duration = Date.now() - startTime;

  // Record metrics
  latencyTrend.add(duration);
  errorRate.add(response.status !== 200);

  // Validate response
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response has matches': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.processed !== undefined;
      } catch {
        return false;
      }
    },
  });

  // Small delay between batches
  sleep(0.1);
}

export function handleSummary(data) {
  return {
    '/results/summary.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const metrics = data.metrics;
  return `
Load Test Results
=================

Requests:
  Total: ${metrics.http_reqs.values.count}
  Rate: ${metrics.http_reqs.values.rate.toFixed(2)}/s

Latency (http_req_duration):
  Avg: ${metrics.http_req_duration.values.avg.toFixed(2)}ms
  P95: ${metrics.http_req_duration.values['p(95)'].toFixed(2)}ms
  Max: ${metrics.http_req_duration.values.max.toFixed(2)}ms

Errors:
  Rate: ${(metrics.errors?.values?.rate * 100 || 0).toFixed(2)}%

Checks:
  Passed: ${data.root_group.checks.reduce((acc, c) => acc + c.passes, 0)}
  Failed: ${data.root_group.checks.reduce((acc, c) => acc + c.fails, 0)}
`;
}
