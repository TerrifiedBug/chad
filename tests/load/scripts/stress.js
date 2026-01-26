/**
 * Stress Test
 *
 * Ramps up load until system degrades to find capacity limits.
 * No thresholds - we want to observe where performance breaks down.
 *
 * Usage:
 *   docker compose run k6 run /scripts/stress.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const latencyTrend = new Trend('latency');
const logsProcessed = new Counter('logs_processed');

// Configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const LOG_SHIPPING_SECRET = __ENV.LOG_SHIPPING_SECRET || 'test-secret';
const INDEX_SUFFIX = __ENV.INDEX_SUFFIX || 'windows-sysmon';

// Stress test: ramp up aggressively to find breaking point
export const options = {
  stages: [
    { duration: '2m', target: 50 },   // Warm up
    { duration: '2m', target: 100 },  // Normal load
    { duration: '2m', target: 200 },  // Above normal
    { duration: '2m', target: 300 },  // High load
    { duration: '2m', target: 400 },  // Very high load
    { duration: '2m', target: 500 },  // Stress load
    { duration: '5m', target: 0 },    // Recovery
  ],
  // No thresholds - we want to find the breaking point
};

// Generate a realistic sysmon log with varying complexity
function generateLog(complexity) {
  const now = new Date().toISOString();
  const processId = Math.floor(Math.random() * 65535);
  const parentProcessId = Math.floor(Math.random() * 65535);

  const baseLog = {
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

  // Add extra fields for higher complexity
  if (complexity > 1) {
    baseLog.destination = {
      ip: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      port: Math.floor(Math.random() * 65535),
    };
    baseLog.network = {
      bytes: Math.floor(Math.random() * 100000),
      packets: Math.floor(Math.random() * 100),
    };
  }

  if (complexity > 2) {
    baseLog.file = {
      path: 'C:\\Windows\\Temp\\suspicious.exe',
      hash: {
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
    };
    baseLog.registry = {
      path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      value: 'malware.exe',
    };
  }

  return baseLog;
}

export default function () {
  // Vary batch size based on current VU count
  const batchSize = 10;
  const complexity = Math.ceil(Math.random() * 3);

  const logs = [];
  for (let i = 0; i < batchSize; i++) {
    logs.push(JSON.stringify(generateLog(complexity)));
  }
  const payload = logs.join('\n');

  const params = {
    headers: {
      'Content-Type': 'application/x-ndjson',
      'Authorization': `Bearer ${LOG_SHIPPING_SECRET}`,
    },
    timeout: '30s',  // Longer timeout for stress conditions
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

  if (response.status === 200) {
    try {
      const body = JSON.parse(response.body);
      logsProcessed.add(body.processed || batchSize);
    } catch {
      logsProcessed.add(batchSize);
    }
  }

  // Validate response
  check(response, {
    'status is 200': (r) => r.status === 200,
    'latency under 1s': (r) => duration < 1000,
    'latency under 5s': (r) => duration < 5000,
  });

  // Minimal delay during stress test
  sleep(0.05);
}

export function handleSummary(data) {
  const metrics = data.metrics;

  // Find the breaking point - where latency or errors spiked
  const p95 = metrics.http_req_duration.values['p(95)'];
  const p99 = metrics.http_req_duration.values['p(99)'];
  const errorPct = (metrics.errors?.values?.rate * 100 || 0);

  let breakingPoint = 'Unknown';
  if (errorPct > 5) {
    breakingPoint = 'Error rate exceeded 5%';
  } else if (p99 > 5000) {
    breakingPoint = 'P99 latency exceeded 5 seconds';
  } else if (p95 > 2000) {
    breakingPoint = 'P95 latency exceeded 2 seconds';
  } else {
    breakingPoint = 'System remained stable at peak load (500 VUs)';
  }

  const summary = `
Stress Test Results
===================

Configuration:
  Peak VUs: 500
  Ramp Pattern: 50 → 100 → 200 → 300 → 400 → 500 → 0
  Total Duration: 17 minutes

Requests:
  Total: ${metrics.http_reqs.values.count}
  Peak Rate: ${metrics.http_reqs.values.rate.toFixed(2)}/s

Latency (http_req_duration):
  Avg: ${metrics.http_req_duration.values.avg.toFixed(2)}ms
  Median: ${metrics.http_req_duration.values.med.toFixed(2)}ms
  P95: ${p95.toFixed(2)}ms
  P99: ${p99.toFixed(2)}ms
  Max: ${metrics.http_req_duration.values.max.toFixed(2)}ms

Errors:
  Rate: ${errorPct.toFixed(2)}%
  Total Failed: ${metrics.http_req_failed?.values?.passes || 0}

Logs Processed:
  Total: ${metrics.logs_processed?.values?.count || 'N/A'}

Breaking Point Analysis:
  ${breakingPoint}

Recommendations:
  ${p95 < 500 ? '✓ P95 latency acceptable' : '⚠ Consider scaling if P95 > 500ms at expected load'}
  ${errorPct < 1 ? '✓ Error rate acceptable' : '⚠ Investigate error sources'}
  ${p99 < 2000 ? '✓ P99 latency acceptable' : '⚠ Long tail latency may need attention'}
`;

  return {
    '/results/stress-summary.json': JSON.stringify(data, null, 2),
    stdout: summary,
  };
}
