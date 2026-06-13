"""Prometheus pipeline metrics.

Exposes the throughput / latency / loss signals an operator needs to confirm
CHAD is keeping up with real-time detection at scale (e.g. ~2 TB/day). All
metrics are registered on the default prometheus_client registry and rendered by
the /metrics endpoint.
"""

from prometheus_client import Counter, Histogram

# Events received for detection, per index pattern.
ingest_events_total = Counter(
    "chad_ingest_events_total",
    "Log events received for detection",
    ["index_pattern"],
)

# Alerts created, per index pattern.
ingest_alerts_total = Counter(
    "chad_ingest_alerts_total",
    "Alerts created from detections",
    ["index_pattern"],
)

# Batches that failed processing (left unacknowledged for retry) — non-zero means
# the pipeline is shedding/retrying and may be falling behind.
ingest_batch_failures_total = Counter(
    "chad_ingest_batch_failures_total",
    "Log batches that failed processing",
    ["index_pattern"],
)

# End-to-end batch processing time (percolate + enrich + write), per index pattern.
batch_processing_seconds = Histogram(
    "chad_batch_processing_seconds",
    "Time to process one log batch end to end",
    ["index_pattern"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)


def record_batch(index_pattern: str, events: int, alerts: int, seconds: float) -> None:
    """Record metrics for a successfully processed batch. Never raises."""
    try:
        label = index_pattern or "unknown"
        if events:
            ingest_events_total.labels(label).inc(events)
        if alerts:
            ingest_alerts_total.labels(label).inc(alerts)
        batch_processing_seconds.labels(label).observe(seconds)
    except Exception:  # metrics must never break ingestion
        pass


def record_batch_failure(index_pattern: str) -> None:
    """Record a failed batch. Never raises."""
    try:
        ingest_batch_failures_total.labels(index_pattern or "unknown").inc()
    except Exception:
        pass
