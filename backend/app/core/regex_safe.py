"""Timeout-bounded regex matching to prevent ReDoS on the ingest hot path.

User-supplied patterns (rule-exception REGEX operators, Sigma wildcard values)
are matched against attacker-controlled log content. Python's stdlib ``re`` has
no timeout and is vulnerable to catastrophic backtracking, so a single crafted
pattern (e.g. ``(a+)+``) against an adversarial log can peg a worker.

The third-party ``regex`` module is API-compatible with ``re`` and supports a
per-call ``timeout``. We use it and fail *closed* (no match) when a pattern
exceeds its budget: for a detection platform, a regex that cannot be evaluated
must not be allowed to silently suppress alerts, so "no match" is the safe
direction (an exception that times out does not suppress; a Sigma wildcard that
times out does not match).
"""

import logging
from functools import lru_cache

import regex

logger = logging.getLogger(__name__)

# Per match-attempt wall-clock budget. Typical patterns evaluate in well under a
# millisecond; anything approaching this is almost certainly pathological.
DEFAULT_REGEX_TIMEOUT = 1.0


@lru_cache(maxsize=2048)
def _compile(pattern: str, flags: int):
    """Compile and cache a pattern. lru_cache is thread-safe and compiled
    patterns are safe to share across the asyncio.to_thread worker threads."""
    return regex.compile(pattern, flags)


def safe_search(
    pattern: str,
    text: str,
    *,
    flags: int = 0,
    timeout: float = DEFAULT_REGEX_TIMEOUT,
) -> bool:
    """Return True if ``pattern`` is found anywhere in ``text``, bounded by ``timeout``.

    Never raises. Returns False on an invalid pattern or a timeout (likely
    ReDoS), so a malicious or pathological pattern cannot hang the caller or
    silence detections.
    """
    try:
        compiled = _compile(pattern, flags)
    except regex.error:
        return False

    try:
        return compiled.search(text, timeout=timeout) is not None
    except TimeoutError:
        # Pattern digest only — never log the raw (attacker-influenced) pattern.
        logger.warning(
            "Regex match timed out after %.1fs (possible ReDoS); treating as no-match",
            timeout,
        )
        return False
    except Exception as e:  # defensive: any engine-level error -> no match
        logger.warning("Regex match failed: %s", type(e).__name__)
        return False
