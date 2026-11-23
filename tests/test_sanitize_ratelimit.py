"""Output sanitisation and rate limiting."""

from __future__ import annotations

from dawarich_mcp import sanitize as sa
from dawarich_mcp.ratelimit import RateLimiter


def test_clean_text_strips_ansi_and_bidi() -> None:
    nasty = "\x1b[31mHome\x1b[0m\u202eegduj\u200b"
    cleaned = sa.clean_text(nasty, max_len=100)
    assert "\x1b" not in cleaned
    assert "\u202e" not in cleaned
    assert "\u200b" not in cleaned


def test_clean_text_collapses_and_caps() -> None:
    assert sa.clean_text("line1\r\nline2\ttab", max_len=100) == "line1 line2 tab"
    long = sa.clean_text("x" * 300, max_len=50)
    assert len(long) == 50 and long.endswith("…")


def test_clean_float_bounds() -> None:
    assert sa.clean_float(52.5, *sa.LAT_RANGE) == 52.5
    assert sa.clean_float(999.0, *sa.LAT_RANGE) is None
    assert sa.clean_float("52", *sa.LAT_RANGE) is None
    assert sa.clean_float(True, *sa.LAT_RANGE) is None


def test_clean_timestamp_shape() -> None:
    assert sa.clean_timestamp("2026-11-23T21:30:00Z") == "2026-11-23T21:30:00Z"
    assert sa.clean_timestamp("not a date") is None
    assert sa.clean_timestamp(None) is None


def test_rate_limiter_burst_then_refill() -> None:
    clock = [0.0]
    limiter = RateLimiter(rate_per_minute=60, burst=2, clock=lambda: clock[0])
    assert limiter.acquire("a") == 0.0
    assert limiter.acquire("a") == 0.0
    assert limiter.acquire("a") > 0  # bucket drained
    clock[0] += 5.0  # five seconds -> ~5 tokens, above burst cap of 2
    assert limiter.acquire("a") == 0.0


def test_rate_limiter_is_per_key() -> None:
    limiter = RateLimiter(rate_per_minute=60, burst=1, clock=lambda: 0.0)
    assert limiter.acquire("a") == 0.0
    assert limiter.acquire("a") > 0
    assert limiter.acquire("b") == 0.0
