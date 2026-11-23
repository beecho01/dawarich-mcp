"""Sanitisation of every value that reaches a tool result.

Visit names, places, cities and countries in Dawarich are user-editable text
(and, for reverse-geocoded labels, third-party data), so they are untrusted
input that ends up in a language model's context (indirect prompt injection)
and often in a terminal. Strings are scrubbed of control characters, ANSI/OSC
escape sequences, bidirectional overrides and zero-width characters, collapsed
to one line and length-capped. Values with a known shape (timestamps,
coordinates, distances) are validated against that shape and dropped if they
do not fit.
"""

from __future__ import annotations

import re
import unicodedata

# CSI (ESC [ ... final), OSC (ESC ] ... BEL or ST) and other two-byte ESC sequences.
_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[@-Z\\-_]"
)

# Cc control, Cf format (bidi overrides, zero-width), Cs surrogate, Co private use,
# Cn unassigned, Zl/Zp line/paragraph separators.
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_TIMESTAMP_RE = re.compile(r"^[0-9T:.+\-Z ]{10,40}$")
_MONTH_RE = re.compile(r"^[A-Za-z]{3,9}$")

# Coordinates on Earth; anything else is a data error and is dropped.
LAT_RANGE = (-90.0, 90.0)
LON_RANGE = (-180.0, 180.0)


def clean_text(value: str, *, max_len: int) -> str:
    """Return a single-line, printable version of ``value`` capped at ``max_len``."""
    value = _ANSI_RE.sub("", value)
    out: list[str] = []
    for ch in unicodedata.normalize("NFC", value):
        if ch.isspace():  # line breaks, tabs and Unicode spaces become plain word separators
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP_CATEGORIES:
            out.append(ch)
    text = " ".join("".join(out).split())
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def clean_optional_text(value: object, *, max_len: int) -> str | None:
    """``clean_text`` for values that may be missing or of the wrong type."""
    if not isinstance(value, str):
        return None
    return clean_text(value, max_len=max_len) or None


def clean_identifier(value: object) -> str | None:
    """Opaque upstream identifiers (place ids, visit ids): short, ASCII, no spaces."""
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value):
        return value
    return None


def clean_timestamp(value: object) -> str | None:
    """Pass an ISO 8601 timestamp through unmodified if it is one, else None.

    Timestamps are user data (their own history), so a valid value is returned
    exactly as received rather than re-formatted.
    """
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        return None
    return value


def clean_float(value: object, lo: float, hi: float) -> float | None:
    """A finite number within [lo, hi]; anything else (NaN, inf, strings) is dropped."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        return None
    if lo <= number <= hi:
        return number
    return None


def clean_month(value: object) -> str | None:
    """Month names like ``october`` or ``Oct``."""
    if isinstance(value, str) and _MONTH_RE.fullmatch(value.strip()):
        return value.strip().lower()[:9]
    return None
