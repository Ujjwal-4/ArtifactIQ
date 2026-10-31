"""Timestamp normalization.

Rules (Phase 4):
- Store UTC when and only when a well-defined UTC/offset is available.
- Keep the original string and the precision; never invent data.
- Missing timestamps stay missing: no "now" fallbacks.
"""
from __future__ import annotations

from datetime import datetime, timezone


def to_utc_iso(dt: datetime) -> str | None:
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, OverflowError, OSError):
        return None


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def internal_ms(dt: datetime) -> int | None:
    """Integer milliseconds since epoch for a tz-aware datetime (or None)."""
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(round((dt - _EPOCH).total_seconds() * 1000))
    except (ValueError, OverflowError, OSError):
        return None


def parse_common(s: str) -> tuple[datetime | None, str | None, str]:
    """Parse a few common artifact timestamp formats.

    Returns (datetime | None, precision, tcp_source_note). Never guesses a
    timezone: naive strings are treated as local-unparsed and are NOT converted.
    """
    if not s or not s.strip():
        return None, None, "unknown"
    s = s.strip()
    # Windows FILETIME-like 18-digit integers are handled by their parsers.
    formats = [
        ("%Y-%m-%dT%H:%M:%S.%fZ", "utc", "string_utc"),
        ("%Y-%m-%dT%H:%M:%SZ", "utc", "string_utc"),
        ("%Y-%m-%dT%H:%M:%S.%f", "unknown", "string_naive"),
        ("%Y-%m-%dT%H:%M:%S", "unknown", "string_naive"),
        ("%Y-%m-%d %H:%M:%S", "unknown", "string_naive"),
        ("%m/%d/%Y %H:%M:%S", "unknown", "string_naive"),
        ("%d/%m/%Y %H:%M:%S", "ambiguous", "string_ambiguous"),
    ]
    for fmt, prec, src in formats:
        try:
            dt = datetime.strptime(s, fmt)
            if src == "string_ambiguous":
                return None, "ambiguous", "ambiguous_day_month"
            if fmt.endswith("Z") and dt.tzinfo is None:
                # the trailing 'Z' in the artifact itself declares UTC
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, prec, src
        except ValueError:
            continue
    return None, "unparsed", "unparsed_format"


def filetime_to_dt(value: int) -> datetime | None:
    """Windows FILETIME (1601-01-01 epoch, 100ns units) to datetime UTC."""
    try:
        if value <= 0:
            return None
        return _EPOCH + __import__("datetime").timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None


def dt_from_chrome_ms(value):  # Chrome epoch microseconds offset
    try:
        v = int(value)
        if v <= 0:
            return None
        return _EPOCH + __import__("datetime").timedelta(microseconds=v - 11644473600000000)
    except (TypeError, ValueError, OverflowError):
        return None


def iso_now() -> str:
    return to_utc_iso(datetime.now(timezone.utc))
