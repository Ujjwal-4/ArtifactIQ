"""IDs and small string/format helpers."""
from __future__ import annotations

import html
import re
import uuid
from datetime import datetime, timezone


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_EMAILISH = re.compile(r"@")
_REDACT = re.compile(r"https?://\S+", re.IGNORECASE)


def redact_url(u: str) -> str:
    """Used only when sending derived data to an explicitly configured LLM."""
    if not u:
        return u
    return _REDACT.sub("<redacted-url>", u)


def truncate(s, n: int) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def clamp(v: float, lo: float, hi: float) -> int:
    return max(lo, min(hi, int(round(v))))


def display_size(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n} B"


def safe_int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def strip_html(s: str) -> str:
    return html.escape(str(s or ""), quote=True)
