"""Audit trail: append-only record of administrative/security-relevant actions.

The local audit table is evidence of what the application did. Like the
custody ledger it is not, by itself, an immutable cryptographic record.
"""
from __future__ import annotations

from flask import has_request_context, request, current_app

from ..db import insert
from ..util.ids import now_iso


def audit(action: str, target: str = "", detail: str = "", actor: str = "user") -> None:
    entry = {
        "ts": now_iso(),
        "actor": actor,
        "action": action,
        "target": target,
        "detail": detail,
        "ip": request.remote_addr if has_request_context() and request else "",
    }
    try:
        insert("audit_events", entry)
    except Exception:  # noqa: BLE001 - auditing must never break the request
        if has_request_context():
            current_app.logger.exception("audit write failed")
