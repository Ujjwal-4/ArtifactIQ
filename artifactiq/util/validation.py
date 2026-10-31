"""Input validation helpers (form + API payloads)."""
from __future__ import annotations

import re
from datetime import datetime

CASE_NUM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,40}$")
TITLE_RE = re.compile(r"^\S.{0,200}$")


def validate_case_payload(data: dict) -> tuple[dict | None, str | None]:
    if not isinstance(data, dict):
        return None, "Payload must be a JSON object."
    out = {}
    title = (data.get("title") or "").strip()
    if not (3 <= len(title) <= 200) or not TITLE_RE.match(title):
        return None, "Title must be 3-200 characters long."
    investigator = (data.get("investigator") or "").strip()
    if not (2 <= len(investigator) <= 80):
        return None, "Investigator name must be 2-80 characters."
    case_number = (data.get("case_number") or "").strip() or _default_case_number()
    if not CASE_NUM_RE.match(case_number):
        return None, "Case number may contain letters, digits, dot, dash, underscore (3-41 chars)."
    out["title"] = title
    out["investigator"] = investigator
    out["case_number"] = case_number
    desc = (data.get("description") or "").strip()
    if len(desc) > 4000:
        return None, "Description too long (max 4000)."
    scope = (data.get("scope") or "").strip()
    if len(scope) > 4000:
        return None, "Scope too long (max 4000)."
    out["description"], out["scope"] = desc, scope
    authorization = (data.get("authorization") or "").strip()
    if len(authorization) > 2000:
        return None, "Authorization note too long (max 2000)."
    out["authorization"] = authorization
    mode = (data.get("mode") or "full").strip()
    if mode not in {"full", "targeted"}:
        return None, "Mode must be 'full' or 'targeted'."
    capability = (data.get("capability") or "").strip() or None
    if mode == "targeted" and not capability:
        return None, "Targeted mode requires a capability id."
    if capability and capability not in CAPABILITIES:
        return None, f"Unknown capability '{capability}'."
    out["mode"], out["capability"] = mode, capability
    return out, None


def _default_case_number() -> str:
    return "CASE-" + datetime.utcnow().strftime("%Y%m%d-%H%M%S")


CAPABILITIES = {
    "usb_check": "USB device-history check (setupapi.dev.log / .reg)",
    "evtx_check": "Windows event log (.evtx) parse and timeline",
    "browser_check": "Browser history / downloads (SQLite)",
    "integrity_check": "Evidence hash verification and custody review",
    "registry_check": "Registry hive / .reg artifact review",
}
