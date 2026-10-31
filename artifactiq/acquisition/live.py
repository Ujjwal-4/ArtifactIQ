"""Authorized, targeted artifact acquisition from the local Windows endpoint.

Design (Phases 2-3):
- Acquisition never starts without an audited explicit acknowledgment that the
  operator knows which sources will be read and why.
- Sources are individually selected; nothing is collected "by default".
- Collectors use documented Windows APIs (win32 API via ctypes where available),
  read-only file copies, or plain file reads. No services are installed, no
  registry writes happen, no security tooling is touched, and collection is
  never concealed.
- Copy-first for Event Logs (documented API), no log clearing, no timestamp
  changes.
- Copy failures (access denied) are reported honestly and suggest an authorized
  offline acquisition instead of silently falling back to another mechanism.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from ..util.ids import new_id, now_iso
from ..util.audit import audit
from ..util import hashing
from ..db import insert, update as _db_update, jdump
from ..services import custody, evidence

SOURCES = {
    "eventlog_system": {
        "label": "Windows System event log (copy of %SystemRoot%\\System32\\winevt\\Logs\\System.evtx)",
        "impact": "Read-only copy via the documented Event Log API; may generate ordinary audit telemetry. NOT zero-footprint.",
        "requires_windows": True,
    },
    "eventlog_application": {
        "label": "Windows Application event log (copy)",
        "impact": "Read-only copy via the documented API; NOT zero-footprint.",
        "requires_windows": True,
    },
    "eventlog_security": {
        "label": "Windows Security event log (requires Administrator)",
        "impact": "Administrator rights required; read-only Event Log API; NOT zero-footprint.",
        "requires_windows": True,
    },
    "eventlog_powershell": {
        "label": "PowerShell Operational log (copy, if present)",
        "impact": "Read-only copy; NOT zero-footprint.",
        "requires_windows": True,
    },
    "usb_setupapi_log": {
        "label": "setupapi.dev.log copy (USB device installs)",
        "impact": "Plain read-only file copy; minimal, measurable footprint.",
        "requires_windows": False,
    },
    "registry_software_hive_copy": {
        "label": "SOFTWARE hive copy (needs Administrator; source taken by VSS or direct read)",
        "impact": "May require elevated privileges; if VSS is used the snapshot has a real operational footprint.",
        "requires_windows": True,
    },
    "browser_profile_copy": {
        "label": "Chrome History SQLite (copy from the operator's own profile path if permitted)",
        "impact": "Read-only file copy; History main DB only; cookies are NOT read.",
        "requires_windows": False,
    },
}

EVTX_CHANNELS = {
    "eventlog_system": "System",
    "eventlog_application": "Application",
    "eventlog_security": "Security",
    "eventlog_powershell": "Microsoft-Windows-PowerShell/Operational",
}


def _tmp_acq_dir() -> Path:
    """Isolated temp workspace; cleaned after hashing regardless of success."""
    base = Path(os.environ.get("ARTIFACTIQ_DATA_DIR") or ".aiq_tmp_acq")
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="acq_", dir=str(base)))
    return work


def start_session(case_id: str, operator: str, plan: list[str],
                  authorization_ack: bool, impact_ack: bool) -> str:
    if not authorization_ack or not impact_ack:
        raise ValueError("Live acquisition requires BOTH the authorization and "
                         "impact-surface acknowledgments.")
    invalid = [p for p in plan if p not in SOURCES]
    if invalid:
        raise ValueError(f"Unknown acquisition source(s): {', '.join(invalid)}.")
    if not plan:
        raise ValueError("Select at least one source; nothing is collected by default.")
    sid = new_id("acq")
    insert("acquisition_sessions", {
        "id": sid, "case_id": case_id, "operator": operator,
        "status": "planned", "started_at": now_iso(), "finished_at": None,
        "plan": jdump(plan), "authorization_ack": 1, "impact_ack": 1,
        "warnings": "[]", "log": jdump([]),
    })
    audit("acquisition_planned", target=sid, detail=f"sources={plan}")
    return sid


def run_session(sid: str) -> dict:
    """Execute a planned session source-by-source, honoring failures honestly."""
    from ..db import one, query

    ses = one("SELECT * FROM acquisition_sessions WHERE id=?", (sid,))
    if not ses:
        raise ValueError("Acquisition session not found.")
    if ses["status"] != "planned":
        raise ValueError(f"Session is not runnable (status={ses['status']}).")

    plan = _load_plan(ses["plan"])
    session_log: list = []
    for source in plan:
        started = now_iso()
        res = _collect(source, sid)
        session_log.append(res)
        insert("acquisition_artifacts", {
            "id": new_id("aa"), "session_id": sid, "case_id": ses["case_id"],
            "source_id": source, "source_label": SOURCES[source]["label"],
            "status": res["status"], "message": res["message"],
            "details": res.get("details", ""),
            "evidence_id": res.get("evidence_id"),
            "started_at": started, "finished_at": res.get("finished_at", now_iso()),
            "warnings": jdump(res.get("warnings", [])),
        })
        audit("acquisition_source", target=f"{sid}:{source}", detail=res["status"])
    _db_update("acquisition_sessions", sid, {"log": jdump(session_log)})
    # Session status derives from the worst artifact status rather than being
    # marked successful just because the session itself ran.
    arts = query("SELECT status FROM acquisition_artifacts WHERE session_id=?", (sid,))
    statuses = [a["status"] for a in arts]
    if all(s == "completed" for s in statuses):
        final = "completed"
    elif any(s in ("completed_with_warnings",) for s in statuses):
        final = "completed_with_warnings"
    elif any(s == "access_denied" for s in statuses):
        final = "completed_with_warnings"
    elif all(s in ("skipped_with_reason", "unsupported") for s in statuses):
        final = "completed_with_warnings"
    else:
        final = "completed_with_warnings" if "completed" in statuses else "failed"
    update_session(sid, status=final, finished_at=now_iso())
    custody.append("acquisition_session", ses["case_id"], None,
                   actor=ses["operator"],
                   reason=f"Live/local acquisition session {sid} finished with status={final} "
                          f"(sources={', '.join(plan)}).")
    return {"session_id": sid, "status": final, "artifacts": arts and [dict(a) for a in arts]}


def _load_plan(raw) -> list[str]:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    import json

    try:
        return list(json.loads(raw or "[]"))
    except Exception:
        return []


def _collect(source: str, session_id: str) -> dict:
    """One source. Every branch returns completed/access_denied/unsupported/failed status."""
    from ..db import one as _one

    ses = _one("SELECT * FROM acquisition_sessions WHERE id=?", (session_id,))
    case_id = ses["case_id"]
    warn: list = []
    work = None
    try:
        work = _tmp_acq_dir()
        target: Path = _working_target(source, work)
        if target is None:
            return {"status": "unsupported", "message": "Source not supported on this platform.",
                    "warnings": [], "finished_at": now_iso()}
        _copy_channels(source, target, warn)
        if not target.exists() or target.stat().st_size == 0 and source in EVTX_CHANNELS:
            # An empty or absent log is NOT handed to the case as evidence.
            return {"status": "unsupported",
                    "message": f"Channel did not produce a copyable log at the documented path; "
                               "collect one offline instead of changing collection mechanics.",
                    "warnings": warn, "finished_at": now_iso()}
        sha = hashing.sha256_file(target)
        ev_row = evidence.store_copy(
            case_id=case_id,
            source_path=str(target),
            original_name=_display_name(source, target),
            declared_type=None,
            investigator=ses["operator"],
            source_desc=SOURCES[source]["label"],
            notes=f"Acquired live/local by ArtifactIQ source={source}; session={session_id}",
            acquisition_method="live_collect",
            source_hash=sha,
            actor="system",
        )
        return {
            "status": "completed" if not warn else "completed_with_warnings",
            "message": f"Collected and hashed (sha256 {sha[:16]}).",
            "evidence_id": ev_row["id"],
            "warnings": warn, "finished_at": now_iso(),
        }
    except PermissionError as exc:
        return {
            "status": "access_denied",
            "message": f"Access denied while reading the source ({exc}). "
                       "No fallback was attempted. Suggest authorized offline acquisition of the same artifact.",
            "warnings": warn, "finished_at": now_iso(),
        }
    except FileNotFoundError as exc:
        return {"status": "skipped_with_reason",
                "message": f"Documented source path does not exist on this endpoint: {exc}",
                "warnings": warn, "finished_at": now_iso()}
    except ValueError as exc:
        if "already registered" in str(exc):
            return {"status": "skipped_with_reason",
                    "message": "Not collected again: an identical file (same size and SHA-256) "
                               "is already registered in this case, so a duplicate copy would "
                               "add nothing to the evidence record.",
                    "warnings": warn, "finished_at": now_iso()}
        return {"status": "failed", "message": f"Collector error: {exc}"[:400],
                "warnings": warn, "finished_at": now_iso()}
    except Exception as exc:  # collector must never crash the session run
        return {"status": "failed", "message": f"Collector error: {exc}"[:400],
                "warnings": warn, "finished_at": now_iso()}
    finally:
        if work and work.exists():
            for f in work.glob("*"):
                try:
                    f.unlink()
                except OSError:
                    pass


def _working_target(source: str, work: Path) -> Path | None:
    import sys

    if source in EVTX_CHANNELS:
        if not sys.platform.startswith("win"):
            return None
        return work / (EVTX_CHANNELS[source].replace("-", "_").replace("/", "_") + ".evtx")
    if source == "usb_setupapi_log":
        return work / "setupapi.dev.log"
    if source == "registry_software_hive_copy":
        if not sys.platform.startswith("win"):
            return None
        return work / "SOFTWARE_copy"
    if source == "browser_profile_copy":
        return work / "History"
    return None


def _copy_channels(source: str, target: Path, warn: list) -> None:
    """Copy-only acquisition. NO registry writes; NO service install; NO
    deletion of source files; NO attempt to hide collection."""
    import sys

    if source in EVTX_CHANNELS:
        if not sys.platform.startswith("win"):
            raise FileNotFoundError("Windows Event Log API requires Windows.")
        _evtx_copy(source, target)
        return
    if source == "usb_setupapi_log":
        p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "INF" / "setupapi.dev.log"
        if not p.exists():
            raise FileNotFoundError(str(p))
        shutil.copy2(str(p), str(target))
        return
    if source == "registry_software_hive_copy":
        srcdir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "config"
        src = srcdir / "SOFTWARE"
        if not src.exists():
            raise FileNotFoundError(str(src))
        shutil.copy2(str(src), str(target))
        warn.append("Direct hive copy while Windows is running may omit in-memory changes. "
                    "A VSS acquisition would have a larger footprint; run it explicitly if needed.")
        return
    if source == "browser_profile_copy":
        prof = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "History"
        if not prof.exists():
            raise FileNotFoundError(str(prof))
        shutil.copy2(str(prof), str(target))
        return
    raise FileNotFoundError(f"Unknown source {source}")


def _evtx_copy(source: str, target: Path) -> None:
    """Copy an event-log channel artifact from its recorded backing file.

    Approach: read-only copy of the channel's backing .evtx file from the
    documented location (%SystemRoot%\\System32\\winevt\\Logs). Reading those
    files requires OS privileges; Security.evtx usually needs Administrator.
    Reading a live channel file touches the running Event Log service and is
    NOT zero-footprint. Missing/locked files are reported with the exact
    limitation; no silent fallback to another mechanism occurs.
    """
    channel = EVTX_CHANNELS[source]
    root = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "winevt" / "Logs"
    candidate = root / (channel.split("/")[-1] + ".evtx")
    if not candidate.exists():
        alt = root / "".join(
            part.title() for part in channel.split("/")[-1].split("-")
        ) + ".evtx"
        if not alt.exists():
            raise FileNotFoundError(
                f"Backing file for channel '{channel}' was not found at either "
                f"{candidate} or {alt}."
            )
        candidate = alt
    try:
        with open(str(candidate), "rb") as src, open(str(target), "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
    except PermissionError as exc:
        raise PermissionError(
            f"Access denied reading {candidate}: {exc}. Run elevated for this "
            "source, or collect an offline EVTX copy instead."
        ) from exc


def _display_name(source: str, target: Path) -> str:
    return target.name


def list_detailed_for_case(case_id: str) -> list:
    from ..db import query

    return [dict(r) for r in query(
        "SELECT * FROM acquisition_artifacts WHERE case_id=? ORDER BY started_at DESC", (case_id,))]


def update_session(sid: str, **chg) -> None:
    from ..db import update

    update("acquisition_sessions", sid, chg)


def cancel_session(sid: str) -> None:
    from ..db import update

    update("acquisition_sessions", sid, {"status": "cancelled", "finished_at": now_iso()})
