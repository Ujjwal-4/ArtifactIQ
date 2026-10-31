"""Parser orchestration: run parsers against evidence, persist normalized events.

Guarantees:
- One corrupt evidence file never aborts the whole case.
- The same dedupe_key is not inserted twice from the same evidence (parser
  re-run is idempotent).
- Missing/unreadable timestamps are preserved, never fabricated.
"""
from __future__ import annotations

import hashlib
import time

from ..db import insert, insert_many, query, one, jdump
from ..util.ids import new_id, now_iso, safe_int
from ..util.audit import audit
from . import custody
from ..parsers import all_parsers, parsers_for_media, parser_by_name, PARSER_VERSION
from ..config import Config
import json


def _dedupe_key(evidence_id: str, ev: dict) -> str:
    material = "|".join([
        evidence_id,
        str(ev.get("raw_ref") or ""),
        str(ev.get("event_type") or ""),
        str(ev.get("ts_utc") or ""),
        str(ev.get("event_code") or ""),
    ])
    return hashlib.sha256(material.encode()).hexdigest()


def run_parser(evidence_row, parser_name: str = "", incremental: bool = True) -> dict:
    """Parse one evidence item. Returns the parser_run row (dict)."""
    from .evidence import abs_path_of

    media = evidence_row["media_type"]
    if parser_name:
        chosen = [p for p in [parser_by_name(parser_name)] if p and media in p.media_types]
        if not chosen and parser_by_name(parser_name):
            skip = True
            impl = parser_by_name(parser_name)
            detail = {
                "reason": f"Parser '{parser_name}' cannot handle media '{media}'.",
            }
            run = _persist_run(evidence_row, impl or parser_by_name(parser_name),
                               "skipped", 0, 0, 0, [], [],
                               detail, finished=True)
            return run
    else:
        chosen = parsers_for_media(media)
    if incremental:
        prior = query(
            "SELECT run_id FROM events WHERE evidence_id=? LIMIT 1", (evidence_row["id"],))
        if prior and not parser_name:
            run = _persist_run(evidence_row, chosen[0] if chosen else None,
                              "skipped", 0, 0, 0, [], [],
                              {"reason": "Evidence already parsed (idempotent re-run). Use force flag to re-parse."}, finished=True)
            return run

    if not chosen:
        detail = {
            "reason": f"No parser is implemented for media type '{media}'. Evidence preserved intact.",
        }
        run = _persist_run(evidence_row, None, "unsupported", 0, 0, 0, [], [], detail, finished=True)
        return run

    impl = chosen[0]
    try:
        path = abs_path_of(evidence_row["data_path"])
    except ValueError as exc:
        run = _persist_run(evidence_row, impl, "failed", 0, 0, 0, [], [],
                           {"reason": f"stored path could not be resolved safely: {exc}"}, finished=True)
        return run

    limit = Config.MAX_EVENTS_PER_EVIDENCE
    started = now_iso()
    t0 = time.time()
    try:
        if not hasattr(impl, "parse"):
            raise RuntimeError(f"Parser '{impl.name}' is not a BaseParser subclass.")
        outcome = impl.parse(path, evidence_row, limit)
        if impl.needs and media in getattr(impl, "media_types", ()) and impl.name == "evtx" and not outcome.errors:
            pass
    except Exception as exc:  # parse-time failure: never crash the request
        dur = round(time.time() - t0, 2)
        run_id = new_id("run")
        run = {
            "id": run_id, "case_id": evidence_row["case_id"], "evidence_id": evidence_row["id"],
            "parser": impl.name, "parser_version": PARSER_VERSION, "status": "failed",
            "started_at": started, "finished_at": now_iso(), "events_added": 0,
            "events_skipped": 0, "errors": 1, "warnings": 0,
            "message": f"Parser raised {type(exc).__name__}: {exc}"[:500],
            "detail": jdump({"duration_s": dur, "errors": [{"raw_ref": "file", "message": str(exc)[:400]}]}),
        }
        insert("parser_runs", run)
        return run
    dur = round(time.time() - t0, 2)
    status = outcome.status if outcome.events or outcome.errors else "unsupported"
    if outcome.events and not outcome.errors:
        status = "completed"
    detail = {
        "duration_s": dur,
        "errors": outcome.errors[:50],
        "warnings": outcome.warnings[:50],
        "parser": impl.name,
        "parsers_tried": [c.name for c in chosen],
        "needs": impl.needs,
    }
    run = _persist_events(evidence_row, impl, status, outcome.events, detail)
    return run


def _persist_events(evidence_row, impl, status, events, detail) -> dict:
    run_id = new_id("run")
    insert_ids = 0
    skipped_dupes = 0
    rows = []
    seen = set()
    case_id = evidence_row["case_id"]
    ev_id = evidence_row["id"]
    for ev in events:
        dk = _dedupe_key(ev_id, ev)
        if dk in seen:
            skipped_dupes += 1
            continue
        seen.add(dk)
        eid = new_id("n")
        rows.append({
            "id": eid, "case_id": case_id, "evidence_id": ev_id, "run_id": run_id,
            "ts_utc": ev.get("ts_utc"), "ts_original": ev.get("ts_original"),
            "ts_precision": ev.get("ts_precision"), "ts_source": ev.get("ts_source"),
            "event_type": ev.get("event_type") or "unknown",
            "category": ev.get("category") or "other",
            "channel": ev.get("channel"), "provider": ev.get("provider"),
            "event_code": ev.get("event_code"), "record_id": ev.get("record_id"),
            "hostname": ev.get("hostname"), "username": ev.get("username"),
            "user_sid": ev.get("user_sid"),
            "process_name": ev.get("process_name"), "process_id": ev.get("process_id"),
            "parent_process_id": ev.get("parent_process_id"),
            "command_line": ev.get("command_line"),
            "source_ip": ev.get("source_ip"), "destination_ip": ev.get("destination_ip"),
            "source_path": ev.get("source_path"), "destination_path": ev.get("destination_path"),
            "raw_ref": ev.get("raw_ref"), "parser": ev.get("parser") or impl.name,
            "parser_version": ev.get("parser_version") or PARSER_VERSION,
            "parse_status": ev.get("parse_status") or "ok",
            "confidence": ev.get("confidence"), "tags": jdump(ev.get("tags") or []),
            "dedupe_key": dk, "created_at": now_iso(),
        })
        insert_ids += 1
    if rows:
        insert_many("events", rows)
    run = {
        "id": run_id, "case_id": case_id, "evidence_id": ev_id,
        "parser": impl.name if impl else "none", "parser_version": PARSER_VERSION,
        "status": status, "started_at": now_iso(), "finished_at": now_iso(),
        "events_added": insert_ids, "events_skipped": skipped_dupes,
        "errors": len(detail.get("errors", [])), "warnings": len(detail.get("warnings", [])),
        "message": detail.get("reason", ""),
        "detail": jdump(detail),
    }
    insert("parser_runs", run)
    if run["status"] == "completed":
        custody.append("parser_run", case_id, ev_id, actor="system",
                       reason=f"Parser '{run['parser']}' normalized {insert_ids} events "
                              f"({skipped_dupes} duplicates skipped).")
    elif run["status"] in ("completed_with_errors", "failed", "unsupported", "skipped"):
        custody.append("parser_run_notice", case_id, ev_id, actor="system",
                       reason=f"Parser '{run['parser']}' status={status}: {run['message'][:160]}")
    audit("parser_run", target=ev_id, detail=f"{run['parser']}:{status}:{insert_ids}")
    return run


def _persist_run(evidence_row, parser, status, added, errors, warnings, _e, _w, detail, finished=True) -> dict:
    run = {
        "id": new_id("run"), "case_id": evidence_row["case_id"],
        "evidence_id": evidence_row["id"],
        "parser": parser.name if parser else "none", "parser_version": PARSER_VERSION,
        "status": status, "started_at": now_iso(), "finished_at": now_iso() if finished else None,
        "events_added": added, "events_skipped": 0, "errors": errors, "warnings": warnings,
        "message": detail.get("reason", ""), "detail": jdump(detail),
    }
    insert("parser_runs", run)
    return run


def run_all_parsers(case_id: str) -> dict:
    # media whose real analysis lives in a dedicated phase, not a timeline parser
    delegated_media = {"disk_image": "phase 6 disk-image analysis (real Sleuth Kit engine)"}
    evs = query("SELECT * FROM evidence WHERE case_id=? ORDER BY created_at", (case_id,))
    results = []
    for ev in evs:
        if ev["media_type"] in delegated_media:
            reason = delegated_media[ev["media_type"]]
            results.append({
                "evidence_id": ev["id"], "original_name": ev["original_name"],
                "run_id": None, "status": "delegated", "events": 0,
                "message": (f"Disk image media is not parsed into the timeline; it is "
                            f"processed by the {reason}. Open the evidence tab and run "
                            f"'Analyze disk image' to complete phase 6."),
            })
            continue
        r = run_parser(ev)
        results.append({"evidence_id": ev["id"], "original_name": ev["original_name"],
                        "run_id": r["id"], "status": r["status"], "events": r["events_added"],
                        "message": r["message"]})
    return {"runs": results}


def parse_case_case_cases(case_id: str):  # kept for API naming symmetry
    return run_all_parsers(case_id)


def coverage_report(case_id: str) -> dict:
    evs = query("SELECT * FROM evidence WHERE case_id=?", (case_id,))
    per = []
    for ev in evs:
        latest = one(
            "SELECT * FROM parser_runs WHERE evidence_id=? ORDER BY started_at DESC LIMIT 1",
            (ev["id"],))
        per.append({
            "evidence_id": ev["id"], "name": ev["original_name"], "media_type": ev["media_type"],
            "status": latest["status"] if latest else "not_parsed",
            "parser": latest["parser"] if latest else None,
            "events": latest["events_added"] if latest else 0,
            "errors": latest["errors"] if latest else 0,
            "warnings": latest["warnings"] if latest else 0,
            "message": latest["message"] if latest else "",
        })
    return {"parsers": [p.name for p in all_parsers()], "evidence": per}
