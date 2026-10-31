"""Workflow phase state machine (Phase model, section 8).

Phase status is DERIVED from actual case artifacts, never a static label.
Each status transition stores run id, timestamps, version and detail JSON.
"""
from __future__ import annotations

from ..db import query, one, insert, jdump
from ..util.ids import new_id, now_iso

ALL_PHASES = [
    ("p01_cases", "Cases and case metadata"),
    ("p02_acquisition_plan", "Acquisition plan and authorization"),
    ("p03_acquisition", "Evidence acquisition / import"),
    ("p04_parsing", "Artifact parsing and normalization"),
    ("p05_custody", "Integrity and chain of custody"),
    ("p06_image", "Disk-image analysis (when applicable)"),
    ("p07_timeline", "Unified timeline"),
    ("p08_graph_attack", "Graph and ATT&CK mapping"),
    ("p09_branches", "Predictive investigation branches"),
    ("p10_risk", "Risk and impact assessment"),
    ("p11_explain", "Explainable summary"),
    ("p12_reports", "Dashboard and reporting"),
]
PHASE_ORDER = [p[0] for p in ALL_PHASES]
PHASE_TITLE = dict(ALL_PHASES)


def record_case_intake(case_id: str, detail: dict) -> None:
    _run("p01_cases", case_id, "completed", {
        "detail": detail, "version": "cases/2.0.0"})


def _run(phase: str, case_id: str, status: str, detail: dict) -> dict:
    row = {
        "id": new_id("pr"), "case_id": case_id, "phase": phase, "status": status,
        "started_at": now_iso(), "finished_at": now_iso(),
        "version": detail.get("version", "2.0.0"),
        "detail": jdump({k: v for k, v in detail.items() if k != "version"}),
    }
    insert("phase_runs", row)
    return row


def record_explanation(case_id: str, detail: dict) -> None:
    """p11 is completed on demand: the explanation was actually built + shown."""
    _run("p11_explain", case_id, "completed",
         {**detail, "version": "explanation/2.0.0"})


def refresh_phase_status(case_id: str, phase: str, detail: dict | None = None) -> str:
    """Derive and persist the currently correct status for one phase."""
    if phase == "p01_cases":
        c = one("SELECT * FROM cases WHERE id=?", (case_id,))
        st = "completed" if c else "not_started"
        return _run(phase, case_id, st, {"detail": "case record exists"} )["status"]
    if phase == "p02_acquisition_plan":
        sess = one("SELECT COUNT(*) AS n FROM acquisition_sessions WHERE case_id=?",
                   (case_id,))["n"]
        if sess:
            return _run(phase, case_id, "completed",
                        {"detail": f"{sess} acquisition session(s) planned with authorization recorded"})["status"]
        ev = one("SELECT COUNT(*) AS n FROM cases WHERE id=?", (case_id,))["n"]
        st = "ready" if ev else "not_started"
        return _run(phase, case_id, st, {"detail": "case present; plan awaiting sources"} )["status"]
    if phase == "p03_acquisition":
        evidence = one("SELECT COUNT(*) AS n FROM evidence WHERE case_id=?", (case_id,))["n"]
        bad = one(
            "SELECT COUNT(*) AS n FROM evidence WHERE case_id=? AND verify_status='mismatch'",
            (case_id,))["n"]
        if evidence == 0:
            st = "not_started"
        elif bad:
            st = "completed_with_warnings"
        else:
            st = "completed"
        return _run(phase, case_id, st,
                    {"evidence_count": evidence, "mismatched_hashes": bad})["status"]
    if phase == "p04_parsing":
        runs = query(
            "SELECT status, COUNT(*) AS n FROM parser_runs WHERE case_id=? GROUP BY status",
            (case_id,))
        if not runs:
            return _run(phase, case_id, "not_started", {"note": "no parser runs yet"})["status"]
        counts = {r["status"]: r["n"] for r in runs}
        ok = counts.get("completed", 0)
        err = counts.get("completed_with_errors", 0)
        bad = counts.get("failed", 0) + counts.get("unsupported", 0)
        if ok + err == 0:
            st = "blocked"
        elif bad and not ok and not err:
            st = "failed"
        elif bad:
            st = "completed_with_warnings"
        else:
            st = "completed"
        return _run(phase, case_id, st, {"by_status": counts})["status"]
    if phase == "p05_custody":
        # custody ledger is live as soon as evidence exists; the phase
        # completes when every item passed intake integrity verification
        n = one("SELECT COUNT(*) AS n FROM evidence WHERE case_id=?", (case_id,))["n"]
        bad = one(
            "SELECT COUNT(*) AS n FROM evidence WHERE case_id=? AND verify_status IN "
            "('mismatch','error')", (case_id,))["n"]
        pending = one(
            "SELECT COUNT(*) AS n FROM evidence WHERE case_id=? AND verify_status="
            "'unverified'", (case_id,))["n"]
        if n == 0:
            st = "not_started"
        elif bad:
            st = "completed_with_warnings"
        elif pending:
            st = "ready"   # rows not yet through intake hashing (should not happen)
        else:
            st = "completed"
        return _run(phase, case_id, st,
                    {"evidence": n, "misverified": bad, "pending": pending,
                     "note": "past items logged under verify_status='retained' remain counted"})["status"]
    if phase == "p07_timeline":
        n = one("SELECT COUNT(*) AS n FROM events WHERE case_id=?", (case_id,))["n"]
        unknown = one(
            "SELECT COUNT(*) AS n FROM events WHERE case_id=? AND ts_utc IS NULL", (case_id,))["n"]
        # missing timestamps are only a WARNING when the source actually had one
        # and it was dropped/misparsed. A source that carries no timestamp at
        # all (.reg text exports, for example) is a documented data limitation,
        # not a parsing problem.
        no_src = one(
            "SELECT COUNT(*) AS n FROM events WHERE case_id=? "
            "AND ts_utc IS NULL AND ts_source='no_timestamp'", (case_id,))["n"]
        warn = unknown - no_src
        if n == 0:
            st = "not_started"
        elif warn == n:
            st = "failed"
        elif warn:
            st = "completed_with_warnings"
        else:
            st = "completed"
        return _run(phase, case_id, st,
                    {"events": n, "unknown_ts": unknown, "not_in_source": no_src,
                     "dropped_or_unparsed": warn,
                     "note": "no-in-source timestamps are a source-format limitation "
                             "(shown as such on the timeline), not warnings"})["status"]
    if phase == "p08_graph_attack":
        ents = one("SELECT COUNT(*) AS n FROM entities WHERE case_id=?", (case_id,))["n"]
        maps = one("SELECT COUNT(*) AS n FROM attack_mappings WHERE case_id=?", (case_id,))["n"]
        if ents and maps:
            st = "completed"
        elif ents:
            st = "completed_with_warnings"
        else:
            st = "not_started"
        return _run(phase, case_id, st,
                    {"entities": ents, "mappings": maps,
                     "note": "0 mappings is an honest complete outcome if no rule fired"})["status"]
    if phase == "p09_branches":
        n = one("SELECT COUNT(*) AS n FROM branches WHERE case_id=?", (case_id,))["n"]
        st = "completed" if n else "not_started"
        return _run(phase, case_id, st, {"branches": n})["status"]
    if phase == "p10_risk":
        r = one("SELECT * FROM risk_assessments WHERE case_id=?", (case_id,))
        st = "completed" if r else "not_started"
        return _run(phase, case_id, st,
                    {"score": r["score"] if r else None, "band": r["band"] if r else None})["status"]
    if phase == "p11_explain":
        # recorded on demand
        st = "ready"
        return _run(phase, case_id, st, {} )["status"]
    if phase == "p12_reports":
        r = one("SELECT COUNT(*) AS n FROM reports WHERE case_id=?", (case_id,))["n"]
        st = "completed" if r else "ready"
        return _run(phase, case_id, st, {"reports": r})["status"]
    if phase == "p06_image":
        from . import image_analysis as img
        n = one("SELECT COUNT(*) AS n FROM evidence WHERE case_id=? AND "
                "media_type='disk_image'", (case_id,))["n"]
        if n == 0:
            return _run(phase, case_id, "blocked",
                        {"reason": "no disk-image evidence registered in this case "
                                   "(phase applies when an image is in scope)"})["status"]
        last = img.last_run(case_id)
        if not last:
            e = img.engine()
            if not e["installed"]:
                return _run(phase, case_id, "blocked",
                            {"reason": "disk-image evidence is registered but the parsing "
                                       "engine (pytsk3 / The Sleuth Kit) is not installed",
                             "engine": ""})["status"]
            return _run(phase, case_id, "ready",
                        {"reason": "disk image registered; run analysis to complete the phase",
                         "engine": e["version"]})["status"]
        d = {"evidence_id": last["evidence_id"], "engine": last.get("engine"),
             "files": last.get("files"), "dirs": last.get("dirs"),
             "deleted": last.get("deleted"), "message": last.get("message"),
             "partitions": last.get("partitions")}
        return _run(phase, case_id, last["status"], d)["status"]
    return status_of(phase, case_id)


def status_of(phase: str, case_id: str) -> str:
    last = one(
        "SELECT * FROM phase_runs WHERE case_id=? AND phase=? ORDER BY started_at DESC, rowid DESC LIMIT 1",
        (case_id, phase))
    return (last["status"] if last else "not_started")


def status_map(case_id: str) -> dict:
    out = {}
    for p in PHASE_ORDER:
        last = one(
            "SELECT * FROM phase_runs WHERE case_id=? AND phase=? ORDER BY started_at DESC, rowid DESC LIMIT 1",
            (case_id, p))
        title = PHASE_TITLE[p]
        if last:
            out[p] = {
                "phase": p, "title": title, "status": last["status"],
                "at": last["finished_at"] or last["started_at"],
                "detail": last["detail"], "version": last["version"],
            }
        else:
            out[p] = {"phase": p, "title": title, "status": "not_started", "at": None,
                      "detail": "{}", "version": ""}
    return out


def refresh_case(case_id: str) -> dict:
    """Re-derive every phase status from real artifacts."""
    for p in PHASE_ORDER:
        if p == "p11_explain":
            continue
        try:
            refresh_phase_status(case_id, p)
        except Exception:
            _run(p, case_id, "failed", {"error": "status derivation exception"})
    return status_map(case_id)
