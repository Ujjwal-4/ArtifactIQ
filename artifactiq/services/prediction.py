"""Predictive investigative branches — evidence-grounded next-step suggestions.

Design notes (Phase 9):
- Branches suggest what to EXAMINE next; they never assert facts about an
  attacker or the future.
- Every branch cites supporting event/evidence ids and names what is missing.
- Priority is a documented rule-based calculation, NOT a probability.
"""
from __future__ import annotations

from ..db import query, insert, execute, one, update, jdump
from ..util.ids import new_id, now_iso

RULES_VERSION = "branch-rules/2025b/1.1"
PRIO_FORMULA = "priority = min(90, severity_base*20 + 5*min(2, corroboration-1))"


def priority_of(base_severity: int, corroboration: int) -> tuple[int, dict]:
    bonus = 5 * min(2, max(0, corroboration - 1))
    p = min(90, base_severity * 20 + bonus)
    return p, {
        "formula": PRIO_FORMULA,
        "severity_base": base_severity,
        "corroboration": corroboration,
        "priority": p,
        "note": "rule-based investigative priority; not a probability of compromise",
    }


def _mk(case_id, question, why, events, evidence_ids, missing, steps,
        base_severity, corroboration, rule_id):
    p, calc = priority_of(base_severity, corroboration)
    ev_ids = [e["id"] for e in events][:50]
    return {
        "id": new_id("br"), "case_id": case_id, "question": question, "why": why,
        "evidence_ids": jdump(sorted(set(evidence_ids))),
        "event_ids": jdump(ev_ids),
        "missing_evidence": jdump(missing), "steps": jdump(steps),
        "priority": p, "priority_calc": jdump(calc),
        "status": "open", "closure_note": "",
        "rule_id": rule_id, "rule_version": RULES_VERSION,
        "created_at": now_iso(),
    }


def generate(case_id: str) -> dict:
    events = query("SELECT * FROM events WHERE case_id=? ORDER BY ts_utc", (case_id,))
    if not events:
        return {"ok": True, "branches": 0,
                "note": "No normalized events to reason about yet. Parse evidence first."}
    by_type: dict = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)
    procs = by_type.get("process_created", [])
    usb = by_type.get("usb_device_connected", []) + by_type.get("usb_device", [])
    file_events = [e for e in events
                   if e["category"] == "file" or e["event_type"].startswith("file_")]
    out = []

    # --- B1: failed logons -> check the successful-logon context -------------
    failures = by_type.get("logon_failure", [])
    successes = by_type.get("logon_success", [])
    if failures:
        out.append(_mk(
            case_id,
            f"What preceded and followed the {len(failures)} failed logon event(s) on this host?",
            "Failed logons may signal credential misuse, scheduled activity, or simple "
            "typos; the nearby successful-logon context is what distinguishes these cases.",
            failures[:20],
            sorted({f["evidence_id"] for f in failures[:20]}),
            ["4634/4624 success events for the same host and window are needed to close this branch"],
            ["Pivot to the timeline window 60 seconds before and after each failure",
             "Check each failure for a later 4624 success on the same account",
             "Record the outcome as confirmed / rejected / inconclusive"],
            4 if successes else 3,
            2 if len(failures) > 3 else 1,
            "B1_failed_logon_context",
        ))

    # --- B2: suspicious process parent (PowerShell) --------------------------
    ps_procs = [p for p in procs
                if "powershell" in str(p["process_name"]).lower()
                or (p["command_line"] and "powershell" in p["command_line"].lower())]
    if ps_procs:
        out.append(_mk(
            case_id,
            "Which parent launched PowerShell, and is that expected on this host?",
            "PowerShell is common in administration but is also a major malware loader; "
            "the parent process and change-control status decide which interpretation holds.",
            ps_procs[:15],
            sorted({p["evidence_id"] for p in ps_procs[:15]}),
            ["ParentProcess/ParentCommandLine require 4688 or Sysmon audit policy that may have been off"],
            ["Look up the recorded parent process id under the same host",
             "Compare the command line against change control / software inventory",
             "Note elevation indicators (cmd /c, -nop, -enc) without asserting intent"],
            4, 2, "B2_process_parent",
        ))

    # --- B3: USB connect with/without file activity -------------------------
    if usb and not file_events:
        out.append(_mk(
            case_id,
            f"Did the {len(usb)} connected USB device(s) move data on or from this host?",
            "A device-install event alone proves a device was attached, not data movement.",
            usb[:10],
            sorted({e["evidence_id"] for e in usb[:10]}),
            ["File-creation / MFT / prefetch evidence covering the connection window "
             "is missing from this case"],
            ["Acquire or import file-system metadata covering the connection window",
             "Re-run analysis after that evidence is parsed"],
            3, 1, "B3_usb_needs_files",
        ))
    elif usb and file_events:
        out.append(_mk(
            case_id,
            f"Which file events fall within 10 minutes of the USB event(s)?",
            "Proximity infers nothing by itself, but a tight window is the first thing "
            "investigators verify.",
            (usb + file_events)[:25],
            sorted({e["evidence_id"] for e in (usb + file_events)[:25]}),
            [],
            ["Filter the timeline to 10-minute windows around each USB timestamp",
             "Open each correlated file event and record its evidence reference"],
            3, 2, "B3b_usb_correlation",
        ))

    # --- B4: persistence artifacts (services / scheduled tasks) --------------
    svc = by_type.get("service_installed", [])
    tasks = by_type.get("scheduled_task_created", [])
    if tasks or svc:
        out.append(_mk(
            case_id,
            f"Review the {len(tasks)} scheduled task and {len(svc)} service installation "
            "event(s) for unexpected binaries.",
            "Both are documented Windows persistence mechanisms; validation depends on "
            "change-control records, which this case does not contain yet.",
            (tasks + svc)[:15],
            sorted({e["evidence_id"] for e in (tasks + svc)[:15]}),
            ["Disk artifacts (TaskCache, SYSTEM\\ControlSet001\\Services) are needed to validate fully"],
            ["For each entry, record the ImagePath/Task content and whether the binary exists",
             "Check group policy or change tickets for the binary name",
             "Map each verified item in the ATT&CK panel when content is in the case"],
            4, 2 if (tasks and svc) else 1, "B4_persistence_review",
        ))

    # --- B5: audit-log clearing ----------------------------------------------
    cleared = by_type.get("audit_log_cleared", [])
    if cleared:
        out.append(_mk(
            case_id,
            "Which events are missing because of the audit-log clearing, and what other "
            "artifacts still cover the gap?",
            "Cleared logs create an evidence gap whose exact contents are unknowable; "
            "other artifact families may partially cover the cleared window.",
            cleared,
            sorted({c["evidence_id"] for c in cleared}),
            ["The exact contents of the cleared window are unknowable; any narrative must say so"],
            ["Record the clearing timestamp as the incident-window boundary",
             "Collect alternative artifacts (registry, browser, filesystem) for that window"],
            5, 1, "B5_log_clear_gap",
        ))

    # --- B6: downloaded executable -> run? ------------------------------------
    down = by_type.get("file_downloaded", [])
    for d in down:
        exe = ((d["destination_path"] or "").split("\\") or [""])[-1]
        if not exe or not exe.lower().endswith(
                (".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js")):
            continue
        has_run = [p for p in procs
                   if p["process_name"]
                   and p["process_name"].lower().endswith(exe.lower())]
        out.append(_mk(
            case_id,
            f"Where did the downloaded executable '{exe}' come from, and did it run?",
            "Downloaded executables are the main chain between user activity and "
            "malware execution on Windows endpoints.",
            [d],
            [d["evidence_id"]],
            ([f"No process-creation event matching '{exe}' was found in this case"] if not has_run
             else [f"Corroborating process event id: {has_run[0]['id']}"]),
            ["Open the download record and its source URL",
             "Search the timeline for that executable name after the download time",
             "Mark confirmed only when a matching process event is located"],
            4, 2 if has_run else 1, "B6_download_execute",
        ))
        break

    # --- B7: network destinations -------------------------------------------
    net_events = by_type.get("network_connection", [])
    if net_events:
        out.append(_mk(
            case_id,
            f"Are the {len(net_events)} network-connection event(s) normal for this endpoint's role?",
            "Network events list destinations, not purpose; authorization must come from "
            "asset inventory or firewall baselines, which the case does not contain yet.",
            net_events[:15],
            sorted({e["evidence_id"] for e in net_events[:15]}),
            ["Asset criticality / firewall baselines have not been provided in this case"],
            ["List destination IPs and check whether they are known-good services",
             "Record unresolved destinations in the risk panel as evidence gaps"],
            3, 1, "B7_network_authorization",
        ))

    execute("DELETE FROM branches WHERE case_id=?", (case_id,))
    for b in out:
        insert("branches", b)
    return {"ok": True, "branches": len(out), "rule_version": RULES_VERSION}


def decide(branch_id: str, status: str, note: str = "") -> dict | None:
    if status not in ("open", "confirmed", "rejected", "inconclusive", "deferred"):
        raise ValueError("status must be open/confirmed/rejected/inconclusive/deferred")
    row = one("SELECT * FROM branches WHERE id=?", (branch_id,))
    if not row:
        return None
    update("branches", branch_id, {"status": status, "closure_note": note[:1000]})
    return {"id": branch_id, "status": status, "closure_note": note}
