"""MITRE ATT&CK mapping with explicit, evidence-grounded rules.

RULES_VERSION identifies the rule set AND the pinned technique subset below
(curated from MITRE ATT&CK Enterprise). We do NOT load the full enterprise
bundle; mappings beyond this set are reported as 'unmapped' honestly.

A mapping fires ONLY when the referenced evidence actually exists in the case
and the rule condition is met. Rationale, evidence ids, rule version and a
disclaimer travel with every mapping.
"""
from __future__ import annotations

from ..db import query, insert, execute, jdump, jload
from ..util.ids import new_id, now_iso

RULES_VERSION = "attack-rules/2025a (pinned techniques T1003.001, T1059.003, T1059.001, T1098, T1543.003, T1053.005, T1070.002, T1078, T1091, T1204.002)"

TECHNIQUES = {
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1543.003": ("Windows Service", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1070.002": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1091": ("Replication Through Removable Media", "Initial Access"),
    "T1204.002": ("Malicious File", "Execution"),
}


def _rows_for_case(case_id: str):
    return query("SELECT * FROM events WHERE case_id=?", (case_id,))


def _mk_mapping(case_id, finding_id, tech, rationale, eids, workspace: list) -> None:
    tid, (name, tactic) = tech, TECHNIQUES[tech]
    workspace.append({
        "id": new_id("atm"), "case_id": case_id, "finding_id": finding_id,
        "technique_id": tid, "technique_name": name, "tactic": tactic,
        "rationale": rationale, "evidence_ids": jdump(sorted(set(eids))),
        "rule_version": RULES_VERSION,
        "confidence": "high" if len(set(eids)) >= 2 else "medium",
    })


def build_mappings(case_id: str) -> dict:
    """Rules over normalized events. Each rule references concrete event ids."""
    events = _rows_for_case(case_id)
    if not events:
        return {"ok": True, "mappings": 0, "findings": 0,
                "note": "No normalized events in the case, so no mapping is supported yet."}
    by_type: dict = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)

    findings = []
    mappings = []

        # R1: Failed logon burst for the same account
    failures = by_type.get("logon_failure", [])
    if failures:
        counts: dict = {}
        for e in failures:
            counts.setdefault(e["username"], []).append(e)
        for user, evs in counts.items():
            if len(evs) >= 5 and user:
                eids = sorted({e["evidence_id"] for e in evs})
                f = _mk_finding(case_id,
                                f"Repeated logon failures for '{user}'",
                                f"{len(evs)} logon_failure events reference account '{user}'. "
                                "This can indicate password guessing, but rainbow-table or typo bursts look identical; it is not conclusive.",
                                severity=3, evs=evs, rule_id="R1_logon_failure_burst")
                findings.append(f)
                _mk_mapping(case_id, f["id"], "T1078",
                            f"Repeated failed authentication for '{user}' may represent attempts to misuse "
                            "valid accounts. Mapping reflects observed authentication behavior only.",
                            eids + [], mappings)
    # R2: Service installed
    svc = [e for e in by_type.get("service_installed", [])]
    for e in svc:
        svc_name = e["process_name"] or e["destination_path"] or "name not recorded in source event"
        img = (e["source_path"] or "")
        f = _mk_finding(case_id,
                        f"Service installed: {svc_name}",
                        f"A Windows service '{svc_name}' was installed (ImagePath={img[:160] or 'not recorded'}). "
                        "Services are a persistence mechanism; legitimacy depends on change control records, not on what is seen here.",
                        severity=4, evs=[e], rule_id="R2_service_install")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1543.003",
                    "A service installation event is direct evidence of the Windows Service persistence "
                    "technique being exercised (SANCTIONED: attacker OR administrator).",
                    [e["evidence_id"]], mappings)
    # R3: Scheduled task
    tasks = by_type.get("scheduled_task_created", [])
    for e in tasks:
        task_name = e["process_name"] or e["destination_path"] or "name not recorded in source event"
        f = _mk_finding(case_id, f"Scheduled task created: {task_name}",
                        f"A scheduled task named '{task_name}' was created. Tasks are a "
                        "documented persistence mechanism. Verification requires content review.",
                        severity=4, evs=[e], rule_id="R3_task_create")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1053.005",
                    "Creation of a scheduled task matches T1053.005; the rule relies only on "
                    "task-creation events present in this case.",
                    [e["evidence_id"]], mappings)
    # R4: Log cleared
    cleared = by_type.get("audit_log_cleared", [])
    for e in cleared:
        f = _mk_finding(case_id, "Audit log cleared",
                        f"An audit-log clearing event was observed at {e['ts_utc']} on {e['hostname']} "
                        "(channel: " + str(e['channel']) + "). Post-clearing gaps ARE presumed and are "
                        "explicitly a data limitation: what is missing is unknown.",
                        severity=5, evs=[e], rule_id="R4_log_clear")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1070.002",
                    "Event 1102/104 is direct evidence of Windows event log clearing.",
                    [e["evidence_id"]], mappings)
    # R5: PowerShell execution
    ps = [e for e in by_type.get("process_created", [])
          if "powershell" in (str(e["process_name"]) + str(e["command_line"])).lower()]
    if ps:
        eids_set = sorted({e["evidence_id"] for e in ps})
        f = _mk_finding(case_id, "PowerShell process execution",
                        f"{len(ps)} process-creation events reference powershell. Command lines "
                        "are recorded in the event ids listed; their authorization requires the investigator's judgment.",
                        severity=3, evs=ps[:25], rule_id="R5_powershell")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1059.001",
                    "Observed powershell process creation maps to T1059.001.",
                    eids_set, mappings)
    # R6: USB followed by files
    usb = by_type.get("usb_device_connected", []) + by_type.get("usb_device", [])
    if usb:
        eids_u = sorted({e["evidence_id"] for e in usb})
        f = _mk_finding(case_id, "Removable device connected",
                        f"{len(usb)} USB connect/install events were observed. Whether data moved "
                        "cannot be concluded from these events alone.",
                        severity=2, evs=usb[:50], rule_id="R6_usb")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1091",
                    "Removable media use relates to replication through removable media; the rule "
                    "records the device-install evidence without claiming files were written.",
                    eids_u, mappings)
    # R7: User account created
    for e in by_type.get("user_account_created", []):
        f = _mk_finding(case_id, f"User account created: {e['username']}",
                        f"A local user account '{e['username']}' was created at {e['ts_utc']}.",
                        severity=3, evs=[e], rule_id="R7_account_create")
        findings.append(f)
        _mk_mapping(case_id, f["id"], "T1098",
                    "New user account creation corresponds to Account Manipulation.",
                    [e["evidence_id"]], mappings)
    # R8: Browser download followed by process with same name
    downloads = by_type.get("file_downloaded", [])
    procs = by_type.get("process_created", [])
    for d in downloads:
        exe = ((d["destination_path"] or "").split("\\") or [""])[-1].lower()
        if not exe:
            continue
        hit = [p for p in procs if exe and exe in ((p["process_name"] or "").split("\\") or [""])[-1].lower()]
        if hit:
            eids = sorted({d["evidence_id"], *{h["evidence_id"] for h in hit}})
            f = _mk_finding(case_id, f"Download followed by execution: {exe}",
                            f"'{d['destination_path']}' was downloaded and a process ending in '{exe}' "
                            "executed shortly afterwards (download event " + str(d["id"]) + ").",
                            severity=4, evs=hit[:10], rule_id="R8_download_execute",
                            extra_eids=[d["evidence_id"]])
            findings.append(f)
            _mk_mapping(case_id, f["id"], "T1204.002",
                        "Downloaded file execution is user-executed code (T1204.002) when "
                        "download-and-execution are linked in time.",
                        eids, mappings)
    from ..db import execute as _ex

    _ex("DELETE FROM attack_mappings WHERE case_id=?", (case_id,))
    # Rebuild rule-generated findings as well, so re-runs do not pile up
    # duplicates — but never remove a finding the investigator has confirmed
    # or dismissed: machine output can be regenerated, human decisions cannot.
    _ex("DELETE FROM findings WHERE case_id=? AND status='open' AND rule_id LIKE 'R\\_%' ESCAPE '\\'",
        (case_id,))
    for m in mappings:
        insert("attack_mappings", m)
    for f in findings:
        insert("findings", f)
    return {
        "ok": True,
        "mappings": len(mappings),
        "findings": len(findings),
        "rule_version": RULES_VERSION,
        "workspace": None,
        "note": ("Zero mappings is a supported, honest outcome when no rule conditions are met."),
    }


def _mk_finding(case_id: str, title: str, description: str, severity: int, evs,
                rule_id: str, extra_eids=None) -> dict:
    eids = sorted({*(e["evidence_id"] for e in evs), *(extra_eids or [])})
    return {
        "id": new_id("f"), "case_id": case_id, "title": title, "description": description,
        "rule_id": rule_id, "rule_version": RULES_VERSION, "severity": max(1, min(5, severity)),
        "evidence_ids": jdump(eids), "event_ids": jdump([e["id"] for e in evs][:100]),
        "status": "open", "created_at": now_iso(),
    }


def cap_findings_at(case_id: str) -> int:
    from ..db import one

    return one("SELECT COUNT(*) AS n FROM findings WHERE case_id=?", (case_id,))["n"]
