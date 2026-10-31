"""Behavioral scenario simulator (the "attack-chain simulation" layer).

Design notes (companion to Phase 9 branches):
- Click a suspicious trigger found in the case evidence; the simulator walks a
  documented chain of what attackers *typically* do next: per node it shows the
  ATT&CK technique, the artifacts this step would leave behind, the possible
  consequence and impact, and generic prevention guidance.
- EVERY node carries an explicit status:
    "observed"     -> matching events exist in THIS case (ids cited);
    "predicted"    -> typical next behavior; no matching artifact (yet);
                      the text is a CONTRACT to search for specific artifacts,
                      never an assertion that the attacker did anything.
- Node content comes from a finite, versioned knowledge base (sim-rules/2026a).
  Same events + same ruleset => same simulation, every time (no LLM softness).
- Impact/prevention text cites MITRE ATT&CK mitigation codes (M-codes) and is
  deliberately generic: it is defense guidance, not a case finding.
- No node is ever marked merely because "malware would do X": observation
  requires a real event/artifact row in this case.
"""
from __future__ import annotations

from ..db import query, insert, execute, jdump, jload
from ..util.ids import new_id, now_iso

RULES_VERSION = "sim-rules/2026a/1.0"
PRIO_FORMULA = "priority = min(95, trigger_severity*20 + 6*observed_nodes)"
MITIGATION_DISCLAIMER = (
    "Mitigation codes cite the MITRE ATT&CK Enterprise mitigations list; the "
    "advice is generic good practice, not a case-specific finding.")

# Markers that make a process/interpreter suspicious enough to trigger a chain.
SCRIPT_MARKERS = [
    "powershell", "-enc", "-encodedcommand", "-nop", "-w hidden",
    "-windowstyle hidden", "iex(", "invoke-expression", "downloadstring",
    "bypass policy", "wscript", "cscript", "mshta", "cmd.exe /c", "cmd /c",
    ".ps1", ".vbs", ".vbe", ".js ", ".hta", ".bat", ".cmd", "certutil",
    "bitsadmin",
]
EXE_EXTS = (".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js")


def _mk_tech(tid: str, name: str, tactic: str) -> dict:
    return {"technique_id": tid, "technique_name": name, "tactic": tactic}


def _node(idx: int, title: str, tech: dict, description: str,
          expected: list, consequence: str, impact: str, prevention: list,
          match: dict | None, honesty_note: str = "") -> dict:
    """Build one static chain node; status is filled by the engine."""
    return {
        "idx": idx, "title": title, "technique": tech,
        "description": description,
        "expected_artifacts": expected,          # what to look for in evidence
        "consequence": consequence,
        "impact": impact,
        "prevention": prevention,                # ATT&CK M-codes
        "match": match or {},                    # how 'observed' is decided
        "honesty_note": honesty_note,
        # engine-filled:
        "status": "predicted",                   # observed | predicted
        "event_ids": [], "evidence_ids": [],
    }


def _tail_persist_cred_exfil() -> list:
    """Stages 3-6 shared by the execution chains (fresh dicts per call)."""
    return [
        _node(3, "Persistence established on the endpoint",
              _mk_tech("T1547.001", "Registry Run Keys / Startup Folder (+ T1053.005 Scheduled Task, T1543.003 Windows Service)",
                       "Persistence"),
              "To survive a reboot, the payload typically writes a persistence anchor: a Run key, a scheduled task, or a service.",
              ["scheduled_task_created / service_installed events for unexpected binaries",
               "Run-key entries under HKCU/HKLM ...\\Run (needs registry-hive evidence, not parsed by the current parsers yet)"],
              "Reboot-surviving foothold on the host; removal of the payload alone would not remove access.",
              "Attacker regains execution after cleanup, adding to remediation cost and dwell time.",
              ["M1022 Restrict File and Directory Permissions",
               "M1024 Restrict Registry Permissions",
               "M1040 Behavior Prevention on Endpoint"],
              {"event_types": ["scheduled_task_created", "service_installed"]},
              "Run-key persistence requires parsing the SOFTWARE/NTUSER hive; treat as a collection target for this case."),
        _node(4, "Credential access and account misuse",
              _mk_tech("T1003.001", "LSASS Memory (+ T1110.001 Password Guessing)", "Credential Access"),
              "With a foothold inside an authenticated process space, attackers attempt credential extraction (memory of lsass) or offline/online password guessing.",
              ["logon_failure bursts followed by a matching logon_success for the same account",
               "process_created events for comsvcs.dll minidump, procdump, taskmgr dump"],
              "Stolen credentials unlock other systems and data without needing the original exploit again.",
              "Account takeover beyond the initially compromised host; harder to trace once credentials circulate.",
              ["M1018 Credential Access Protection",
               "M1027 Password Policies",
               "M1026 Privileged Account Management"],
              {"event_types": ["logon_failure", "logon_success"]},
              "Credential-dumping processes are only visible if process auditing captured them; absence is not proof of absence."),
        _node(5, "Staging and exfiltration",
              _mk_tech("T1560.001", "Archive via Utility (+ T1041 Exfiltration Over C2)", "Exfiltration"),
              "Collected data is commonly compressed/archived, then sent out over the same or a separate channel.",
              ["network_connection events to unfamiliar destinations near the incident window",
               "large file-writes followed by uploads (needs filesystem evidence)"],
              "Data leaves the environment; confidentiality breach becomes an incident with regulatory scope.",
              "Lost IP / PII / contractual secrets; the step is often invisible without network or proxy logs.",
              ["M1053 Data Loss Prevention",
               "M1030 Network Segmentation",
               "M1032 Multi-Factor Authentication"],
              {"event_types": ["network_connection"]},
              "Network events list destinations and volume, never purpose; authorization baselines decide what is abnormal."),
        _node(6, "Anti-forensics: log clearing",
              _mk_tech("T1070.002", "Clear Windows Event Logs", "Defense Evasion"),
              "After ensuring access, attackers often clear audit logs to erase the record of earlier stages.",
              ["audit_log_cleared (1102/104) events — already the strongest single tamper indicator"],
              "The exact actions inside the cleared window become unknowable; other artifact families only partially cover it.",
              "Investigation scope itself is compromised; any narrative must disclose the gap.",
              ["M1029 Remote Data Storage (ship logs to a central system)",
               "M1028 Operating System Configuration (protect the event log service)"],
              {"event_types": ["audit_log_cleared"]},
              "If this node is observed, steps executed before the clearing may have no surviving log rows at all."),
    ]


def _detect_triggers(events: list) -> list:
    """Find incident triggers in normalized events (rule-based, cited)."""
    by_type: dict = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)
    procs = by_type.get("process_created", [])
    file_events = [e for e in events
                   if e["category"] == "file" or e["event_type"].startswith("file_")]
    trig: list = []

    # TR1 suspicious script/interpreter execution
    susp = [p for p in procs
            if any(m in (str(p["process_name"]) + " " + str(p["command_line"] or "")).lower()
                   for m in SCRIPT_MARKERS)]
    if susp:
        trig.append({"rule": "TR1_script_execution", "scenario": "SIM-C1_script_chain",
                     "events": susp[:20], "severity": 5,
                     "summary": f"{len(susp)} script/interpreter process event(s) with suspicious markers"})

    # TR2 downloaded executable
    down = [d for d in by_type.get("file_downloaded", [])
            if ((d["destination_path"] or "").split("\\") or [""])[-1].lower().endswith(EXE_EXTS)]
    if down:
        trig.append({"rule": "TR2_downloadable_payload", "scenario": "SIM-C5_download_chain",
                     "events": down[:10], "severity": 4,
                     "summary": f"executable file(s) downloaded: {', '.join(((d['destination_path'] or '?').split('\\\\') or ['?'])[-1] for d in down[:3])}"})

    # TR3 USB with file activity
    usb = by_type.get("usb_device_connected", []) + by_type.get("usb_device", [])
    if usb and file_events:
        trig.append({"rule": "TR3_usb_with_files", "scenario": "SIM-C2_usb_chain",
                     "events": usb[:10], "severity": 4,
                     "summary": f"{len(usb)} USB connect event(s) plus {len(file_events)} file event(s) in the case"})

    # TR4 failed logon burst
    failures = by_type.get("logon_failure", [])
    if failures:
        users: dict = {}
        for f in failures:
            if f["username"]:
                users.setdefault(f["username"], []).append(f)
        burst = [u for u, evs in users.items() if len(evs) >= 5]
        if burst:
            trig.append({"rule": "TR4_logon_burst", "scenario": "SIM-C3_credential_chain",
                         "events": [e for u in burst for e in users[u]][:20], "severity": 4,
                         "summary": f"failed-logon burst (>=5) for account(s): {', '.join(burst[:3])}"})

    # TR5 log clearing
    cleared = by_type.get("audit_log_cleared", [])
    if cleared:
        trig.append({"rule": "TR5_log_clearing", "scenario": "SIM-C4_tamper_chain",
                     "events": cleared[:10], "severity": 5,
                     "summary": f"{len(cleared)} audit-log clearing event(s)"})
    return trig


def _scenario_chain(scenario_id: str, trig: dict, events: list) -> list:
    """Ordered node list for one scenario knowledge-base entry."""
    by_type: dict = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)
    procs = by_type.get("process_created", [])
    file_events = [e for e in events
                   if e["category"] == "file" or e["event_type"].startswith("file_")]

    if scenario_id == "SIM-C1_script_chain":
        return [
            _node(1, "Malicious script executed (trigger)",
                  _mk_tech("T1059.001", "PowerShell / T1059.003 Windows Command Shell", "Execution"),
                  f"The {len(trig['events'])} triggering event(s) show interpreter code executing. "
                  "A script CAN wound; it is not itself proof of malice — the downstream chain decides.",
                  ["these exact process_created events (cited below)"],
                  "From execution onward, every later stage is CONNECTED behavior, not isolated noise.",
                  "Code ran under an approved interpreter with unapproved logic.",
                  ["M1033 Limit Software Installation",
                   "M1040 Behavior Prevention on Endpoint",
                   "M1017 User Training"],
                  {"event_types": ["process_created"], "markers": SCRIPT_MARKERS},
                  ""),
            _node(2, "Defense evasion around the interpreter",
                  _mk_tech("T1562.001", "Impair Defenses (typical follow-up)", "Defense Evasion"),
                  "Script payloads commonly run hidden, try to bypass execution policy, or weaken local monitoring before doing anything else.",
                  ["process_created events with -enc / -nop / -w hidden / disable--defender style markers"],
                  "If defenses are weakened first, later stages leave fewer traces.",
                  "Reduced visibility compounds into miss-detection of the whole chain.",
                  ["M1040 Behavior Prevention on Endpoint",
                   "M1049 Antivirus/Antimalware",
                   "M1028 Operating System Configuration"],
                  {"event_types": ["process_created"],
                   "markers": ["-enc", "-nop", "-w hidden", "-windowstyle hidden",
                               "disable", "set-mppreference", "add-defender"]},
                  ""),
            *_tail_persist_cred_exfil(),
        ]

    if scenario_id == "SIM-C2_usb_chain":
        return [
            _node(1, "Removable device attached (trigger)",
                  _mk_tech("T1091", "Replication Through Removable Media", "Initial Access"),
                  f"The {len(trig['events'])} connect event(s) prove attachment on this host.",
                  ["these usb connect events (cited below)"],
                  "Attachment alone proves presence of the device, nothing about data flow.",
                  "Exfiltration OR payload delivery channel; impact depends on the next node.",
                  ["M1034 Limit Hardware Installation",
                   "M1017 User Training"],
                  {"event_types": ["usb_device_connected", "usb_device"]},
                  ""),
            _node(2, "File movement to/from the device",
                  _mk_tech("T1560.001", "Archive via Utility (staging)", "Exfiltration"),
                  "File events near the connect window show actual data movement.",
                  [f"file events ({len(file_events)}) in the case — proximity to the "
                   "connect window must be verified on the timeline"],
                  "Data in or out: copy-in delivers a payload, copy-out removes data.",
                  "Possible confidential-data loss if the window's files are sensitive.",
                  ["M1053 Data Loss Prevention", "M1022 Restrict File and Directory Permissions"],
                  {},  # file events are matched generically; proximity needs timeline review
                  "Observation here means file events EXIST in the case, not that they are "
                  "linked to the device window; verify proximity before confirming."),
            _node(3, "Payload execution of dropped file",
                  _mk_tech("T1204.002", "Malicious File", "Execution"),
                  "A file that arrived via removable media is executed by a user or a launcher.",
                  ["process_created whose name matches a file from the USB window"],
                  "Converts a storage event into code execution (full script chain applies).",
                  "Same downstream impact as SIM-C1.",
                  ["M1033 Limit Software Installation",
                   "M1040 Behavior Prevention on Endpoint"],
                  {"event_types": ["process_created"]},
                  "Name matching between file events and processes requires linking; treat matches as corroborating, not conclusive."),
            *_tail_persist_cred_exfil()[2:],   # credential access + exfil + anti-forensics
        ]

    if scenario_id == "SIM-C3_credential_chain":
        tail = _tail_persist_cred_exfil()
        return [
            _node(1, "Failed-logon burst (trigger)",
                  _mk_tech("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
                  f"{len(trig['events'])} logon_failure events for the same account(s).",
                  ["these logon_failure events (cited below)"],
                  "Guessing bursts precede either success (takeover) or abandonment (false alarm).",
                  "If guessing succeeds, the attacker inherits the REAL holder's privileges.",
                  ["M1027 Password Policies",
                   "M1032 Multi-Factor Authentication",
                   "M1036 Account Lockout Policy"],
                  {"event_types": ["logon_failure"]},
                  ""),
            _node(2, "Successful logon with the tested account",
                  _mk_tech("T1078", "Valid Accounts", "Defense Evasion"),
                  "A success for the same account near the burst is the pivot that turns guessing into access.",
                  ["logon_success events for the same username within the burst window"],
                  "Valid, authorized credentials are then used for unauthorized purposes.",
                  "Hard to distinguish from the real user's activity without extra context.",
                  ["M1032 Multi-Factor Authentication",
                   "M1017 User Training"],
                  {"event_types": ["logon_success"]},
                  ""),
            _node(3, "Account manipulation to keep access",
                  _mk_tech("T1098", "Account Manipulation", "Persistence"),
                  "New accounts or group changes make the access independent of the guessed password.",
                  ["user_account_created events"],
                  "Access no longer depends on the original entry vector.",
                  "Longer dwell time; cleanups that revert passwords won't revoke the new account.",
                  ["M1026 Privileged Account Management",
                   "M1032 Multi-Factor Authentication"],
                  {"event_types": ["user_account_created"]},
                  ""),
            tail[0],  # persistence node (idx 3 -> renumbered below)
            tail[1],  # credential node
            tail[2],  # exfiltration node
        ]

    if scenario_id == "SIM-C4_tamper_chain":
        return [
            _node(1, "Audit log cleared (trigger)",
                  _mk_tech("T1070.002", "Clear Windows Event Logs", "Defense Evasion"),
                  f"The {len(trig['events'])} clearing event(s) mark the boundary of the evidence gap.",
                  ["these audit_log_cleared events (cited below)"],
                  "Everything inside the cleared window is unknowable from these logs alone.",
                  "Narratives must state the gap; scope may be UNDERstated without care.",
                  ["M1029 Remote Data Storage",
                   "M1028 Operating System Configuration"],
                  {"event_types": ["audit_log_cleared"]},
                  ""),
            _node(2, "The unknowable gap (must be disclosed, not guessed)",
                  {"technique_id": "-", "technique_name": "Evidence limitation", "tactic": "-"},
                  "The contents of the cleared window cannot be recovered from the cleared source. "
                  "This simulator refuses to fill the gap with invented steps.",
                  ["alternative families for the window: registry audit, browser history, "
                   "filesystem metadata, USB history, network/device logs"],
                  "Honest narratives list what was searched and what was found, leaving unknowns unknown.",
                  "Not applicable (investigative, not behavioral).",
                  ["M1029 Remote Data Storage (prevention for future incidents)"],
                  {},  # never observed by design
                  "This node can never be 'observed': absence of evidence here is an evidence-LIMITATION, not an event."),
            _node(3, "Why clearing usually happens mid-attack",
                  _mk_tech("T1070.002", "Clear Windows Event Logs", "Defense Evasion"),
                  "Clearing typically occurs AFTER credential actions or persistence setup, since "
                  "perpetrators must already hold admin rights to clear Security/Syste� logs.",
                  ["admin-level logon events just before the clearing timestamp; "
                   "service/task events in the preceding window"],
                  "The pre-clear window is the priority zone for alternative artifact collection.",
                  "Bounds what other artifacts must cover.",
                  ["M1026 Privileged Account Management",
                   "M1028 Operating System Configuration"],
                  {"event_types": ["logon_success"]},
                  "Inference about intent is prohibited; only the temporal fact (need admin) is cited."),
        ]

    # SIM-C5_download_chain
    exe = ((trig["events"][0]["destination_path"] or "?").split("\\") or ["?"])[-1]
    return [
        _node(1, "Payload delivered via browser download (trigger)",
              _mk_tech("T1566.002", "Phishing: Malicious Link (delivery)", "Initial Access"),
              f"'{exe}' was recorded as downloaded. Delivery proves acquisition, not execution.",
              ["the file_downloaded event(s) cited below"],
              "The payload now sits on disk and awaits execution.",
              "If a user runs it, full SIM-C1-equivalent impact follows.",
              ["M1017 User Training",
               "M1033 Limit Software Installation"],
              {"event_types": ["file_downloaded"]},
              ""),
        _node(2, "Payload executed",
              _mk_tech("T1204.002", "Malicious File", "Execution"),
              f"A process named '{exe}' would confirm execution; its absence keeps this node predicted.",
              ["process_created matching " + exe],
              "Execution upgrades a routine download into a possible incident.",
              "Everything from SIM-C1 stages 2-6 becomes possible.",
              ["M1040 Behavior Prevention on Endpoint",
               "M1049 Antivirus/Antimalware"],
              {"event_types": ["process_created"]},
              ""),
        *_tail_persist_cred_exfil(),
    ]


def _observed_for(node: dict, events: list) -> list:
    """Return events satisfying the node's match spec (or [] if none)."""
    spec = node.get("match") or {}
    types = spec.get("event_types") or []
    markers = spec.get("markers") or []
    if not types and not markers:
        return []
    hits: list = []
    for e in events:
        if types and e["event_type"] not in types:
            continue
        if markers:
            hay = (str(e["process_name"]) + " " + str(e["command_line"] or "")).lower()
            if not any(m in hay for m in markers):
                continue
        hits.append(e)
    return hits


def generate(case_id: str) -> dict:
    events = query("SELECT * FROM events WHERE case_id=? ORDER BY ts_utc", (case_id,))
    if not events:
        return {"ok": True, "scenarios": 0,
                "note": "No normalized events to simulate from yet. Parse evidence first."}
    out: list = []
    for trig in _detect_triggers(events):
        nodes = _scenario_chain(trig["scenario"], trig, events)
        # clean late-binding entries: drop non-dict placeholders, renumber
        nodes = [n for n in nodes if isinstance(n, dict)]
        for i, n in enumerate(nodes, 1):
            hits = _observed_for(n, events)
            n["idx"] = i
            n["status"] = "observed" if hits else "predicted"
            n["event_ids"] = [e["id"] for e in hits][:40]
            n["evidence_ids"] = sorted({e["evidence_id"] for e in hits})
        observed = sum(1 for n in nodes if n["status"] == "observed")
        sev = trig["severity"]
        p = min(95, sev * 20 + 6 * observed)
        calc = {
            "formula": PRIO_FORMULA,
            "trigger_severity": sev, "observed_nodes": observed, "priority": p,
            "note": "rule-based scenario priority; not a probability of compromise",
        }
        out.append({
            "id": new_id("sim"), "case_id": case_id,
            "scenario_id": trig["scenario"],
            "title": SCENARIO_TITLES[trig["scenario"]],
            "trigger_rule": trig["rule"], "trigger_summary": trig["summary"],
            "trigger_event_ids": jdump([e["id"] for e in trig["events"]]),
            "evidence_ids": jdump(sorted({e["evidence_id"] for e in trig["events"]})),
            "severity_base": sev, "observed_count": observed,
            "depth": len(nodes), "priority": p, "priority_calc": jdump(calc),
            "nodes": jdump(nodes), "rule_version": RULES_VERSION,
            "created_at": now_iso(),
        })

    execute("DELETE FROM simulations WHERE case_id=?", (case_id,))
    for s in out:
        insert("simulations", s)
    trig_count = len(out)
    return {"ok": True, "scenarios": trig_count, "rule_version": RULES_VERSION,
            "version": RULES_VERSION}


SCENARIO_TITLES = {
    "SIM-C1_script_chain": "Malicious script: what typically happens next",
    "SIM-C2_usb_chain": "USB-delivered event: what typically happens next",
    "SIM-C3_credential_chain": "Credential guessing: what typically happens next",
    "SIM-C4_tamper_chain": "Log tampering: what typically happens next",
    "SIM-C5_download_chain": "Downloaded executable: what typically happens next",
}
