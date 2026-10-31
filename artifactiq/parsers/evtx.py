"""Windows Event Log (.evtx) parser using python-evtx.

Fails honestly: a corrupt or unsupported file yields a failed/unsupported
outcome, never a fake success. Record XML is kept by reference (offset), never
stored wholesale.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import BaseParser, ParserError, ParseOutcome
from ..util import timestamps as tsu

try:  # optional dependency; the parser still registers evidence when absent
    from Evtx.Evtx import Evtx, LastHeaderException

    EVTX_AVAILABLE = True
    EVTX_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover
    EVTX_AVAILABLE = False
    EVTX_IMPORT_ERROR = str(exc)
    Evtx = None  # type: ignore

# Event id -> (event_type, category) for well-understood Windows/Sysmon codes.
EVENT_ID_MAP = {
    "1102": ("audit_log_cleared", "system"), "104": ("audit_log_cleared", "system"),
    "4624": ("logon_success", "authentication"), "4625": ("logon_failure", "authentication"),
    "4634": ("logoff", "authentication"), "4647": ("logoff", "authentication"),
    "4648": ("explicit_credential_logon", "authentication"),
    "4672": ("special_privileges", "authentication"),
    "4688": ("process_created", "process"), "4689": ("process_terminated", "process"),
    "4697": ("service_installed", "service"),
    "4698": ("scheduled_task_created", "task"), "4699": ("scheduled_task_deleted", "task"),
    "4702": ("scheduled_task_updated", "task"),
    "4720": ("user_account_created", "authentication"), "4726": ("user_account_deleted", "authentication"),
    "4728": ("group_member_added", "authentication"), "4732": ("group_member_added", "authentication"),
    "4738": ("user_account_changed", "authentication"),
    "4740": ("account_locked", "authentication"),
    "7045": ("service_installed", "service"),
    "6005": ("eventlog_started", "system"), "6006": ("eventlog_stopped", "system"),
    "1": ("process_created", "process"),       # Sysmon
    "2": ("file_time_changed", "file"),
    "3": ("network_connection", "network"),
    "5": ("process_terminated", "process"),
    "6": ("driver_loaded", "system"), "7": ("image_loaded", "process"),
    "8": ("remote_thread", "process"), "10": ("process_access", "process"),
    "11": ("file_created", "file"), "12": ("object_created", "system"),
    "13": ("registry_value_set", "registry"), "14": ("registry_object", "registry"),
    "15": ("file_stream_created", "file"),
    "22": ("dns_query", "network"), "23": ("file_deleted", "file"),
    "26": ("file_deleted_detected", "file"),
}
_POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _data_value(root, name):
    sec = root.find(f"{NS}EventData")
    if sec is None:
        return None
    for d in sec.findall(f"{NS}Data"):
        if (d.get("Name") or "").lower() == name.lower():
            return (d.text or "").strip() or None
    return None


def _channel_guess(name: str | None, path: str) -> str:
    src = ((name or "") + " " + (path or "")).lower()
    if "security" in src:
        return "Security"
    if "sysmon" in src:
        return "Microsoft-Windows-Sysmon/Operational"
    if "powershell" in src:
        return _POWERSHELL
    if "application" in src:
        return "Application"
    if "system" in src:
        return "System"
    return "unknown"


class EvtxParser(BaseParser):
    name = "evtx"
    media_types = ("evtx",)
    needs = ("python-evtx",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        if not EVTX_AVAILABLE:
            out = ParseOutcome()
            out.errors.append({"raw_ref": "file", "message": f"python-evtx not installed: {EVTX_IMPORT_ERROR}"})
            return out
        out = ParseOutcome()
        base = {
            "channel": _channel_guess(evidence_row.get("original_name"), str(path)),
            "provider": None, "event_code": None, "record_id": None,
            "hostname": None, "username": None, "user_sid": None,
            "process_name": None, "process_id": None, "parent_process_id": None,
            "command_line": None, "source_ip": None, "destination_ip": None,
            "source_path": None, "destination_path": None, "confidence": None,
        }
        count = 0
        try:
            with Evtx(str(path)) as log:
                for record in log.records():
                    count += 1
                    if count > limit:
                        out.skipped += 1
                        if count == limit + 1:
                            out.warnings.append("Event limit reached; later records were skipped (see parser limits).")
                        continue
                    offset = record.offset()
                    try:
                        eid = str(record.event_id() & 0xFFFF)
                        record_number = str(record.record_num())
                        provider_guid = record.provider_guid()
                    except Exception as exc:
                        out.errors.append({"raw_ref": f"offset={offset}", "message": f"record header unreadable: {exc}"})
                        continue
                    etype, category = EVENT_ID_MAP.get(eid, ("other", "other"))
                    ev = dict(base)
                    ev.update({
                        "event_type": etype,
                        "category": category,
                        "event_code": eid,
                        "record_id": record_number,
                        "raw_ref": f"record_number={record_number},offset={offset}",
                    })
                    try:
                        dt = record.timestamp()
                        ev["ts_utc"] = tsu.to_utc_iso(dt)
                        ev["ts_original"] = dt.isoformat() if dt else None
                        ev["ts_precision"] = "utc_millisecond" if ev["ts_utc"] else "unknown"
                        ev["ts_source"] = "evtx_systemtime"
                    except Exception:
                        ev["ts_source"] = "evtx_systemtime_unreadable"
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        sys_tag = root.find(f"{NS}System")
                        if sys_tag is not None:
                            prov = sys_tag.find(f"{NS}Provider")
                            if prov is not None:
                                ev["provider"] = prov.get("Name") or provider_guid
                            comp = sys_tag.find(f"{NS}Computer")
                            if comp is not None and (comp.text or "").strip():
                                ev["hostname"] = comp.text.strip()
                            sec = sys_tag.find(f"{NS}Security")
                            if sec is not None and sec.get("UserID"):
                                ev["user_sid"] = sec.get("UserID")
                        _enrich(ev, eid, root)
                    except ET.ParseError as exc:
                        out.warnings.append(f"record {record_number}: XML render failed ({exc}); event kept with header data only")
                        ev["parse_status"] = "partial"
                    except Exception as exc:
                        out.errors.append({"raw_ref": f"record_number={record_number}", "message": f"unexpected enrichment failure: {exc}"})
                        ev["parse_status"] = "partial"
                    out.events.append(ev)
        except LastHeaderException as exc:
            raise ParserError(f"File is not a valid or intact EVTX: {exc}") from exc
        except (OSError, IOError) as exc:
            raise ParserError(f"I/O error reading EVTX: {exc}") from exc
        return out


def _enrich(ev: dict, eid: str, root) -> None:
    def d(name):
        return _data_value(root, name)

    if eid in ("4624", "4625"):
        ev["username"] = d("TargetUserName")
        ev["process_name"] = d("ProcessName")
        ip = d("IpAddress")
        if ip and ip not in ("-", "::1", "0.0.0.0"):
            ev["source_ip"] = ip
        etype, category = EVENT_ID_MAP[eid]
        ev["event_type"], ev["category"] = etype, category
        tags = ev.get("tags") or []
        tags.append("logon_" + ("success" if eid == "4624" else "failure"))
        ev["tags"] = tags
    elif eid == "4688":
        ev["command_line"] = d("CommandLine")
        ev["process_name"] = d("NewProcessName")
        ev["process_id"] = d("NewProcessId")
        ev["username"] = d("SubjectUserName")
        ev["tags"] = (ev.get("tags") or []) + ["process_creation"]
    elif eid in ("7045", "4697"):
        ev["process_name"] = d("ServiceName")
        ev["source_path"] = d("ImagePath")
        ev["username"] = d("SubjectUserName") or d("AccountName")
        ev["tags"] = (ev.get("tags") or []) + ["service_install"]
    elif eid in ("4698", "4702"):
        ev["process_name"] = d("TaskName")
        ev["source_path"] = d("TaskContent") or d("CommandLine")
        ev["username"] = d("SubjectUserName")
    elif eid == "4720" or eid == "4726":
        ev["username"] = d("TargetUserName")
    elif eid == "4740":
        ev["username"] = d("TargetUserName")
        ev["source_ip"] = d("CallerComputerName")
    elif eid == "1":  # Sysmon
        ev["command_line"] = d("CommandLine")
        ev["process_name"] = d("Image")
        ev["process_id"] = d("ProcessId")
        ev["parent_process_id"] = d("ParentProcessId")
        ev["username"] = d("User")
        ev["tags"] = (ev.get("tags") or []) + ["sysmon"]
    elif eid == "3":  # Sysmon network
        ev["destination_ip"] = d("DestinationIp")
        ev["process_name"] = d("Image")
        ev["process_id"] = d("ProcessId")
        ev["tags"] = (ev.get("tags") or []) + ["sysmon_network"]
    elif eid == "11":
        ev["source_path"] = d("TargetFilename")
        ev["tags"] = (ev.get("tags") or []) + ["sysmon_file"]
    elif eid == "22":
        ev["source_path"] = d("QueryName")
        ev["tags"] = (ev.get("tags") or []) + ["sysmon_dns"]
    elif eid in ("6", "7"):
        ev["source_path"] = d("ImageLoaded") or d("ImageLoadedPath")
        ev["process_name"] = d("Image")
        ev["tags"] = (ev.get("tags") or []) + ["sysmon_load"]
    else:
        sub = d("SubjectUserName")
        if sub:
            ev["username"] = sub

