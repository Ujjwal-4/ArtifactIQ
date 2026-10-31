"""CSV event-log parser with a documented column allow-list.

Real exports from other SIEM/tooling are common; the columns below map to the
normalized schema. Unknown columns are ignored but the row is kept.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .base import BaseParser, ParseOutcome, ParserError
from ..util import timestamps as tsu
from ..util.ids import truncate

COLUMN_MAP = {
    "timestamp": "ts_raw", "time": "ts_raw", "date": "ts_raw", "timecreated": "ts_raw",
    "eventtime": "ts_raw", "@timestamp": "ts_raw", "datetime": "ts_raw",
    "eventid": "event_code", "event_id": "event_code", "id": "event_code",
    "event_type": "event_type_hint", "eventtype": "event_type_hint",
    "level": "level", "logname": "channel", "channel": "channel", "source": "provider",
    "provider": "provider", "computer": "hostname", "hostname": "hostname", "host": "hostname",
    "user": "username", "username": "username", "account": "username", "sid": "user_sid",
    "targetuser": "username_fill", "subjectuser": "username_fill", "subjectusername": "username_fill",
    "process": "process_name", "processname": "process_name", "image": "process_name",
    "newprocessname": "process_name_fill", "newprocess": "process_name_fill",
    "newprocessname_new": "process_name_fill",
    "servicename": "process_name_fill", "taskname": "process_name_fill",
    "pid": "process_id", "processid": "process_id", "ppid": "parent_process_id",
    "parentprocessid": "parent_process_id",
    "commandline": "command_line", "cmdline": "command_line", "message": "message",
    "message_raw": "message",
    "sourceip": "source_ip", "src_ip": "source_ip", "sourceip": "source_ip", "ipaddress": "source_ip",
    "destinationip": "destination_ip", "dest_ip": "destination_ip", "dst": "destination_ip",
    "sourcepath": "source_path", "src_path": "source_path", "path": "source_path",
    "destinationpath": "destination_path", "dst_path": "destination_path",
    "recordid": "record_id", "record_id": "record_id", "eventrecordid": "record_id",
}

TYPE_BY_CODE = {
    "4624": ("logon_success", "authentication"),
    "4625": ("logon_failure", "authentication"),
    "4688": ("process_created", "process"),
    "4648": ("explicit_credential_logon", "authentication"),
    "4698": ("scheduled_task_created", "task"),
    "4697": ("service_installed", "service"),
    "7045": ("service_installed", "service"),
    "4720": ("user_account_created", "authentication"),
    "4726": ("user_account_deleted", "authentication"),
    "4740": ("account_locked", "authentication"),
    "1102": ("audit_log_cleared", "system"),
    "3": ("network_connection", "network"),
    "1": ("process_created", "process"),
    "22": ("dns_query", "network"),
}


class CsvEventsParser(BaseParser):
    name = "csv_events"
    media_types = ("csv",)
    needs = ("stdlib csv",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        parser_name = self.name
        try:
            with open(str(path), "r", encoding="utf-8-sig", newline="") as fh:
                sample = fh.read(4096)
                fh.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(fh, dialect=dialect)
                headers = [h.strip() for h in (reader.fieldnames or [])]
                if not headers:
                    raise ParserError("CSV has no header row; cannot map columns.")
                mapped = {h: COLUMN_MAP.get(h.strip().lower()) for h in headers}
                if not any(mapped.values()):
                    raise ParserError(
                        "No recognizable header columns; cannot map CSV to the "
                        "normalized schema (unknown format, not an event export).")
                for i, row in enumerate(reader, 2):
                    if len(out.events) >= limit:
                        out.skipped += 1
                        if out.skipped == 1:
                            out.warnings.append("Row limit reached; remaining rows skipped.")
                        continue
                    ev = {
                        "ts_utc": None, "ts_original": None, "ts_precision": "unknown",
                        "ts_source": None, "event_type": "csv_event", "category": "csv_import",
                        "channel": None, "provider": None, "event_code": None, "record_id": None,
                        "hostname": None, "username": None, "user_sid": None,
                        "process_name": None, "process_id": None, "parent_process_id": None,
                        "command_line": None, "source_ip": None, "destination_ip": None,
                        "source_path": None, "destination_path": None, "confidence": None,
                        "raw_ref": f"row={i}", "parser": parser_name, "parser_version": "v2",
                        "parse_status": "ok", "tags": ["csv"],
                    }
                    missing_required = 0
                    for h, target in mapped.items():
                        if not target:
                            continue
                        v = (row.get(h) or "").strip()
                        if not v or v == "-":
                            # "-" is a common SIEM placeholder for "no value":
                            # keep it out of the normalized record entirely.
                            continue
                        if target == "ts_raw":
                            dt, prec, src = tsu.parse_common(v)
                            if dt and dt.tzinfo:
                                ev["ts_utc"] = tsu.to_utc_iso(dt)
                                ev["ts_precision"] = "utc" if src == "string_utc" else "utc_offset"
                                ev["ts_source"] = "csv_timestamp"
                            else:
                                ev["ts_original"] = v
                                ev["ts_precision"] = prec or "unknown"
                                ev["ts_source"] = "csv_timestamp_unparsed" if not dt else "csv_timestamp_no_tz"
                        elif target == "event_type_hint":
                            ev["event_type"] = v.lower().replace(" ", "_")
                            ev["category"] = _category_for(ev["event_type"])
                        elif target == "event_code":
                            ev["event_code"] = v
                            pair = TYPE_BY_CODE.get(v)
                            if pair and ev["event_type"] == "csv_event":
                                ev["event_type"], ev["category"] = pair
                        elif target == "process_name_fill":
                            # ServiceName / TaskName / NewProcessName style columns
                            # only fill process_name when the main columns had none.
                            if not ev["process_name"]:
                                ev["process_name"] = v
                        elif target == "username_fill":
                            # TargetUser / SubjectUser style columns only fill the
                            # username when the main columns had none.
                            if not ev["username"]:
                                ev["username"] = v
                        elif target == "message":
                            if v and not ev["command_line"]:
                                ev["tags"].append("has_message")
                            ev["destination_path"] = truncate(v, 400) if not ev["destination_path"] else ev["destination_path"]
                        else:
                            ev[target] = v
                    if ev["ts_utc"] is None and ev["ts_original"] is None:
                        ev["ts_precision"] = "missing"
                        ev["ts_source"] = "no_timestamp_column"
                        missing_required += 1
                    if missing_required:
                        out.warnings.append("Some rows have no usable timestamp; kept with ts_precision=missing.")
                    out.events.append(ev)
        except (OSError, UnicodeError) as exc:
            raise ParserError(f"CSV read failed: {exc}") from exc
        return out


_CATEGORY_HINTS = {
    "logon": "authentication", "logoff": "authentication", "account": "authentication",
    "process": "process", "service": "service", "task": "task", "network": "network",
    "file": "file", "registry": "registry", "usb": "usb", "download": "browser",
    "visit": "browser", "dns": "network",
}


def _category_for(event_type: str) -> str:
    for k, v in _CATEGORY_HINTS.items():
        if k in event_type:
            return v
    return "csv_import"
