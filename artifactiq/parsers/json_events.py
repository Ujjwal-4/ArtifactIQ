"""JSON/JSONL event import parser with a documented mapping."""
from __future__ import annotations

import json
from pathlib import Path

from .base import BaseParser, ParseOutcome, ParserError
from ..util import timestamps as tsu
from ..util.ids import truncate

_FIELD_MAP = {
    "timestamp": "ts_raw", "time": "ts_raw", "datetime": "ts_raw", "ts_utc": "ts_utc_str",
    "event_type": "event_type_hint", "eventid": "event_code", "event_id": "event_code",
    "channel": "channel", "provider": "provider", "computer": "hostname",
    "hostname": "hostname", "host": "hostname",
    "user": "username", "username": "username", "account": "username", "sid": "user_sid",
    "process_name": "process_name", "image": "process_name", "process": "process_name",
    "process_id": "process_id", "pid": "process_id",
    "parent_process_id": "parent_process_id", "ppid": "parent_process_id",
    "command_line": "command_line", "cmdline": "command_line",
    "source_ip": "source_ip", "destination_ip": "destination_ip",
    "source_path": "source_path", "destination_path": "destination_path",
    "message": "message", "record_id": "record_id",
}


class JsonEventsParser(BaseParser):
    name = "json_events"
    media_types = ("json",)
    needs = ("stdlib json",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        try:
            raw = Path(str(path)).read_text(encoding="utf-8-sig", errors="replace").strip()
        except (OSError, UnicodeError) as exc:
            raise ParserError(f"JSON read failed: {exc}") from exc
        if not raw:
            return out
        records: list
        if raw[0] == "[":
            try:
                records = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ParserError(f"Malformed JSON array: {exc}") from exc
        else:
            records = []
            for li, line in enumerate(raw.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    out.errors.append({"raw_ref": f"line={li}", "message": "JSONL line not valid JSON; skipped"})
            if not records and raw[0] == "{":
                # single object with "events" list support
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict) and isinstance(obj.get("events"), list):
                        records = obj["events"]
                except json.JSONDecodeError as exc:
                    raise ParserError(f"Malformed JSON object: {exc}") from exc
        if not isinstance(records, list):
            raise ParserError("Top-level JSON must be an array of events or JSONL.")
        for i, rec in enumerate(records, 1):
            if len(out.events) >= limit:
                out.skipped += 1
                if out.skipped == 1:
                    out.warnings.append("Event limit reached; remaining records skipped.")
                break
            if not isinstance(rec, dict):
                out.errors.append({"raw_ref": f"record={i}", "message": "Event record is not a JSON object; skipped"})
                continue
            ev = {
                "ts_utc": None, "ts_original": None, "ts_precision": "unknown", "ts_source": None,
                "event_type": "json_event", "category": "json_import",
                "channel": None, "provider": None, "event_code": None, "record_id": None,
                "hostname": None, "username": None, "user_sid": None,
                "process_name": None, "process_id": None, "parent_process_id": None,
                "command_line": None, "source_ip": None, "destination_ip": None,
                "source_path": None, "destination_path": None, "confidence": None,
                "raw_ref": f"record={i}", "parser": self.name, "parser_version": "v2",
                "parse_status": "ok", "tags": ["json"],
            }
            for k, v in rec.items():
                tgt = _FIELD_MAP.get(str(k).lower())
                if not tgt or v in (None, ""):
                    continue
                if tgt == "ts_raw":
                    dt, prec, src = tsu.parse_common(str(v))
                    if dt and dt.tzinfo:
                        ev["ts_utc"] = tsu.to_utc_iso(dt)
                        ev["ts_precision"] = "utc"
                        ev["ts_source"] = "json_timestamp"
                    elif dt:
                        ev["ts_original"] = str(v)
                        ev["ts_precision"] = prec or "unknown"
                        ev["ts_source"] = "json_timestamp_no_tz"
                    else:
                        ev["ts_original"] = str(v)
                        ev["ts_precision"] = "unparsed"
                        ev["ts_source"] = "json_timestamp_unparsed"
                elif tgt == "ts_utc_str":
                    ev["ts_utc"] = str(v)
                    ev["ts_precision"] = "utc"
                    ev["ts_source"] = "json_ts_utc"
                elif tgt == "event_type_hint":
                    ev["event_type"] = str(v).lower().replace(" ", "_")
                    ev["category"] = _category_for(ev["event_type"])
                elif tgt == "message":
                    ev["tags"].append("has_message")
                    ev["destination_path"] = truncate(str(v), 400)
                else:
                    ev[tgt] = truncate(str(v), 500)
            if ev["ts_utc"] is None and ev["ts_original"] is None:
                ev["ts_precision"] = "missing"
                ev["ts_source"] = "no_timestamp"
            out.events.append(ev)
        return out


CATEGORY_HINTS = {
    "logon": "authentication", "logoff": "authentication", "account": "authentication",
    "process": "process", "service": "service", "task": "task", "network": "network",
    "file": "file", "registry": "registry", "usb": "usb", "download": "browser",
    "visit": "browser", "dns": "network",
}


def _category_for(event_type: str) -> str:
    for k, v in CATEGORY_HINTS.items():
        if k in event_type:
            return v
    return "json_import"
