"""Windows Registry: .HIVE parsing via regipy (optional) and .reg text files.

The .reg text parser is fully self-contained and testable; hive parsing uses
the optional regipy library and reports unsupported status when absent.
"""
from __future__ import annotations

import re
from pathlib import Path

from .base import BaseParser, ParseOutcome, ParserError
from ..util import timestamps as tsu

_HIVE_HEADER = b"regf"
_LOCAL = dict(version=None)

_INTERESTING_KEYS = {
    "run": "run_key_value",
    "runonce": "run_key_value",
    "services": "service_registry",
    "usbstor": "usb_device",
    "mountpoints2": "usb_mount",
    "wifi": "network",
    "schedule": "task_registry",
}

# .reg value entry: "Name"=<type>:<data>  or  "Name"="string data"
_REG_ENTRY = re.compile(r'^\s*"([^"]+)"\s*=\s*(.+?)\s*$')
_VALUE_TYPE = re.compile(r'^(dword|hex(?:\(\d+\))?|multi_sz|expand_sz|qword)\s*:\s*(.*)$', re.IGNORECASE)


def _hexstr_to_int(s: str) -> int:
    s = (s or "").strip()
    try:
        return int(s, 16) if s else 0
    except ValueError:
        try:
            return int(s)
        except ValueError:
            return 0


class RegistryTextParser(BaseParser):
    """Parse plain-text .reg exports (regedit format)."""

    name = "registry_text"
    media_types = ("registry_export",)
    needs = ("stdlib re",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        current_key = ""
        tagbase = "registry"
        try:
            text = Path(str(path)).read_text(encoding="utf-16", errors="replace")
        except UnicodeError:
            try:
                text = Path(str(path)).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ParserError(f"Cannot read .reg file: {exc}") from exc
        except OSError as exc:
            raise ParserError(f"Cannot read .reg file: {exc}") from exc

        lineno = 0
        for line in text.splitlines():
            lineno += 1
            line = line.rstrip("\r")
            if line.startswith("["):
                current_key = line.strip("[]\\".replace("\\", "").replace("/", "")) or line
                current_key = line.strip("[]")
                current_key = current_key.rstrip("\\")
                # (strip leading \\ only when doubled)
                if current_key.startswith("\\"):
                    current_key = current_key[1:]
                continue
            if not line or line.startswith(";"):
                continue
            m = _REG_ENTRY.match(line)
            if not m:
                continue
            value_name, raw = m.group(1), m.group(2)
            vm = _VALUE_TYPE.match(raw)
            if vm:
                val_type, raw_data = vm.group(1).lower(), vm.group(2).strip()
            elif raw.startswith('"') and raw.endswith('"'):
                val_type, raw_data = "reg_sz", raw[1:-1]
            else:
                val_type, raw_data = "(unknown)", raw
            key_l = current_key.lower()
            etype, category = "generic_value", "registry"
            tags = ["registry"]
            if "usbstor" in key_l:
                etype, category = "usb_device", "usb"
                tags.append("usbstor")
            elif "mountpoints2" in key_l:
                etype, category = "usb_mount", "usb"
                tags.append("mountpoint")
            elif "runonce" in key_l:
                etype, category = "run_key", "persistence"
            elif "run" in key_l and "runonce" not in key_l:
                etype, category = "run_key", "persistence"
            elif "services" in key_l:
                etype, category = "service_registry", "service"
            ts_utc, ts_original, prec, src = None, None, "unknown", "no_timestamp"
            # Binary System_Stamp timestamps are opaque; we do not fake them.
            raw_ref = f"key={current_key};value={value_name};type={val_type}"
            events = []
            ev = {
                "ts_utc": ts_utc, "ts_original": ts_original, "ts_precision": prec, "ts_source": src,
                "event_type": etype, "category": category,
                "channel": "registry", "provider": "RedEditExport",
                "event_code": val_type or None, "record_id": None,
                "hostname": "HKLM" if key_l.upper().startswith("HKEY_LOCAL_MACHINE") else None,
                "username": None, "user_sid": None,
                "process_name": None, "process_id": None, "parent_process_id": None,
                "command_line": raw_data[:500] if val_type.lower() in ("hex(2)", "hex") and event_is_persist(etype) else None,
                "source_ip": None, "destination_ip": None,
                "source_path": current_key, "destination_path": value_name,
                "raw_ref": raw_ref, "parser": self.name, "parser_version": "v2",
                "parse_status": "ok", "confidence": 0.6, "tags": tags,
            }
            events.append(ev)
            out.events.append(ev)
            if len(out.events) >= limit:
                out.warnings.append("Value limit reached while parsing the .reg file.")
                break
        return out


def event_is_persist(etype):
    return etype in ("run_key", "run_key_value")


KEY_EXTRACT_HINTS = {
    event_is_persist("x"): None,
}

_AMD64TIMESTAMP = None


class RegistryHiveParser(BaseParser):
    """Live hive parsing via regipy (optional dependency)."""

    name = "registry_hive"
    media_types = ("registry_hive",)
    needs = ("regipy",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        try:
            from regipy.registry import RegistryHive
        except Exception as exc:
            out.errors.append({
                "raw_ref": "file",
                "message": f"regipy not available - hive left unparsed ({exc}). The copy is still intact in the evidence store.",
            })
            return out
        data = Path(str(path))
        if data.read_bytes()[:4] != b"regf":
            out.errors.append({"raw_ref": "file", "message": "File does not start with 'regf' magic; not a Windows registry hive."})
            return out
        try:
            hive = RegistryHive(str(path))
        except Exception as exc:
            raise ParserError(f"regipy could not open the hive: {exc}") from exc
        interesting = [k.lower() for k in (
            r"ControlSet001\Services", r"USBSTOR", r"CurrentVersion\Run",
            r"CurrentVersion\RunOnce",
        )]
        try:
            for entry in hive.recurse_subkeys(as_json=True):
                if len(out.events) >= limit:
                    out.warnings.append("Event limit reached while walking the hive.")
                    break
                sk_path = getattr(entry, "path", "") or ""
                sk_l = sk_path.lower()
                if not any(i in sk_l for i in interesting) and "usb" not in sk_l:
                    continue
                ts = getattr(entry, "timestamp", None)
                dt = ts if hasattr(ts, "tzinfo") else None
                try:
                    dt = ts if dt and dt.tzinfo else None
                except Exception:
                    dt = None
                values = getattr(entry.values, "values", None) or (getattr(entry, "values_str", []) or [])
                vv = getattr(entry, "values", [])
                for v in (vv if isinstance(vv, list) else []):
                    try:
                        name = v.get("name")
                        vtype = v.get("value_type")
                        vval = str(v.get("value"))[:400]
                    except Exception:
                        name, vtype, vval = "?", "?", "?"
                    etype, category = ("usb_device", "usb" if "usb" in sk_l else ("registry", "registry"))
                    if "services" in sk_l:
                        etype, category = "service_registry", "service"
                    if "run" in sk_l:
                        etype, category = "run_key", "persistence"
                    out.events.append({
                        "ts_utc": tsu.to_utc_iso(dt) if dt else None,
                        "ts_original": dt.isoformat() if dt else None,
                        "ts_precision": "utc_second" if dt else "unknown",
                        "ts_source": "hive key last-write (key level)",
                        "event_type": etype, "category": category,
                        "channel": "registry", "provider": "regipy",
                        "event_code": str(vtype or "unknown"), "record_id": None,
                        "hostname": None, "username": None, "user_sid": None,
                        "process_name": name, "process_id": None, "parent_process_id": None,
                        "command_line": vval if category in ("persistence",) else None,
                        "source_ip": None, "destination_ip": None,
                        "source_path": sk_path, "destination_path": name,
                        "raw_ref": f"hive_key={sk_path};value={name}",
                        "parser": self.name, "parser_version": "v2",
                        "parse_status": "ok", "confidence": 0.7, "tags": ["registry", "hive"],
                    })
        except Exception as exc:
            out.errors.append({"raw_ref": "hive_walk", "message": f"hive walk failed partway: {exc}"})
        return out
