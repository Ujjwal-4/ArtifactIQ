"""Windows USB device-history parser for setupapi.dev.log.

setupapi.dev.log records device installs (PNP IDs, VID/PID) with timestamps.
This parser is fully offline and testable; it does not read live USB state.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .base import BaseParser, ParseOutcome, ParserError
from ..util.ids import truncate

# e.g.  >>>  [Device Install (Hardware initiated) - USB\VID_1234&PID_5678\ABC001]
_INSTALL_HDR = re.compile(r">>>\s*\[(?P<hdr>[^\]]+)\]", re.IGNORECASE)
# Real logs show dates either in braces {2016-01-15 12:34:56.000} on dvi: lines
# or bare after "Section start" (slashes or dashes). We accept both variants.
_ANY_DATE = re.compile(
    r"(?P<dt>\d{4}[-/]\d{1,2}[-/]\d{1,2} \d{1,2}:\d{2}:\d{2}(?:\.\d+)?)")
_USB_PNP = re.compile(
    r"USB(?:\\|%5c|%2f)[^\s]*?VID_|USB\\", re.IGNORECASE
)


class UsbSetupApiParser(BaseParser):
    name = "usb_setupapi"
    media_types = ("usb_history",)
    needs = ("stdlib re",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        try:
            data = __import__("pathlib").Path(str(path)).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ParserError(f"Cannot read log: {exc}") from exc
        if not data.strip():
            return out

        current_dev = None
        current_ts = None
        recognized_sections = 0
        for lineno, line in enumerate(data.splitlines(), 1):
            # A "Section start" line carries the date; check it before the
            # generic date scan below, and before treating the bracket text
            # as a new device header.
            if current_dev and "Section start" in line:
                recognized_sections += 1
                md = _ANY_DATE.search(line)
                if md:
                    d = _date_to_dt(md.group("dt"))
                    if d:
                        current_ts = d
                iso = _iso(current_ts) if current_ts else None
                vidpid, serial = _split_usb_id(current_dev)
                out.events.append({
                    "ts_utc": iso,
                    "ts_original": current_ts.isoformat() if current_ts else None,
                    "ts_precision": "utc_second" if current_ts else ("unknown timestamp: header date line missing"),
                    "ts_source": "setupapi Section Date" if current_ts else "setupapi (no date found)",
                    "event_type": "usb_device_connected",
                    "category": "usb",
                    "channel": "setupapi.dev.log",
                    "provider": "SetupAPI",
                    "event_code": vidpid or None,
                    "record_id": None,
                    "process_name": None, "process_id": None, "parent_process_id": None,
                    "command_line": None,
                    "source_ip": None, "destination_ip": None,
                    "source_path": current_dev,
                    "destination_path": serial,
                    "raw_ref": f"line={lineno}",
                    "parser": self.name,
                    "parser_version": "v2",
                    "parse_status": "ok",
                    "confidence": 0.8,
                    "tags": ["usb", "setupapi", "device_install"],
                })
                current_dev = None
                current_ts = None
                if len(out.events) >= limit:
                    out.warnings.append("USB event limit reached; remaining records skipped.")
                    break
                continue
            lh = _INSTALL_HDR.search(line)
            if lh:
                current_dev = lh.group("hdr").strip()
                current_ts = None
                continue
            md = _ANY_DATE.search(line)
            if md:
                d = _date_to_dt(md.group("dt"))
                if d:
                    current_ts = d
                continue
        if not out.events and not recognized_sections:
            out.warnings.append("No 'Device Install' sections recognized; this may be a different log format.")
        return out


def _date_to_dt(s: str):
    s = s.replace("/", "-").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _iso(dt) -> str | None:
    try:
        dt = dt.astimezone(timezone.utc)
        # keep the source's fractional seconds (real logs carry e.g. ".100")
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"
    except (ValueError, OverflowError, OSError):
        return None


_SPLIT = re.compile(r"(VID_[0-9A-Za-z]{4})(?:&|%26)(PID_[0-9A-Za-z]{4})(?:&|%26)?(.*)", re.IGNORECASE)


def _split_usb_id(pnp):
    m = _SPLIT.search(pnp)
    if not m:
        return truncate(pnp, 80), ""
    return f"{m.group(1)}&{m.group(2)}", (m.group(3) or "").strip("\\\\")
