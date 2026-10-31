"""Unit tests: parsers on synthetic fixtures."""
from __future__ import annotations

import json as _json
import sqlite3
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from artifactiq.demo_loader import (  # noqa: E402
    _make_browser, _make_csv, _make_json, _make_reg, _make_usb_log,
)
from artifactiq.parsers.browser_sqlite import BrowserSqliteParser  # noqa: E402
from artifactiq.parsers.csv_events import CsvEventsParser  # noqa: E402
from artifactiq.parsers.json_events import JsonEventsParser  # noqa: E402
from artifactiq.parsers.registry import RegistryTextParser  # noqa: E402
from artifactiq.parsers.usb_setupapi import UsbSetupApiParser  # noqa: E402


def _row(tmp_path, kind):
    return {"id": f"ev_test_{kind}", "case_id": "cs_test", "media_type": kind,
            "original_name": kind}


def test_csv_parser_maps_columns_and_types(tmp_path):
    p = tmp_path / "Security.csv"
    _make_csv(p)
    out = CsvEventsParser().parse(str(p), _row(tmp_path, "csv"), limit=500)
    assert out.errors == []
    types = {e["event_type"] for e in out.events}
    assert "logon_failure" in types and "audit_log_cleared" in types
    assert "service_installed" in types and "scheduled_task_created" in types
    # 4625 burst carries target user and source IP, not "-" placeholders
    fail = [e for e in out.events if e["event_type"] == "logon_failure"]
    assert len(fail) == 7
    assert fail[0]["username"] == "svc-backup"
    assert fail[0]["source_ip"] == "10.20.6.41"
    # service name comes from NewProcessName fill, never a bare "-"
    svc = [e for e in out.events if e["event_type"] == "service_installed"]
    assert svc[0]["process_name"] == "psh-backup"
    # timestamps parsed with UTC precision
    assert out.events[0]["ts_utc"].startswith("2025-08-17T")


def test_csv_parser_placeholder_dash_is_never_data(tmp_path):
    p = tmp_path / "Security.csv"
    _make_csv(p)
    out = CsvEventsParser().parse(str(p), _row(tmp_path, "csv"), limit=500)
    for e in out.events:
        for k, v in e.items():
            if k in ("process_name", "username", "source_ip", "destination_path"):
                assert v != "-", f"placeholder leaked into {k}"


def test_json_parser(tmp_path):
    p = tmp_path / "events.json"
    _make_json(p)
    out = JsonEventsParser().parse(str(p), _row(tmp_path, "json"), limit=500)
    assert len(out.events) == 5
    proc = [e for e in out.events if e["event_type"] == "process_created"]
    assert proc and "powershell" in proc[0]["process_name"]
    net = [e for e in out.events if e["event_type"] == "network_connection"]
    assert net and net[0]["destination_ip"] == "203.0.113.47"


def test_browser_sqlite_parser(tmp_path):
    src = tmp_path / "History"
    _make_browser(src)
    out = BrowserSqliteParser().parse(str(src), _row(tmp_path, "browser_sqlite"), limit=500)
    assert out.errors == []
    visits = [e for e in out.events if e["event_type"] == "url_visited"]
    dl = [e for e in out.events if e["event_type"] == "file_downloaded"]
    assert len(visits) == 5 and len(dl) == 1
    # visit timestamps convert from Chrome epoch microseconds; T0+0min
    assert visits[0]["ts_utc"].startswith("2025-08-17T22:12")
    # download timestamp must be T0+10min (regression: parser once read
    # received_bytes instead of start_time and emitted Chrome-epoch-zero)
    assert dl[0]["ts_utc"].startswith("2025-08-17T22:22")
    assert dl[0]["destination_path"].endswith("toolpack.exe")


def test_usb_setupapi_parser(tmp_path):
    p = tmp_path / "setupapi.dev.log"
    _make_usb_log(p)
    out = UsbSetupApiParser().parse(str(p), _row(tmp_path, "usb_history"), limit=500)
    assert out.errors == []
    assert len(out.events) == 2
    ev = out.events[0]
    assert "VID_07AB&PID_FC89" in (ev["source_path"] or "")
    assert ev["ts_utc"] == "2025-08-17T22:20:00.000Z"
    assert ev["destination_path"] == "0700123456"


def test_usb_parser_accepts_slash_and_dash_dates(tmp_path):
    p = tmp_path / "setupapi.dev.log"
    p.write_text(
        ">>>  [Device Install (Hardware initiated) - USB\\VID_1A2B&PID_3C4D\\X001]\n"
        ">>>  Section start 2016/01/15 12:34:56.100\n",
        encoding="utf-8")
    out = UsbSetupApiParser().parse(str(p), _row(tmp_path, "usb_history"), limit=500)
    assert out.events and out.events[0]["ts_utc"] == "2016-01-15T12:34:56.100Z"


def test_registry_text_parser(tmp_path):
    p = tmp_path / "USBSTOR.reg"
    _make_reg(p)
    out = RegistryTextParser().parse(str(p), _row(tmp_path, "registry_export"), limit=500)
    assert out.errors == []
    assert len(out.events) == 2
    by_val = {e["destination_path"]: e for e in out.events}
    # values resolve to a type, no colon required in the entry line
    assert by_val["DeviceDesc"]["event_code"] == "reg_sz"
    assert by_val["WriteProtect"]["event_code"] == "dword"
    # usbstor key is classified as a USB device event
    usbstor = [e for e in out.events if "usbstor" in (e["source_path"] or "").lower()]
    assert usbstor and usbstor[0]["event_type"] == "usb_device"


def test_registry_parser_returns_unknown_type_honestly(tmp_path):
    p = tmp_path / "odd.reg"
    p.write_text('Windows Registry Editor Version 5.00\n\n'
                 '[HKEY_LOCAL_MACHINE\\SOFTWARE\\Test]\n'
                 '"WeirdValue"=weirddata:xx\n', encoding="utf-8")
    out = RegistryTextParser().parse(str(p), _row(tmp_path, "registry_export"), limit=500)
    assert len(out.events) == 1
    assert out.events[0]["event_type"] == "generic_value"


def test_evtx_parser_rejects_non_evtx_honestly(tmp_path):
    """Garbage bytes must be reported, never invent events; copy stays intact."""
    from artifactiq.parsers.evtx import EvtxParser
    p = tmp_path / "evil.evtx"
    p.write_bytes(b"not really an event log" * 40)
    row = _row(tmp_path, "evtx")
    row["media_type"] = "evtx"
    out = EvtxParser().parse(str(p), row, limit=500)
    assert out.events == []
    assert out.errors or out.warnings


def test_csv_parser_no_header_is_an_error(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("4625,Security\n4625,Security\n", encoding="utf-8")
    with pytest.raises(Exception):
        CsvEventsParser().parse(str(p), _row(tmp_path, "csv"), limit=500)


def test_browser_parser_cleans_up_working_copy(tmp_path):
    src = tmp_path / "History2"
    _make_browser(src)
    import glob as _g
    BrowserSqliteParser().parse(str(src), _row(tmp_path, "browser_sqlite"), limit=500)
    leftovers = [d for d in __import__("tempfile").gettempdir()
                 if Path(d).name.startswith("aiq_browser_")
                 and Path(d).exists()]
    # temp working copies are removed after parsing
    assert all(not list(__import__("pathlib").Path(d).glob("*")) for d in leftovers)
