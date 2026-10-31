"""Read-only evidence preview: see what is inside an attached file.

The preview opens the PRESERVED copy only, never writes, and reports a
SHA-256 cross-check. Text formats show a decoded snippet, SQLite shows
table names + row counts read-only, binaries show a hexdump. Nothing here
modifies evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def _mk_case(context, cid):
    from artifactiq.db import insert
    from artifactiq.util.ids import now_iso
    insert("cases", {"id": cid, "case_number": f"TEST-PV-{cid[-6:]}",
                     "title": "preview test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})


def _attach(context, tmp_path, cid, name, mt, content):
    from artifactiq.services import evidence as ev
    _mk_case(context, cid)
    src = tmp_path / name
    src.write_bytes(content)
    return ev.store_copy(cid, str(src), name, mt, "tester",
                         source_desc="test staging", notes="synthetic",
                         actor="tester")


def test_text_preview_decodes_and_verifies_hash(context, tmp_path):
    from artifactiq.services import evidence as ev
    row = _attach(context, tmp_path, "cs_pv_text", "usb.reg",
                  "registry_export",
                  b"Windows Registry Editor Version 5.00\r\n\r\n"
                  b"[HKEY_LOCAL_MACHINE\\SYSTEM\\USBSTOR]\r\n")
    d = ev.preview(row["id"])
    assert d["kind"] == "text"
    assert "USBSTOR" in d["snippet"]
    assert d["hash_check"]["status"] == "verified"
    assert d["hash_check"]["match"] is True
    assert d["read_only"] is True
    # honest note about the format's missing timestamps
    assert "timestamp" in d["note"]


def test_sqlite_preview_lists_tables_readonly(context, tmp_path):
    import sqlite3
    from artifactiq.services import evidence as ev
    row = _attach(context, tmp_path, "cs_pv_sql", "history.SQLite",
                  "browser_sqlite", b"")
    # overwrite the preserved copy with a real sqlite db (demo-scale)
    from artifactiq.services import evidence as evs
    abs_path = evs.abs_path_of(evs.get_evidence(row["id"])["data_path"])
    cn2 = sqlite3.connect(str(abs_path))
    cn2.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)")
    cn2.execute("INSERT INTO urls (url) VALUES ('http://a'), ('http://b')")
    cn2.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY)")
    cn2.commit()
    cn2.close()
    d = ev.preview(row["id"])
    assert d["kind"] == "sqlite"
    assert "urls" in d["snippet"] and "2 rows" in d["snippet"]
    assert "downloads" in d["snippet"]


def test_binary_preview_shows_hexdump(context, tmp_path):
    from artifactiq.services import evidence as ev
    row = _attach(context, tmp_path, "cs_pv_bin", "image.dd",
                  "disk_image", bytes(range(256)))
    d = ev.preview(row["id"])
    assert d["kind"] == "binary"
    assert d["snippet"].startswith("00000000")
    assert "|.| " not in d["snippet"]
    assert "|" in d["snippet"]


def test_missing_copy_and_missing_id_honest(context, tmp_path):
    from artifactiq.services import evidence as ev
    row = _attach(context, tmp_path, "cs_pv_miss", "note.txt", "text", b"hi")
    abs_path = ev.abs_path_of(ev.get_evidence(row["id"])["data_path"])
    abs_path.unlink()
    d = ev.preview(row["id"])
    assert d["kind"] == "unavailable"
    assert "missing" in d["note"]
    try:
        ev.preview("ev_nope")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_extracted_summary_counts_events(context, tmp_path):
    from artifactiq.db import insert
    from artifactiq.services import evidence as ev
    from artifactiq.util.ids import new_id, now_iso
    row = _attach(context, tmp_path, "cs_pv_ext", "events.json", "json", b"[]")
    cid = "cs_pv_ext"
    for i in range(2):
        insert("events", {"id": new_id("n"), "case_id": cid,
                          "evidence_id": row["id"], "run_id": new_id("run"),
                          "created_at": now_iso(), "event_type": "run_key_value",
                          "category": "registry", "ts_utc": now_iso(),
                          "ts_original": None, "ts_precision": "utc",
                          "ts_source": "fixture", "parser": "t",
                          "parser_version": "v", "parse_status": "ok",
                          "tags": "[]"})
    d = ev.preview(row["id"])
    assert d["extracted"]["total_events"] == 2
    assert d["extracted"]["by_event_type"][0]["event_type"] == "run_key_value"
    assert d["extracted"]["by_event_type"][0]["n"] == 2


def test_preview_api_roundtrip(client, context, tmp_path):
    from artifactiq.services import evidence as ev
    row = _attach(context, tmp_path, "cs_pv_api", "log.csv", "csv",
                  b"ts,cmd\n2025-08-17T22:28:00Z,certutil -urlcache\n")
    r = client.get(f"/api/evidence/{row['id']}/preview")
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] is True
    assert j["preview"]["kind"] == "text"
    assert "certutil" in j["preview"]["snippet"]
    r2 = client.get("/api/evidence/ev_missing/preview")
    assert r2.status_code == 404
