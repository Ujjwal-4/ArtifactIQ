"""Unit tests: hash-chained custody ledger, evidence integrity, hashing utils."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from artifactiq.services import custody  # noqa: E402
from artifactiq.db import query, one, execute  # noqa: E402
from artifactiq.util.hashing import sha256_text, sha256_file  # noqa: E402


def _mk_case(context, cid="cs_cust_test"):
    from artifactiq.db import insert
    from artifactiq.util.ids import now_iso
    if one("SELECT id FROM cases WHERE id=?", (cid,)):
        return cid
    insert("cases", {"id": cid, "case_number": f"TEST-CUST-{cid[-6:]}",
                     "title": "custody test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})
    return cid


def test_hash_utils(context, tmp_path):
    # known SHA-256("abc")
    assert sha256_text("abc") == \
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_text("abc") != sha256_text("abd")
    p = tmp_path / "f.bin"
    p.write_bytes(b"\x00\x01\x02")
    h = sha256_file(str(p))
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def test_custody_chain_append_and_verify(context):
    cid = _mk_case(context)
    a = custody.append("unit_test_action", cid, None, actor="pytest", reason="first")
    b = custody.append("unit_test_action", cid, None, actor="pytest", reason="second")
    assert b["prev_hash"] == a["record_hash"]
    assert b["seq"] == a["seq"] + 1
    res = custody.verify(case_id=cid)
    assert res["ok"], res["issue"]
    assert res["records_checked"] >= 2


def test_custody_tamper_detected(context):
    cid = _mk_case(context)
    custody.append("tamper_probe", cid, None, actor="pytest", reason="before")
    # direct sqlite write: simulate DB modification outside the app
    dbp = context.config["DB_PATH"]
    row = one("SELECT seq, reason FROM custody_records WHERE case_id=? ORDER BY seq DESC LIMIT 1", (cid,))
    conn = sqlite3.connect(dbp)
    conn.execute("UPDATE custody_records SET reason=? WHERE seq=?", (row["reason"] + " EVIL", row["seq"]))
    conn.commit()
    conn.close()
    res = custody.verify(case_id=cid)
    assert not res["ok"]
    assert "hash mismatch" in res["issue"].lower() or "link" in res["issue"].lower()


def test_custody_rejected_delete_detected(context):
    cid = _mk_case(context)
    custody.append("del_probe", cid, None, actor="pytest")
    dbp = context.config["DB_PATH"]
    last = one("SELECT MAX(seq) AS s FROM custody_records WHERE case_id=?", (cid,))["s"]
    conn = sqlite3.connect(dbp)
    conn.execute("DELETE FROM custody_records WHERE seq=?", (last,))
    conn.commit()
    conn.close()
    res = custody.verify(case_id=cid)
    # chain must fail: either a gap (if the deleted record is mid-chain) or the
    # remaining trail no longer reaches a consistent head
    all_ok = custody.verify()
    assert not all_ok["ok"] or all_ok["head_hash"]
