"""Integration: full workflow through the HTTP test client.

case -> evidence upload -> verify -> parse -> timeline -> graph -> attack ->
branches -> risk -> explanation -> reports -> phase refresh -> custody chain.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from artifactiq.demo_loader import _make_json  # noqa: E402


def _mk_events_file(tmp_path):
    p = tmp_path / "SYNTHETIC.json"
    _make_json(p)
    return p


def test_full_pipeline(client, tmp_path):
    H = client.csrf_header
    # 1. create case
    r = client.post("/api/cases", data={
        "case_number": "INT-2025-001", "title": "integration case",
        "investigator": "tester", "description": "", "scope": "test",
        "authorization": "test-only", "mode": "full",
    }, headers=H)
    assert r.status_code == 200
    cid = r.get_json()["case_id"]

    # 2. upload evidence (synthetic json events)
    f = _mk_events_file(tmp_path)
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (open(f, "rb"), "SYNTHETIC_events.json"),
        "media_type": "json",
        "notes": "synthetic test fixture",
        "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200, r.get_json()
    row = r.get_json()["evidence"]
    evid = row["id"]
    assert len(row["sha256"]) == 64

    # 3. verify integrity (fresh copy == intake hash)
    r = client.post(f"/api/evidence/{evid}/verify", headers=H)
    assert r.status_code == 200
    assert r.get_json()["result"] in ("verified", "ok") or r.get_json()["evidence"]["verify_status"] == "verified"

    # 4. parse all evidence
    r = client.post(f"/api/cases/{cid}/parse", json={}, headers=H)
    assert r.status_code == 200
    runs = r.get_json()["runs"]
    assert runs and any(x["events"] > 0 for x in runs)

    # 5. timeline
    r = client.get(f"/api/cases/{cid}/timeline")
    j = r.get_json()
    assert j["total"] >= 5

    # 6. rebuild graph + mappings
    r = client.post(f"/api/cases/{cid}/analyze", json={}, headers=H)
    assert r.status_code == 200
    r = client.get(f"/api/cases/{cid}/attack")
    j = r.get_json()
    assert any(m["technique_id"] == "T1059.001" for m in j["mappings"])

    # 6b. graph fetchable
    r = client.get(f"/api/cases/{cid}/graph")
    assert r.status_code == 200 and "nodes" in r.get_json()["graph"]

    # 7. branches + decide
    r = client.post(f"/api/cases/{cid}/branches/generate", json={}, headers=H)
    assert r.status_code == 200
    r = client.get(f"/api/cases/{cid}/branches")
    branches = r.get_json()["branches"]
    assert branches
    bid = [b for b in branches if b["status"] == "open"][0]["id"]
    r = client.post(f"/api/branches/{bid}/decide", json={"status": "confirmed", "note": "int"}, headers=H)
    assert r.status_code == 200 and r.get_json()["status"] == "confirmed"

    # 8. risk
    r = client.post(f"/api/cases/{cid}/risk", json={}, headers=H)
    assert r.status_code == 200
    risk = r.get_json()["risk"]
    assert 0 <= risk["score"] <= 100

    # 9. explanation
    r = client.get(f"/api/cases/{cid}/explanation")
    assert r.status_code == 200 and r.get_json()["sentences"]

    # 10. reports (html/json/manifest)
    for kind in ("html", "findings", "manifest"):
        r = client.post(f"/api/cases/{cid}/reports", json={"kind": kind}, headers=H)
        assert r.status_code == 200, r.get_json()
        rid = r.get_json()["report"]["id"]
        r = client.get(f"/api/reports/{rid}/download")
        assert r.status_code == 200 and len(r.data) > 100

    # 11. custody chain verifies after all writes
    r = client.get(f"/api/cases/{cid}/custody")
    j = r.get_json()
    assert j["verification"]["ok"], j["verification"]["issue"]
    # case_created + evidence_registered + hash_verified + parser_run
    assert j["verification"]["records_checked"] >= 4

    # 12. phase refresh
    r = client.post(f"/api/cases/{cid}/phases/refresh", headers=H)
    sm = r.get_json()["phases"]
    assert sm["p01_cases"]["status"] == "completed"
    assert sm["p12_reports"]["status"] == "completed"


def test_targeted_case_exposes_no_full_tabs(client):
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "INT-TGT-001", "title": "targeted", "investigator": "tester",
        "mode": "targeted", "capability": "usb_check",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.get(f"/cases/{cid}/overview")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    # targeted mode does not show full-case tabs like graph/attack
    assert "/graph" not in html
