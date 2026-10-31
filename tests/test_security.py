"""Security tests: traversal, CSRF, tamper detection, bad ids, path safety."""
from __future__ import annotations

import io
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def test_upload_rejects_path_traversal_names(client, context, tmp_path):
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "SEC-001", "title": "security test", "investigator": "tester", "mode": "full",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (io.BytesIO(b"AAAA"), "..\\..\\..\\windows\\evil.evtx"),
        "media_type": "csv", "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200
    name = r.get_json()["evidence"]["original_name"]
    # traversal components are stripped/sanitized, never stored
    assert ".." not in name and "\\" not in name and "/" not in name
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (io.BytesIO(b"AAAA2"), "../../etc/evil.evtx"),
        "media_type": "csv", "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200, r.get_json()
    assert "../../etc/evil.evtx" not in r.get_json()["evidence"]["original_name"]


def test_csrf_required_for_state_changes(client):
    r = client.post("/api/cases", data={
        "case_number": "SEC-002", "title": "security test", "investigator": "tester", "mode": "full",
    })
    assert r.status_code == 400


def test_bad_case_id_404_json(client):
    r = client.get("/api/cases/does_not_exist/timeline")
    assert r.status_code == 404
    assert r.get_json()["ok"] is False


def test_unknown_event_404(client):
    assert client.get("/api/events/nope").status_code == 404


def test_evidence_verify_detects_mutation(client, context, tmp_path):
    """If the preserved copy changes on disk, verify must report mismatch."""
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "SEC-003", "title": "security test", "investigator": "tester", "mode": "full",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (io.BytesIO(b"ORIGINAL BYTES"), "artifact.txt"),
        "media_type": "csv", "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    evid = r.get_json()["evidence"]["id"]
    r0 = client.post(f"/api/evidence/{evid}/verify", headers=H)
    assert r0.status_code == 200

    # mutate the stored copy directly (simulated divergence)
    from artifactiq.db import one
    row = one("SELECT * FROM evidence WHERE id=?", (evid,))
    from artifactiq.services.evidence import abs_path_of
    p = abs_path_of(row["data_path"])
    p.write_bytes(b"MUTATED BYTES!!!")

    r = client.post(f"/api/evidence/{evid}/verify", headers=H)
    j = r.get_json()
    ok_flag = j.get("ok") is False or j.get("result") == "mismatch" or \
        one("SELECT verify_status FROM evidence WHERE id=?", (evid,))["verify_status"] == "mismatch"
    assert ok_flag, j


def test_corrupt_upload_never_crashes_case(client):
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "SEC-004", "title": "security test", "investigator": "tester", "mode": "full",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (io.BytesIO(b"\x00\x01\xff\xfe garbage not json"), "BAD.json"),
        "media_type": "json", "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    assert r.status_code == 200
    evid = r.get_json()["evidence"]["id"]
    # parsing a corrupt artifact records failure honestly instead of 500
    r = client.post(f"/api/cases/{cid}/parse", json={}, headers=H)
    assert r.status_code == 200
    runs = r.get_json()["runs"]
    assert runs and runs[0]["status"] in ("failed", "unsupported", "completed_with_errors")


def test_case_delete_is_retention_aware(client, context):
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "SEC-005", "title": "security test", "investigator": "tester", "mode": "full",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.post(f"/api/cases/{cid}/delete",
                    json={"confirm": cid + ":DELETE"}, headers=H)
    assert r.status_code == 200
    from artifactiq.db import one
    # evidence is parked in retention, custody history is not erased
    n = one("SELECT COUNT(*) AS n FROM custody_records WHERE case_id=?", (cid,))["n"]
    assert n >= 1


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "object-src 'none'" in csp


def test_evidence_removed_files_parked_not_destroyed(client, context):
    H = client.csrf_header
    r = client.post("/api/cases", data={
        "case_number": "SEC-006", "title": "security test", "investigator": "tester", "mode": "full",
    }, headers=H)
    cid = r.get_json()["case_id"]
    r = client.post(f"/api/cases/{cid}/evidence", data={
        "file": (io.BytesIO(b"RETAIN ME"), "keep.txt"),
        "media_type": "csv", "csrf_token": "pytest-csrf-token",
    }, headers=H, content_type="multipart/form-data")
    evid = r.get_json()["evidence"]["id"]
    r = client.post(f"/api/evidence/{evid}/remove", data={"reason": "test"}, headers=H)
    assert r.status_code == 200
    from artifactiq.db import one
    row = one("SELECT * FROM evidence WHERE id=?", (evid,))
    # the row still exists with retention info rather than being hard-deleted
    assert row is not None and (row["verify_status"] == "retained" or row["notes"])
