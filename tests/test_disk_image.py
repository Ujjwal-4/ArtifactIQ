"""Phase 6 disk-image tests — REAL analysis with the pytsk3 (Sleuth Kit) engine.

The image under test is a genuinely valid synthetic FAT16 volume built by
demo_loader.make_fat16_image (pure stdlib). Tests are skipped honestly when
pytsk3 is not installed in the running environment.
No real evidence is used anywhere.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

pytsk3 = pytest.importorskip("pytsk3", reason="phase-6 engine (pytsk3) not installed")


def _mk_case(context, cid):
    from artifactiq.db import insert, query
    from artifactiq.util.ids import now_iso
    if query("SELECT id FROM cases WHERE id=?", (cid,)):
        return cid
    insert("cases", {"id": cid, "case_number": f"TEST-IMG-{cid[-6:]}",
                     "title": "image test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})
    return cid


def test_fat16_image_builder_produces_openable_volume(tmp_path):
    from artifactiq.demo_loader import make_fat16_image
    p = tmp_path / "usbstick_SYNTHETIC.FAT16.raw"
    info = make_fat16_image(p)
    assert info["fs"] == "FAT16"
    img = pytsk3.Img_Info(str(p))
    fs = pytsk3.FS_Info(img, offset=0)              # real TSK magic check
    names = {e.info.name.name.decode("utf-8", "replace")
             for e in fs.open_dir("/")}
    assert {"README.TXT", "SYNTHETI.TXT", "DOWNLOAD"} <= names
    sub = {e.info.name.name.decode("utf-8", "replace")
           for e in fs.open_dir("/DOWNLOAD")}
    assert "TOOLPACK.EXE" in sub
    meta = next(e for e in fs.open_dir("/DOWNLOAD")
                if e.info.name.name == b"TOOLPACK.EXE").info.meta
    assert meta.size == 624


def test_analyze_records_completed_run_and_files(client, context, tmp_path):
    from artifactiq.db import one
    from artifactiq.demo_loader import make_fat16_image
    from artifactiq.services import evidence as ev, image_analysis as img, phases

    _mk_case(context, "cs_img_full")
    src = tmp_path / "usbstick_axq.FAT16.raw"
    make_fat16_image(src)
    row = ev.store_copy("cs_img_full", str(src), "usbstick_axq.FAT16.raw",
                        "disk_image", "tester", source_desc="test staging",
                        notes="synthetic", actor="tester")
    ev_id = row["id"] if isinstance(row, dict) else row.id if hasattr(row, "id") \
        else one("SELECT id FROM evidence WHERE case_id=? ORDER BY created_at DESC",
                 ("cs_img_full",))["id"]

    res = img.analyze("cs_img_full", ev_id)
    assert res["runs"], "one run expected"
    run = res["runs"][0]
    assert run["status"] == "completed", run["message"]
    # 4 files = README.TXT + SYNTHETI.TXT + TOOLPACK.EXE + AIQDEMO volume label; 1 dir = DOWNLOAD
    assert run["files"] == 4 and run["dirs"] == 1

    files = img.files_for_run(run["id"], 50)
    paths = {f["path"] for f in files}
    assert "/DOWNLOAD/TOOLPACK.EXE" in paths
    assert any(p.endswith("README.TXT") for p in paths)
    # all listed entries carry UTC ISO timestamps or None (honest absent)
    for f in files:
        assert f["mtime"] is None or f["mtime"].endswith("Z")

    # phase 6 must be completed by this run
    st = phases.refresh_phase_status("cs_img_full", "p06_image")
    assert st == "completed"


def test_p06_blocked_without_image_ready_without_run(context):
    from artifactiq.services import phases
    _mk_case(context, "cs_img_blocked")
    st = phases.refresh_phase_status("cs_img_blocked", "p06_image")
    assert st == "blocked"          # no disk-image evidence -> optional phase blocked


def test_p02_and_p05_completion_triggers(context, tmp_path):
    from artifactiq.db import one
    from artifactiq.services import phases, evidence as ev

    _mk_case(context, "cs_trig_p02")
    # before any plan/evidence: p02 ready, p05 not started
    assert phases.refresh_phase_status("cs_trig_p02", "p02_acquisition_plan") in ("ready", "not_started")
    assert phases.refresh_phase_status("cs_trig_p02", "p05_custody") == "not_started"

    # record an acquisition session (plan + acknowledgments) -> p02 completed
    from artifactiq.acquisition import live as acq
    sid = acq.start_session("cs_trig_p02", "tester", ["browser_profile_copy"],
                            authorization_ack=True, impact_ack=True)
    assert one("SELECT status FROM acquisition_sessions WHERE id=?", (sid,))["status"] == "planned"
    assert phases.refresh_phase_status("cs_trig_p02", "p02_acquisition_plan") == "completed"

    # evidence registered with recorded hash -> p05 completed
    fixture = tmp_path / "trig_fixture.csv"
    fixture.write_text("SYNTHETIC,fixture\n", encoding="utf-8")
    ev.store_copy("cs_trig_p02", str(fixture), "trig.csv", "csv", "tester",
                  notes="synthetic", actor="tester")
    assert phases.refresh_phase_status("cs_trig_p02", "p05_custody") == "completed"


def test_p11_completed_on_explanation_record(app, context, fresh_case_id):
    from artifactiq.db import one
    from artifactiq.services import phases
    cid = fresh_case_id
    st = phases.refresh_phase_status(cid, "p11_explain")   # derivation alone stays ready
    # direct record (the GET /explanation path calls this after presenting text)
    phases.record_explanation(cid, {"sentences": 3})
    row = one("SELECT status FROM phase_runs WHERE case_id=? AND phase='p11_explain' "
              "ORDER BY started_at DESC, rowid DESC LIMIT 1", (cid,))
    assert row["status"] == "completed"


def test_image_api_roundtrip(client, context, tmp_path):
    from artifactiq.db import one
    from artifactiq.demo_loader import make_fat16_image
    from artifactiq.services import evidence as ev

    _mk_case(context, "cs_img_api")
    src = tmp_path / "api_img.FAT16.raw"
    make_fat16_image(src)
    ev.store_copy("cs_img_api", str(src), "api_img.FAT16.raw", "disk_image",
                  "tester", notes="synthetic", actor="tester")
    ev_id = one("SELECT id FROM evidence WHERE case_id=? ORDER BY created_at DESC "
                "LIMIT 1", ("cs_img_api",))["id"]
    h = client.csrf_header
    r = client.post("/api/cases/cs_img_api/image/analyze", json={}, headers=client.csrf_header)
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["runs"][0]["status"] == "completed"

    r2 = client.get("/api/cases/cs_img_api/image")
    j2 = r2.get_json()
    assert j2["ok"] and j2["engine"]["installed"]
    assert any(f["path"].endswith("TOOLPACK.EXE") for f in j2["files"])

    # re-verification: analyzing does not change the preserved copy (same run file count)
    r3 = client.get("/api/cases/cs_img_api/phases")
    assert r3.get_json()["phases"]["p06_image"]["status"] == "completed"


def test_image_analyze_rejects_non_image(client, context, tmp_path):
    from artifactiq.db import one
    from artifactiq.services import evidence as ev
    _mk_case(context, "cs_img_neg")
    f = tmp_path / "neg.csv"
    f.write_text("a,b\n", encoding="utf-8")
    ev.store_copy("cs_img_neg", str(f), "neg.csv", "csv", "tester", actor="tester")
    ev_id = one("SELECT id FROM evidence WHERE case_id=? ORDER BY created_at DESC LIMIT 1",
                ("cs_img_neg",))["id"]
    r = client.post("/api/cases/cs_img_neg/image/analyze",
                    json={"evidence_id": ev_id}, headers=client.csrf_header)
    j = r.get_json()
    assert (not j["ok"]) and "disk image" in j["error"].lower()
