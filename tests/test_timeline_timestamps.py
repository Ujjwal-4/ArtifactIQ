"""Timeline timestamp honesty: warnings only for genuinely dropped timestamps.

A .reg text export contains no key timestamps; events derived from it are
displayed as "no timestamp in source" and must NOT demote p07 to
completed_with_warnings. Only a timestamp that existed in the source but was
dropped/misparse counts as a warning.
"""
from __future__ import annotations

from artifactiq.db import insert, one, execute
from artifactiq.services import phases
from artifactiq.util.ids import new_id, now_iso


def _case(context, cid):
    insert("cases", {"id": cid, "case_number": f"TEST-TL-{cid[-6:]}",
                     "title": "timeline ts test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})
    insert("evidence", {"id": f"ev_{cid[-4:]}", "case_id": cid, "original_name": "fixture.bin",
                        "stored_name": "rand", "data_path": "fixture", "size": 1,
                        "sha256": "0" * 64, "media_type": "csv",
                        "acquired_at": now_iso(), "investigator": "tester",
                        "created_at": now_iso()})
    return cid


def _ev(cid, *, ts_utc, ts_source):
    insert("events", {"id": new_id("n"), "case_id": cid, "evidence_id": f"ev_{cid[-4:]}",
                      "run_id": new_id("run"), "created_at": now_iso(),
                      "event_type": "generic_value", "category": "registry",
                      "ts_utc": ts_utc, "ts_original": None, "ts_precision": "unknown",
                      "ts_source": ts_source, "parser": "t", "parser_version": "v2",
                      "parse_status": "ok", "tags": "[]"})


def test_no_in_source_timestamps_do_not_warn(context):
    from artifactiq.services import phases
    cid = "cs_tl_nosrc"
    _case(context, cid)
    # one event with a real timestamp + registry events whose source never had one
    _ev(cid, ts_utc="2025-08-17T22:28:00.000Z", ts_source="evtx/body/TimeCreated")
    _ev(cid, ts_utc=None, ts_source="no_timestamp")
    _ev(cid, ts_utc=None, ts_source="no_timestamp")
    st = phases.refresh_phase_status(cid, "p07_timeline")
    assert st == "completed"
    # the non-source-missing bucket is zero
    n_warn = one("SELECT COUNT(*) AS n FROM events WHERE case_id=? AND ts_utc IS NULL "
                 "AND ts_source!='no_timestamp'", (cid,))["n"]
    assert n_warn == 0


def test_dropped_timestamps_still_warn(context):
    from artifactiq.services import phases
    cid = "cs_tl_warn"
    _case(context, cid)
    _ev(cid, ts_utc="2025-08-17T22:28:00.000Z", ts_source="evtx/body/TimeCreated")
    # timestamp expected but absent: a real timestamp problem
    _ev(cid, ts_utc=None, ts_source="evtx/body/TimeCreated")
    st = phases.refresh_phase_status(cid, "p07_timeline")
    assert st == "completed_with_warnings"


def test_all_missing_with_sources_never_fails(context):
    from artifactiq.services import phases
    cid = "cs_tl_nosrc_all"
    _case(context, cid)
    _ev(cid, ts_utc=None, ts_source="no_timestamp")
    _ev(cid, ts_utc=None, ts_source="no_timestamp")
    st = phases.refresh_phase_status(cid, "p07_timeline")
    # every event lacks ts BECAUSE the source has none — honest completed
    assert st == "completed"


def test_demo_case_p07_is_plain_completed(context):
    from artifactiq.demo_loader import build_demo_case
    from artifactiq.db import one
    cid = build_demo_case()
    st = phases.refresh_phase_status(cid, "p07_timeline")
    assert st == "completed"
    row = one("SELECT detail FROM phase_runs WHERE case_id=? AND phase='p07_timeline' "
              "ORDER BY started_at DESC, rowid DESC LIMIT 1", (cid,))
    assert "not_in_source" in row["detail"]
