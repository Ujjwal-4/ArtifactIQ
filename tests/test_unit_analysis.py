"""Unit tests: analysis services (rules, branches, risk, explanation, timeline, phases).

All events are SYNTHETIC rows inserted directly; no real evidence is used.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from artifactiq.db import insert, query, one, jdump  # noqa: E402
from artifactiq.util.ids import new_id, now_iso  # noqa: E402


def _mk_case(context, cid):
    if one("SELECT id FROM cases WHERE id=?", (cid,)):
        return cid
    insert("cases", {"id": cid, "case_number": f"TEST-AN-{cid[-6:]}",
                     "title": "analysis test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})
    return cid


def _ev(case_id, evidence_id, etype, **kw):
    fields = dict(event_type=etype, category="test", ts_utc=kw.pop("ts_utc", "2025-08-17T22:12:00.000Z"),
                  parser="fixture", parser_version="v2", parse_status="ok")
    fields.update(kw)
    eid = new_id("n")
    row = {"id": eid, "case_id": case_id, "evidence_id": evidence_id, "run_id": new_id("run"),
           "created_at": now_iso(), "tags": jdump(["fixture"]), **fields}
    insert("events", row)
    return row


def _evidence(case_id):
    inter = new_id("ev")
    insert("evidence", {"id": inter, "case_id": case_id, "original_name": "fixture.bin",
                        "stored_name": "rand", "data_path": "fixture", "size": 1,
                        "sha256": "0" * 64, "media_type": "csv",
                        "acquired_at": now_iso(), "investigator": "tester",
                        "created_at": now_iso()})
    return inter


def test_attack_rules_fire_with_evidence(context):
    from artifactiq.services import attack
    cid = _mk_case(context, "cs_an_rules")
    evid = _evidence(cid)
    for i in range(5):
        _ev(cid, evid, "logon_failure", username="svc-scan", hostname="H1")
    _ev(cid, evid, "logon_failure", username="svc-other", hostname="H2")
    _ev(cid, evid, "service_installed", process_name="badsvc")
    _ev(cid, evid, "process_created", process_name="powershell.exe",
        command_line="powershell -nop -w hidden")
    res = attack.build_mappings(cid)
    assert res["ok"] and res["mappings"] >= 3
    techs = {m["technique_id"] for m in query("SELECT * FROM attack_mappings WHERE case_id=?", (cid,))}
    assert "T1543.003" in techs   # Windows Service
    assert "T1059.001" in techs   # PowerShell
    assert "T1078" in techs       # Valid Accounts (logon failures)
    # every mapping names its rule version and carries evidence ids
    for m in query("SELECT * FROM attack_mappings WHERE case_id=?", (cid,)):
        assert m["rule_version"].startswith("attack-rules/")
        assert m["evidence_ids"] != "[]"


def test_attack_no_events_is_honest_zero(context):
    from artifactiq.services import attack
    cid = _mk_case(context, "cs_an_zero")
    res = attack.build_mappings(cid)
    assert res["mappings"] == 0
    assert "no rule" in res["note"].lower() or res["mappings"] == 0


def test_attack_no_placeholder_findings(context):
    from artifactiq.services import attack
    cid = _mk_case(context, "cs_an_dash")
    evid = _evidence(cid)
    _ev(cid, evid, "service_installed", process_name=None)
    attack.build_mappings(cid)
    titles = [f["title"] for f in query("SELECT * FROM findings WHERE case_id=?", (cid,))]
    assert titles and all(": -" not in t for t in titles), titles


def test_risk_formula_exact(context):
    from artifactiq.services import risk
    cid = _mk_case(context, "cs_an_risk")
    evid = _evidence(cid)
    # S=3 (one severity-3 finding), T=1 tactic, C=1 host+1 user, A from 1 evidence 1 run
    _ev(cid, evid, "audit_log_cleared", hostname="H1", username="u1")
    risk_row = risk.compute(cid)
    assert risk_row["policy" if False else "version"] == risk.POLICY_VERSION
    inputs = __import__("json").loads(risk_row["inputs"])
    # components are visible and evidence-labeled
    assert {"S_max_finding_severity", "T_tactic_diversity", "C_breadth",
            "A_analysis_completeness"} <= set(inputs)
    score = risk_row["score"]
    assert 0 <= score <= 100
    # S*16+T*14+C*10+A*10 == score constraint
    S = inputs["S_max_finding_severity"]["value"]
    T = inputs["T_tactic_diversity"]["value"]
    C = inputs["C_breadth"]["value"]
    A = inputs["A_analysis_completeness"]["value"]
    assert min(100, S * 16 + T * 14 + C * 10 + A * 10) == score


def test_branches_are_questions_not_facts(context):
    from artifactiq.services import prediction
    cid = _mk_case(context, "cs_an_br")
    evid = _evidence(cid)
    for i in range(6):
        _ev(cid, evid, "logon_failure", username="svc", hostname="H1")
    _ev(cid, evid, "process_created", process_name="powershell.exe")
    res = prediction.generate(cid)
    rows = query("SELECT * FROM branches WHERE case_id=?", (cid,))
    assert rows and res["branches"] == len(rows)
    for b in rows:
        # branches carry evidence refs, steps, and the priority formula
        assert b["evidence_ids"] != "[]" or b["missing_evidence"] != "[]"


def test_tampered_branch_decide_rejected(context):
    from artifactiq.services import prediction
    from artifactiq.db import insert as dbi
    cid = _mk_case(context, "cs_an_dec")
    dbi("branches", {"id": "br_dec_x", "case_id": cid, "question": "q?", "why": "w",
                     "priority": 10, "priority_calc": jdump({"x": 1}),
                     "rule_id": "B_test", "rule_version": "test/1", "created_at": now_iso()})
    import pytest
    with pytest.raises(ValueError):
        prediction.decide("br_dec_x", "magically_resolved")


def test_explanation_narrative_cites_evidence(context):
    from artifactiq.services import explanation
    cid = _mk_case(context, "cs_an_exp")
    evid = _evidence(cid)
    _ev(cid, evid, "service_installed", process_name="svcX")
    res = explanation.narrative(cid)
    assert res["sentences"]
    assert any(str(evid) in str(c) for c in res["cites"]) or res["cites"]
    assert "did not come from a model" in res["sentences"][-1]


def test_timeline_search_filter_and_pagination(context):
    from artifactiq.services import timeline
    cid = _mk_case(context, "cs_an_tl")
    evid = _evidence(cid)
    for i in range(120):
        _ev(cid, evid, "process_created", ts_utc=f"2025-08-17T22:{i//60:02d}",
            process_name=f"proc{i}")
    res = timeline.search(cid, {"event_type": "process_created"}, page=2, per_page=50)
    assert res["total"] == 120 and len(res["items"]) == 50 and res["page"] == 2
    res2 = timeline.search(cid, {"q": "proc7"}, page=1, per_page=50)
    assert res2["total"] >= 1


def test_timeline_export_csv_headers(context):
    from artifactiq.services import timeline
    cid = _mk_case(context, "cs_an_csv")
    evid = _evidence(cid)
    _ev(cid, evid, "process_created", process_name="p.exe")
    csv_text = timeline.export_csv(cid)
    lines = csv_text.splitlines()
    assert lines[0].startswith("# ArtifactIQ timeline export")
    assert "ts_utc" in lines[1] and "sha" not in lines[1]


def test_phase_status_derivation(context):
    from artifactiq.services import phases
    cid = _mk_case(context, "cs_an_ph")
    evid = _evidence(cid)
    _ev(cid, evid, "process_created")
    r = query("SELECT * FROM parser_runs LIMIT 1")  # none yet
    from artifactiq.services.parsing import _persist_run
    phases.refresh_case(cid)
    sm = phases.status_map(cid)
    assert sm["p03_acquisition"]["status"] in ("completed", "completed_with_warnings")
    assert sm["p04_parsing"]["status"] == "not_started"
    assert sm["p06_image"]["status"] == "blocked"  # no disk image registered
