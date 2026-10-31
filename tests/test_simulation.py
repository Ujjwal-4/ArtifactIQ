"""Behavioral scenario simulator: honesty + determinism + API contract.

Covers:
- generation only runs from real normalized events (honest empty state);
- node statuses are exactly 'observed' or 'predicted', and observed nodes
  always cite event/evidence ids from this case;
- same case + same ruleset => same simulation (deterministic chain/priority);
- regeneration replaces, never duplicates;
- API roundtrip (generate + view) works with CSRF;
- scenario with no triggers returns zero scenarios honestly.
"""
from __future__ import annotations

import pytest


def test_generate_honest_empty(client, context):
    from artifactiq.db import execute

    execute("INSERT INTO cases (id, case_number, title, investigator, mode, status,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, 'full', 'active', ?, ?)",
            ("cs_sim_empty", "TEST-SIM-EMPTY-1", "no events case", "tester", "2026-01-01", "2026-01-01"))
    r = client.post("/api/cases/cs_sim_empty/simulation/generate", json={}, headers=client.csrf_header)
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["scenarios"] == 0


def test_chain_statuses_and_citations(app, context, fresh_case_id):
    from artifactiq.db import query
    from artifactiq.services import simulation as sim

    cid = fresh_case_id
    res = sim.generate(cid)
    assert res["ok"] and res["scenarios"] >= 1
    rows = query("SELECT * FROM simulations WHERE case_id=? ORDER BY priority DESC", (cid,))
    assert rows
    valid_techs = {n["technique"]["technique_id"] for r in rows
                   for n in sim.jload(r["nodes"])}
    for r in rows:
        nodes = sim.jload(r["nodes"])
        assert [n["idx"] for n in nodes] == list(range(1, len(nodes) + 1))
        for n in nodes:
            assert n["status"] in ("observed", "predicted")
            # 'observed' must cite real ids; 'predicted' must NOT cite events
            if n["status"] == "observed":
                assert n["event_ids"] and n["evidence_ids"], \
                    f"observed node without citation: {n['title']}"
            else:
                assert not n["event_ids"]
            assert n["prevention"], "every node carries prevention guidance"
            assert n["expected_artifacts"]
    assert valid_techs and all(t.startswith("T") or t == "-" for t in valid_techs)


def test_determinism_and_regenerate_replaces(app, context, fresh_case_id):
    from artifactiq.db import query
    from artifactiq.services import simulation as sim

    cid = fresh_case_id
    first = sim.generate(cid)
    rows1 = query("SELECT * FROM simulations WHERE case_id=?", (cid,))
    stat1 = [(r["scenario_id"], r["priority"], r["observed_count"], sim.jload(r["nodes"])) for r in rows1]

    # re-run: stateless ruleset => same content
    sim.generate(cid)
    rows2 = query("SELECT * FROM simulations WHERE case_id=?", (cid,))
    stat2 = [(r["scenario_id"], r["priority"], r["observed_count"], sim.jload(r["nodes"])) for r in rows2]
    assert first["scenarios"] == len(rows1) == len(rows2)
    assert stat1 == stat2


def test_priority_formula_visible(app, context, fresh_case_id):
    from artifactiq.db import one
    from artifactiq.services import simulation as sim

    cid = fresh_case_id
    sim.generate(cid)
    row = one("SELECT * FROM simulations WHERE case_id=? ORDER BY priority DESC LIMIT 1", (cid,))
    calc = sim.jload(row["priority_calc"])
    expected = min(95, row["severity_base"] * 20 + 6 * row["observed_count"])
    assert calc["priority"] == row["priority"] == expected
    assert "not a probability" in calc["note"]


def test_simulation_api_roundtrip(client, context, fresh_case_id):
    cid = fresh_case_id
    r = client.post(f"/api/cases/{cid}/simulation/generate", json={}, headers=client.csrf_header)
    assert r.status_code == 200
    j = r.get_json()
    assert j["ok"] and j["scenarios"] >= 1 and j["version"].startswith("sim-rules/")
    r2 = client.get(f"/api/cases/{cid}/simulation")
    j2 = r2.get_json()
    assert j2["ok"] and len(j2["scenarios"]) == j["scenarios"]
    s = j2["scenarios"][0]
    for key in ("nodes", "trigger_summary", "priority_calc", "observed_count", "depth"):
        assert key in s
    assert any(n["status"] == "observed" for n in s["nodes"])
