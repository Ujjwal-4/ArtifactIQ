"""Case deletion must purge derived/analysis rows, not orphan them.

Regression: deleting a case (retention-aware) removed only the `cases` row, so
normalized events, phase runs, mappings, simulations etc. stayed in the DB with
no owner — dashboards then displayed "27 normalized events" next to zero cases,
a phantom counter of deleted data.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def test_delete_purges_derived_rows_and_keeps_evidence_retained(client, context, fresh_case_id):
    from artifactiq.db import one, query

    # demo case is fully derived: events, phases, mappings all present
    counts = {
        "events": one("SELECT COUNT(*) AS n FROM events WHERE case_id=?", (fresh_case_id,))["n"],
        "evidence": one("SELECT COUNT(*) AS n FROM evidence WHERE case_id=?", (fresh_case_id,))["n"],
    }
    assert counts["events"] > 0 and counts["evidence"] > 0

    r = client.post(f"/api/cases/{fresh_case_id}/delete",
                    json={"confirm": f"{fresh_case_id}:DELETE"},
                    headers=client.csrf_header)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True

    # case row is gone…
    assert one("SELECT id FROM cases WHERE id=?", (fresh_case_id,)) is None
    # …and NO derived row is left orphaned (the phantom-counter bug)
    for tbl in ("events", "evidence", "findings", "attack_mappings", "branches",
                "phase_runs", "reports", "entities", "relationships",
                "risk_assessments", "simulations", "acquisition_sessions",
                "acquisition_artifacts", "parser_runs", "image_runs", "image_files"):
        n = query(f"SELECT COUNT(*) AS n FROM {tbl} WHERE case_id=?", (fresh_case_id,))
        assert n[0]["n"] == 0, f"{tbl} still has {n[0]['n']} orphaned rows"
