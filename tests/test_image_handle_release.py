"""Phase 6 must release its pytsk3 media handle after analysis.

Regression: Img_Info kept the OS-level file open, so on Windows the preserved
copy of the disk image stayed locked ("file in use") until the server process
restarted — breaking retention-aware removal of the case with a 500.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def _image_evidence_row(context, case_id):
    from artifactiq.db import query

    rows = query("SELECT id FROM evidence WHERE case_id=? AND media_type=?",
                 (case_id, "disk_image"))
    assert rows, "demo case should contain one disk image evidence row"
    return rows[0]["id"]


def test_image_analysis_releases_handle_so_removal_succeeds(app, fresh_case_id):
    with app.app_context():
        from artifactiq.services import image_analysis as img
        from artifactiq.services import evidence as ev

        ev_id = _image_evidence_row(app, fresh_case_id)
        res = img.analyze(fresh_case_id, ev_id)
        assert res["runs"] and res["runs"][0]["status"] in (
            "completed", "completed_with_warnings", "failed")

        # the whole point: removal must work immediately — no leaked handle
        out = ev.remove_with_retention(ev_id, actor="tester")
        assert out["removed"] is True
        assert out["note"].startswith("Preserved copy moved to trash retention")
