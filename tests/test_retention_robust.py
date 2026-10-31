"""Retention-aware removal must not crash when Windows holds the file open.

OneDrive sync or antivirus scans briefly lock freshly written artifact copies;
the removal retries, then falls back to copy-into-trash with an honest note.
Nothing may 500 because of a transient lock.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


def _attach(context, tmp_path, cid, ev_id, content=b"docx-bytes"):
    """Create a case + one attached artifact with a real stored copy."""
    from artifactiq.db import insert
    from artifactiq.util.ids import now_iso
    from artifactiq.services import evidence as ev

    insert("cases", {"id": cid, "case_number": f"TEST-RM-{cid[-6:]}",
                     "title": "retention test", "investigator": "tester",
                     "mode": "full", "status": "active",
                     "created_at": now_iso(), "updated_at": now_iso()})
    src = tmp_path / f"{ev_id}.reg"
    src.write_bytes(content)
    res = ev.store_copy(cid, str(src), "usb.reg", "registry_export", "tester",
                        source_desc="test staging", notes="synthetic", actor="tester")
    # store_copy returns the evidence id (str) or a dict depending on version;
    # normalize: none of these tests rely on the exact shape.
    if isinstance(res, dict):
        return res.get("evidence_id") or res.get("id") or res
    return res


def test_retry_clears_transient_lock(context, tmp_path, monkeypatch):
    from artifactiq.services import evidence as ev

    evid = _attach(context, tmp_path, "cs_rm_retry", "ev_rm_retry")
    p = ev.abs_path_of(ev.get_evidence(evid)["data_path"])
    assert p.is_file()

    real_move = shutil.move
    calls = {"n": 0}

    def flaky_move(src, dst):
        calls["n"] += 1
        if calls["n"] <= 2:  # two failed attempts, third succeeds
            raise PermissionError("file in use")
        return real_move(src, dst)

    monkeypatch.setattr(shutil, "move", flaky_move)
    res = ev.remove_with_retention(evid, actor="tester")
    assert res["removed"] is True
    assert calls["n"] == 3  # retried instead of crashing


def test_perma_locked_copy_falls_back_with_honest_note(context, tmp_path, monkeypatch):
    from artifactiq.services import evidence as ev

    evid = _attach(context, tmp_path, "cs_rm_lock", "ev_rm_lock")
    p = ev.abs_path_of(ev.get_evidence(evid)["data_path"])
    assert p.is_file()

    def blocked_move(src, dst):
        raise PermissionError("locked by sync engine")

    def blocked_unlink(self, *a, **k):
        raise PermissionError("still held open")

    monkeypatch.setattr(shutil, "move", blocked_move)
    monkeypatch.setattr(Path, "unlink", blocked_unlink)
    res = ev.remove_with_retention(evid, actor="tester")
    # copy fallback succeeded; note is honest about the retained store file
    assert res["note"].startswith("Preserved copy copied to trash retention")
    trash_copy = ev.trash_root() / f"{evid}_{Path(ev.get_evidence(evid)['data_path']).name}"
    assert trash_copy.is_file()           # trash has the full copy
    assert p.is_file()                    # the locked store file remains (honest + disclosed)

    row = ev.get_evidence(evid)
    assert "REMOVED:" in (row["notes"] or "")
