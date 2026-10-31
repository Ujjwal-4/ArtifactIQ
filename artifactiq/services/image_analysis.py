"""Disk-image analysis service (Phase 6) â€” REAL parsing via pytsk3 (The Sleuth Kit).

Honesty contract:
- Phase 6 completes only when a registered disk image is actually opened and
  parsed by the engine. There is no synthetic completion and no simulation.
- The operation is READ-ONLY over the preserved evidence copy; the copy is
  SHA-256 hashed before and after the run and must not change.
- Engine limits (entry caps, truncation) and failures are surfaced in the run
  message, never silently dropped.
- No engine installed => phase stays `blocked` with a clear reason.
  E01/VHD containers depend on optional TSK libraries and are reported as
  failed with the engine's own error text when unsupported.
"""
from __future__ import annotations

import gc
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from ..db import query, one, insert, update, jdump, jload
from ..util.ids import new_id, now_iso
from ..util.audit import audit
from ..util import hashing

MAX_ENTRIES_PER_IMAGE = 25000   # hard cap per image; beyond is honestly truncated
MAX_ROWS = 20000                # max filesystem rows persisted per run
MAX_DEPTH = 14


def engine() -> dict:
    try:
        import pytsk3  # noqa: F401
        ver = str(getattr(pytsk3, "TSK_VERSION_STR", "") or "installed")
        return {"installed": True, "version": f"pytsk3 {ver}"}
    except Exception:
        return {"installed": False, "version": ""}


def _abs_path(ev_row: dict) -> Path:
    from .evidence import abs_path_of
    return Path(abs_path_of(ev_row["data_path"]))


def _iso(ts) -> str | None:
    if ts is None or ts < 0:
        return None
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")
    except (OverflowError, OSError, ValueError):
        return None


def _fs_type_name(pytsk3, fs) -> str:
    try:
        val = getattr(fs.info, "ftype", None)
        if val is None:
            val = getattr(fs, "ftype", None)
    except Exception:
        return "unknown"
    if val is None:
        return "unknown"
    known = {}
    for name in dir(pytsk3):
        if name.startswith("TSK_FS_TYPE_") and "DETECT" not in name and "ENUM" not in name:
            try:
                known.setdefault(int(getattr(pytsk3, name)), name.replace("TSK_FS_TYPE_", ""))
            except (TypeError, ValueError):
                pass
    return known.get(int(val), f"ftype_{int(val)}")


class _RowWriter:
    """Capped filesystem row recorder; counts everything, persists up to MAX_ROWS."""

    def __init__(self, case_id: str, ev_id: str, run_id: str):
        self.case_id, self.ev_id, self.run_id = case_id, ev_id, run_id
        self.rows = []
        self.count = 0

    def write(self, path, is_dir, deleted, size, cr, mt, at, ct, inum):
        self.count += 1
        if self.count > MAX_ROWS:
            return
        self.rows.append({
            "run_id": self.run_id, "case_id": self.case_id, "evidence_id": self.ev_id,
            "path": path, "is_dir": is_dir, "deleted": deleted, "size": size,
            "crtime": cr, "mtime": mt, "atime": at, "ctime": ct, "inum": inum,
        })

    def flush(self):
        for r in self.rows:
            insert("image_files", r)
        n = len(self.rows)
        self.rows = []
        return n


def _walk_fs(pytsk3, fs, writer: _RowWriter) -> dict:
    """Recursively walk one filesystem (read-only). Returns honest counters."""
    c = {"files": 0, "dirs": 0, "deleted": 0, "truncated": False}
    IS_DIR_TYPE = pytsk3.TSK_FS_META_TYPE_DIR
    ALLOC_META = getattr(pytsk3, "TSK_FS_META_FLAG_ALLOC", 0x2)
    UNALLOC_NAME = getattr(pytsk3, "TSK_FS_NAME_FLAG_UNALLOC", 0x2)
    IS_DIR_NAME = getattr(pytsk3, "TSK_FS_NAME_TYPE_DIR", 0x3)

    def norm(name):
        return name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)

    def visit(dirpath: str, depth: int):
        if c["truncated"]:
            return
        if depth > MAX_DEPTH:
            c["truncated"] = True
            return
        entries = fs.open_dir(dirpath)
        for entry in entries:
            ninfo = entry.info.name
            name = norm(ninfo.name)
            if name in (".", ".."):
                continue
            # TSK injects virtual pseudo-entries ($MBR, $FAT1, $OrphanFiles…)
            ntype = getattr(ninfo, "type", None)
            if ntype in (getattr(pytsk3, "TSK_FS_NAME_TYPE_VIRT", None),
                         getattr(pytsk3, "TSK_FS_NAME_TYPE_VIRT_DIR", None)):
                continue
            if name in ("$MBR", "$Boot", "$FAT1", "$FAT2", "$OrphanFiles",
                        "$CarveFiles", "$Metadata"):
                continue
            if writer.count >= MAX_ENTRIES_PER_IMAGE:
                c["truncated"] = True
                return
            meta = entry.info.meta
            mflags = getattr(meta, "flags", 0) if meta else 0
            is_dir = bool(meta and getattr(meta, "type", None) == IS_DIR_TYPE) or (
                meta is None and ntype == IS_DIR_NAME)
            deleted = bool(getattr(ninfo, "flags", 0) & UNALLOC_NAME) or (
                meta is not None and mflags and not (mflags & ALLOC_META))
            size = cr = mt = at = ct = inum = None
            if meta is not None:
                size = getattr(meta, "size", None)
                inum = str(getattr(meta, "inum", "") or "")
                cr = _iso(getattr(meta, "crtime", None))
                mt = _iso(getattr(meta, "mtime", None))
                at = _iso(getattr(meta, "atime", None))
                ct = _iso(getattr(meta, "ctime", None))
            full = (dirpath.rstrip("/") + "/" + name) if dirpath != "/" else ("/" + name)
            if is_dir:
                c["dirs"] += 1
            else:
                c["files"] += 1
            if deleted:
                c["deleted"] += 1
            writer.write(full, 1 if is_dir else 0, 1 if deleted else 0,
                         size, cr, mt, at, ct, inum)
            if is_dir:
                visit(full, depth + 1)

    visit("/", 0)
    return c


def _analyze_one(case_id: str, ev_row: dict, eng: dict) -> dict:
    import pytsk3

    run_id = new_id("imr")
    started = now_iso()
    t0 = time.time()
    parts: list = []
    counters = {"files": 0, "dirs": 0, "deleted": 0, "truncated": 0}
    problems: list = []
    fs_parsed = 0
    reason = ""

    # run row is persisted up-front (status "running") so image_files FK rows
    # have a parent; final values are written back after analysis
    insert("image_runs", {
        "id": run_id, "case_id": case_id, "evidence_id": ev_row["id"],
        "status": "running", "engine": eng["version"],
        "started_at": started, "finished_at": None,
        "partitions": jdump([]), "files": 0, "dirs": 0, "deleted": 0,
        "truncated": 0, "message": "",
    })

    src = _abs_path(ev_row)
    pre_sha = hashing.sha256_file(src)
    writer = _RowWriter(case_id, ev_row["id"], run_id)
    img = None
    vol = None
    fs = None
    try:
        img = pytsk3.Img_Info(str(src))
        block = 512
        vol = None
        try:
            vol = pytsk3.Volume_Info(img)
        except Exception as exc:
            reason = f"no readable partition table (treated as superfloppy): {exc}"[:180]

        targets: list = []
        if vol is not None:
            block = getattr(vol.info, "block_size", 512) or 512
            count = vol.get_part_count()
            for i in range(count):
                part = vol.get_part(i)
                unalloc = bool(getattr(part, "flags", 0)
                               & pytsk3.TSK_VS_PART_FLAG_UNALLOC)
                desc = str(getattr(part, "desc", "") or "")
                start = getattr(part, "start", 0)
                parts.append({
                    "addr": getattr(part, "addr", i), "desc": desc, "start": start,
                    "length_sectors": getattr(part, "len", 0),
                    "block_size": block, "unallocated": unalloc,
                })
                if unalloc:
                    parts[-1]["status"] = "skipped_unallocated"
                    continue
                targets.append((len(parts) - 1, offset := start * block))
        else:
            targets.append((0, 0))
            parts.append({"addr": 0, "desc": "unpartitioned (superfloppy)",
                          "start": 0, "length_sectors": None,
                          "block_size": block, "unallocated": False})

        for pidx, offset in targets:
            try:
                fs = pytsk3.FS_Info(img, offset=offset)
            except Exception as exc:
                parts[pidx].update({"status": "unsupported_filesystem",
                                    "error": str(exc)[:200]})
                problems.append(f"partition '{parts[pidx]['desc'] or pidx}': {exc}"[:180])
                continue
            ftype = _fs_type_name(pytsk3, fs)
            c = _walk_fs(pytsk3, fs, writer)
            fs_parsed += 1
            counters["files"] += c["files"]
            counters["dirs"] += c["dirs"]
            counters["deleted"] += c["deleted"]
            if c["truncated"]:
                counters["truncated"] += 1
            parts[pidx].update({
                "status": "parsed", "fs_type": ftype,
                "files": c["files"], "dirs": c["dirs"],
                "deleted": c["deleted"], "truncated": bool(c["truncated"]),
            })
        persisted = writer.flush()
    except Exception as exc:
        problems.append(f"{type(exc).__name__}: {exc}"[:280])
        persisted = writer.flush()
    finally:
        # Release the media path fully: pytsk3 keeps an OS file handle per
        # underlying TSK object chain, so img.close() alone does NOT unlock the
        # file on Windows — every FS_Info / Volume_Info reference must be
        # dropped and the libtsk bindings collected, or the preserved copy
        # stays locked ("file in use") until the whole process restarts,
        # which breaks retention-aware removal.
        fs = None
        vol = None
        if img is not None:
            try:
                img.close()
            except Exception:
                pass
            img = None
        gc.collect()

    post_sha = hashing.sha256_file(src)
    if pre_sha != post_sha:
        status = "failed"
        problems.append("SEALED EVIDENCE CHANGED during analysis - do not trust this run")
    elif counters["files"] + counters["dirs"] > 0 and not problems and not counters["truncated"]:
        status = "completed"
    elif counters["files"] + counters["dirs"] > 0:
        status = "completed_with_warnings"
    else:
        status = "failed"
        reason = reason or ("; ".join(problems)[-280:] if problems
                            else "no readable filesystem found")

    dur = round(time.time() - t0, 2)
    final = {
        "status": status, "started_at": started, "finished_at": now_iso(),
        "partitions": jdump(parts),
        "files": counters["files"], "dirs": counters["dirs"],
        "deleted": counters["deleted"], "truncated": counters["truncated"],
        "message": (f"engine={eng['version']} fs_parsed={fs_parsed} "
                    f"entries_seen={writer.count} rows_saved={persisted} "
                    f"duration_s={dur}"
                    + (f" | {'; '.join(problems)[-260:]}" if problems else "")
                    + (f" | {reason}" if reason and status == "failed" else ""))[:500],
    }
    update("image_runs", run_id, final)
    audit("image_analyzed", target=case_id,
          detail=f"evidence={ev_row['id']} status={status} files={counters['files']} "
                 f"dirs={counters['dirs']} deleted={counters['deleted']} "
                 f"rows_saved={persisted}", actor="system")
    d = {"id": run_id, "case_id": case_id, "evidence_id": ev_row["id"],
         "engine": eng["version"], **final}
    d["partitions"] = parts
    return d


def analyze(case_id: str, evidence_id: str | None = None) -> dict:
    """Run phase-6 analysis over one (or all) disk-image evidence items. Read-only."""
    eng = engine()
    if not eng["installed"]:
        raise ValueError(
            "Disk-image engine (pytsk3 / The Sleuth Kit) is not installed in this "
            "environment. Install it into the project venv with: "
            "pip install pytsk3 - the phase stays blocked until then.")

    if evidence_id:
        ev = one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
        if not ev or ev["case_id"] != case_id:
            raise ValueError("Evidence not found in this case.")
        if ev["media_type"] != "disk_image":
            raise ValueError(f"Evidence '{ev['original_name']}' is not a disk image.")
        targets = [dict(ev)]
    else:
        targets = [dict(r) for r in query(
            "SELECT * FROM evidence WHERE case_id=? AND media_type='disk_image' "
            "ORDER BY created_at", (case_id,))]
        if not targets:
            raise ValueError("No disk-image evidence is registered in this case.")

    runs = [_analyze_one(case_id, ev, eng) for ev in targets]
    return {"runs": runs, "engine": eng}


def _dehydrate(r) -> dict:
    d = dict(r)
    d["partitions"] = jload(d.get("partitions") or "[]")
    return d


def last_run(case_id: str) -> dict | None:
    r = one("SELECT * FROM image_runs WHERE case_id=? ORDER BY started_at DESC LIMIT 1",
            (case_id,))
    return _dehydrate(r) if r else None


def runs_for_case(case_id: str) -> list:
    return [_dehydrate(r) for r in query(
        "SELECT * FROM image_runs WHERE case_id=? ORDER BY started_at DESC LIMIT 25",
        (case_id,))]


def files_for_run(run_id: str, limit: int = 300) -> list:
    return [dict(r) for r in query(
        "SELECT * FROM image_files WHERE run_id=? ORDER BY id LIMIT ?", (run_id, limit))]


def disk_images(case_id: str) -> list:
    return [dict(r) for r in query(
        "SELECT * FROM evidence WHERE case_id=? AND media_type='disk_image' "
        "ORDER BY created_at", (case_id,))]

