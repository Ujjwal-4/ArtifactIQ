"""Evidence registration, storage, verification, manifest, and retention.

Layout under the data dir:
  evidence/store/<2-char prefix>/<random stored name>   preserved copies
  evidence/trash/                                        retention copies after removal
Parse output, reports and exports are kept well away from this tree.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from ..db import insert, update, one, query
from ..util import hashing
from ..util.ids import new_id, now_iso, display_size
from ..util.pathsafety import safe_original_name, storage_name, resolve_within
from ..util.audit import audit
from . import custody

from ..config import data_dir


def store_root() -> Path:
    return Path(data_dir()) / "evidence" / "store"


def trash_root() -> Path:
    return Path(data_dir()) / "evidence" / "trash"


MEDIA_BY_EXT = {
    ".evtx": "evtx", ".evt": "evtx",
    ".sqlite": "browser_sqlite", ".sqlite3": "browser_sqlite",
    ".db": "generic_sqlite", ".historysqlite": "browser_sqlite",
    ".reg": "registry_export", ".hiv": "registry_hive", ".LOG1": "registry_hive",
    ".csv": "csv", ".json": "json", ".jsonl": "json", ".txt": "text",
    ".pcap": "pcap", ".pcapng": "pcap",
    ".raw": "disk_image", ".dd": "disk_image", ".img": "disk_image",
    ".e01": "disk_image", ".vhd": "disk_image", ".vhdx": "disk_image", ".001": "disk_image",
    ".dmp": "memory_image", ".mem": "memory_image",
}
USB_LOG_NAMES = {"setupapi.dev.log", "setupapi.dev.log.txt", "setupapi.dev.log.csv"}


def sniff_media_type(original_name: str, declared: str | None) -> str | None:
    name_l = (original_name or "").lower()
    if name_l in USB_LOG_NAMES:
        return "usb_history"
    if "history" in name_l and name_l.endswith((".sqlite", ".sqlite3", ".db")):
        return "browser_sqlite"
    p = Path(name_l)
    ext = p.suffix
    if ext.upper() in (".LOG1", ".LOG2"):
        return "registry_hive"
    return MEDIA_BY_EXT.get(ext.lower()) or (declared or None)


def store_copy(case_id: str, source_path: str | Path, original_name: str,
               declared_type: str | None, investigator: str, source_desc: str = "",
               notes: str = "", acquisition_method: str = "offline_upload",
               source_hash: str | None = None, actor: str = "user") -> dict:
    """Preserve a bit-for-bit copy of an existing file as case evidence."""
    src = Path(source_path)
    if not src.is_file():
        raise ValueError("Source file does not exist locally.")

    fp = hashing.quick_fingerprint(src)
    dup = one(
        "SELECT id, original_name FROM evidence WHERE case_id=? AND size=? LIMIT 1",
        (case_id, fp["size"]),
    )
    if dup and one(
        "SELECT id FROM evidence WHERE case_id=? AND size=? AND sha256=?",
        (case_id, fp["size"], _full_sha(src)),
    ):
        raise ValueError(
            f"An identical file is already registered in this case ({dup['original_name']})."
        )

    display = safe_original_name(original_name)
    mt = sniff_media_type(display, declared_type)
    stored = storage_name(Path(display).suffix or "")
    rel = f"{(case_id[:2].lower() or 'aa')}/{stored}"
    dest = store_root() / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(dest))
    sha = hashing.sha256_file(dest)
    size = os.path.getsize(dest)

    eid = new_id("ev")
    verify_status = "recorded"
    if source_hash:
        sh = (source_hash or "").strip().lower().replace(" ", "")
        if sh and (sha.startswith(sh) or sh.startswith(sha[: len(sh)])):
            verify_status = "verified"
        else:
            verify_status = "mismatch"

    row = {
        "id": eid, "case_id": case_id, "original_name": display, "stored_name": stored,
        "data_path": f"evidence/store/{rel}", "size": size, "sha256": sha,
        "source_hash": source_hash or None, "media_type": mt or "unknown",
        "acquisition_method": acquisition_method, "source_desc": source_desc,
        "acquired_at": now_iso(), "investigator": investigator,
        "notes": notes, "verify_status": verify_status,
        "verified_at": now_iso() if source_hash else None,
        "verified_hash": sha if verify_status == "verified" else None,
        "created_at": now_iso(),
    }
    insert("evidence", row)

    hs = f"{display}' ({display_size(size)}, sha256={sha[:16]}"
    custody.append("evidence_registered", case_id, eid, actor=actor,
                   reason=f"Registered '{hs}…, method={acquisition_method}).")
    if verify_status == "verified":
        custody.append("hash_crosscheck", case_id, eid, actor="system",
                       reason="Preserved-copy SHA-256 matches the source hash recorded at acquisition or provided by the operator.")
    elif verify_status == "mismatch":
        custody.append("hash_mismatch", case_id, eid, actor="system",
                       reason="WARNING: preserved copy does NOT match the source hash recorded at acquisition. Investigate before analysis.")
    audit("evidence_registered", target=eid, detail=f"{display} -> {sha[:24]}")
    return row


def _full_sha(src: Path) -> str:
    return hashing.sha256_file(src)


def get_evidence(evidence_id: str):
    return one("SELECT * FROM evidence WHERE id=?", (evidence_id,))


def case_evidence(case_id: str):
    return query("SELECT * FROM evidence WHERE case_id=? ORDER BY created_at DESC", (case_id,))


def abs_path_of(data_path: str) -> Path:
    rel = replace_store_prefix(data_path)
    return resolve_within(store_root(), rel)


def replace_store_prefix(data_path: str) -> str:
    marker = "evidence/store/"
    if marker in data_path:
        return data_path.split(marker, 1)[1]
    return data_path


def verify_evidence(evidence_id: str, actor: str = "user") -> dict:
    ev = get_evidence(evidence_id)
    if not ev:
        raise ValueError("Evidence id not found.")
    try:
        p = abs_path_of(ev["data_path"])
    except ValueError as exc:
        update("evidence", evidence_id, {"verify_status": "error", "verified_at": now_iso()})
        custody.append("hash_verify_failed", ev["case_id"], evidence_id, actor="system",
                       reason=f"Storage path resolve failed: {exc}")
        return {"ok": False, "status": "error", "detail": str(exc)}
    if not p.is_file():
        update("evidence", evidence_id, {"verify_status": "error", "verified_at": now_iso()})
        custody.append("hash_verify_failed", ev["case_id"], evidence_id, actor="system",
                       reason="Preserved copy missing at its recorded path.")
        return {"ok": False, "status": "error", "detail": "Preserved copy is missing from the evidence store."}
    current = hashing.sha256_file(p)
    expected = ev["sha256"]
    if current == expected:
        status, action, reason, ok = "verified", "hash_verified", f"SHA-256 recomputed equals {current[:16]}…", True
    else:
        status = "mismatch"
        action = "hash_mismatch"
        reason = (f"WARNING recomputed sha256 {current[:16]}… differs from recorded {expected[:16]}… "
                  "File may have changed after registration. Do not treat parse output as trustworthy until reviewed.")
        ok = False
    update("evidence", evidence_id,
           {"verify_status": status, "verified_at": now_iso(), "verified_hash": current})
    custody.append(action, ev["case_id"], evidence_id, actor=actor, reason=reason)
    # "result" mirrors "status" so API consumers can switch on either.
    return {"ok": ok, "result": status, "status": status,
            "recorded": expected, "computed": current}


def manifest(case_id: str, tool_version: str) -> dict:
    fields = ["id", "original_name", "stored_name", "size", "sha256", "source_hash",
              "media_type", "acquisition_method", "acquired_at", "investigator",
              "verify_status", "notes"]
    items = [{k: (r[k] if r[k] is not None else "") for k in fields} for r in case_evidence(case_id)]
    return {
        "generated_at": now_iso(),
        "tool": f"ArtifactIQ {tool_version}",
        "hash_algorithm": "SHA-256 (over the preserved copy; does not prove the original source was unmodified)",
        "evidence_count": len(items),
        "evidence": items,
    }


def preview(evidence_id: str) -> dict:
    """Read-only inspection of the preserved copy.

    Shows *what is inside* an attached file without requiring it to be parsed:
    a decoded snippet for declared-text formats, table names for SQLite
    databases, a hexdump for binaries. The evidence copy is opened for
    reading only — nothing is modified, and the recomputed SHA-256 is compared
    with the recorded one when the file is small enough for that to be cheap.
    """
    ev = get_evidence(evidence_id)
    if not ev:
        raise ValueError("Evidence id not found.")
    try:
        p = abs_path_of(ev["data_path"])
    except ValueError as exc:
        raise ValueError(f"Controlled path resolution failed: {exc}")

    mt = (ev["media_type"] or "unknown").lower()
    size = int(ev["size"] or 0)
    out = {
        "evidence_id": evidence_id,
        "original_name": ev["original_name"],
        "media_type": mt,
        "size": size,
        "sha256_recorded": ev["sha256"],
        "read_only": True,
        "kind": "unavailable",
        "snippet": "",
        "truncated": False,
        "note": "",
        "hash_check": None,
        "extracted": _extracted_summary(evidence_id),
    }
    if not p.is_file():
        out["note"] = "Preserved copy is missing from the evidence store (retention or corruption)."
        return out

    # SHA-256 cross-check only for demo-scale files; recomputing a multi-GB
    # image just for a preview would be wasteful, so that is disclosed instead.
    if size <= 64 * 1024 * 1024:
        computed = hashing.sha256_file(p)
        out["hash_check"] = {
            "computed": computed,
            "match": computed == ev["sha256"],
            "status": "verified" if computed == ev["sha256"] else "mismatch",
        }
    else:
        out["hash_check"] = {"computed": None, "match": None,
                             "status": "skipped (file larger than 64 MB)"}

    with p.open("rb") as fh:
        head = fh.read(_SNIPPET_BYTES)
    out["truncated"] = size > len(head)

    texty = mt in _TEXTY and b"\x00" not in head
    if texty:
        out["kind"] = "text"
        try:
            if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
                out["snippet"] = head.decode("utf-16", errors="replace")
                out["note"] = "UTF-16 text export (regedit-style BOM detected)."
            elif head.startswith(b"\xef\xbb\xbf"):
                out["snippet"] = head.decode("utf-8-sig", errors="replace")
            else:
                out["snippet"] = head.decode("utf-8", errors="replace")
        except (UnicodeDecodeError, LookupError):
            out["snippet"] = head.decode("latin-1", errors="replace")
        out["note"] = (out["note"] or "").strip() or _note_for(mt)
    elif mt in ("browser_sqlite", "generic_sqlite"):
        out["kind"] = "sqlite"
        out["snippet"] = _sqlite_tables(p)
        out["note"] = ("Opened read-only (immutable mode): table names and row "
                       "counts from the preserved copy. Parsing extracts the "
                       "records themselves.")
    else:
        out["kind"] = "binary"
        out["snippet"] = _hexdump(head[:_HEX_BYTES])
        out["note"] = ("Binary artifact — show its meaning after parsing "
                       "(disk image, event log, memory dump, …).")
    return out


_TEXTY = {"text", "json", "csv", "usb_history", "registry_export"}
_SNIPPET_BYTES = 4096
_HEX_BYTES = 512


def _note_for(mt: str) -> str:
    return {
        "registry_export": "Text .reg export: key paths and values are visible; "
                           "this format carries no key timestamps.",
        "usb_history": "Setupapi.dev.log text: device install lines are visible.",
        "json": "Structured JSON: shown verbatim.",
        "csv": "CSV rows: shown verbatim.",
        "text": "Log/text file: shown verbatim.",
    }.get(mt, "First bytes of the preserved copy.")


def _hexdump(b: bytes) -> str:
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        printable = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{i:08x}  {hexs:<48}  |{printable}|")
    return "\n".join(lines)


def _sqlite_tables(p: Path) -> str:
    import sqlite3
    import urllib.parse

    uri = "file:" + urllib.parse.quote(p.as_posix()) + "?immutable=1"
    try:
        cn = sqlite3.connect(uri, uri=True)
        try:
            rows = cn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 50").fetchall()
            lines = []
            for (name,) in rows:
                try:
                    n = cn.execute(f'SELECT COUNT(*) AS n FROM "{name}"').fetchone()[0]
                except sqlite3.Error as e2:
                    lines.append(f"  {name}  (unreadable: {e2})")
                else:
                    lines.append(f"  {name}  ({n} rows)")
            return "\n".join(lines) or "  (no user tables found)"
        finally:
            cn.close()
    except sqlite3.Error as e:
        return f"  (read-only inspection failed: {e})"


def _extracted_summary(evidence_id: str) -> dict:
    try:
        rows = query(
            "SELECT event_type, COUNT(*) AS n FROM events WHERE evidence_id=? "
            "GROUP BY event_type ORDER BY n DESC LIMIT 12", (evidence_id,))
        total = one("SELECT COUNT(*) AS n FROM events WHERE evidence_id=?",
                    (evidence_id,))["n"]
        return {"total_events": total,
                "by_event_type": [{"event_type": r["event_type"], "n": r["n"]}
                                  for r in rows]}
    except Exception:
        return {"total_events": 0, "by_event_type": []}


def remove_with_retention(evidence_id: str, actor: str) -> dict:
    """Soft-delete: the artifact copy is moved to the trash folder; ledger notes it.

    Original sources on disk are never touched; custody records are retained.
    """
    ev = get_evidence(evidence_id)
    if not ev:
        raise ValueError("Evidence id not found.")
    try:
        p = abs_path_of(ev["data_path"])
    except ValueError as exc:
        raise ValueError(f"Controlled path resolution failed: {exc}")
    trash_dir = trash_root()
    trash_dir.mkdir(parents=True, exist_ok=True)
    if p.is_file():
        target = trash_dir / f"{evidence_id}_{ev['stored_name']}"
        shutil.move(str(p), str(target))
        note = f"Preserved copy moved to trash retention as {target.name}. Remove manually after the retention period."
    else:
        note = "Preserved copy was already missing from the store."
    # The evidence row stays with retention info so investigators can see what
    # was removed and why parser runs may be incomplete for it.
    update("evidence", evidence_id, {
        "verify_status": "retained",
        "notes": ((ev["notes"] or "") + (" | REMOVED: " + note))[:1900],
    })
    custody.append("evidence_removed", ev["case_id"], None, actor=actor,
                   reason=f"{ev['original_name']} ({evidence_id}); {note} Source artifacts outside this application were not modified.")
    audit("evidence_removed", target=evidence_id, detail=note)
    return {"removed": True, "note": note}
