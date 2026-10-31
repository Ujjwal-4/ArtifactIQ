"""Hash-chained, append-only chain-of-custody ledger.

Each record binds: seq, case, evidence, actor, action, reason, timestamp to the
previous record's hash. Any insert reordering/loss/tampering breaks the chain
and is detected by verify_custody_chain().

Honesty note: hash chaining protects against *undetected modification of the
database table* by this application's own components. It does not make the
local database immutable; an attacker with DB write access can recompute the
chain. Export/anchor checkpoints are the mitigation (see export_checkpoint).
"""
from __future__ import annotations

from ..db import insert, query, one, jdump
from ..util.hashing import sha256_text
from ..util.ids import now_iso, new_id

VERSION = "custody-v2/1.0"


def _record_hash(seq: int, evidence_id: str, case_id: str, actor: str, action: str,
                 reason: str, ts: str, prev_hash: str) -> str:
    material = "\x1f".join(
        [str(seq), case_id, evidence_id or "-", actor, action, reason, ts, prev_hash, VERSION]
    )
    return sha256_text(material)


def append(event_action: str, case_id: str, evidence_id: str | None, actor: str = "user",
           reason: str = "") -> dict:
    ts = now_iso()
    last = one(
        "SELECT * FROM custody_records ORDER BY seq DESC LIMIT 1"
    )
    seq = (last["seq"] if last else 0) + 1
    prev_hash = last["record_hash"] if last else "GENESIS"
    record_hash = _record_hash(seq, evidence_id or "", case_id, actor, event_action, reason, ts, prev_hash)
    insert(
        "custody_records",
        {
            "case_id": case_id,
            "evidence_id": evidence_id,
            "actor": actor if actor else "user",
            "action": event_action,
            "reason": reason,
            "ts": ts,
            "prev_hash": prev_hash,
            "record_hash": record_hash,
        },
    )
    return {"seq": seq, "record_hash": record_hash, "prev_hash": prev_hash, "ts": ts}


def verify(case_id: str | None = None, evidence_id: str | None = None) -> dict:
    """Recompute the chain and report the first inconsistency, if any.

    The ledger is one global, append-only chain: a record's prev_hash is the
    record_hash of the immediately preceding seq, whatever case it belongs to.
    Case/evidence-scoped verification therefore still validates every record
    against its full global predecessor — a tamper in any earlier record also
    invalidates the later chain, which is exactly the guarantee we want.
    """
    all_rows = query("SELECT * FROM custody_records ORDER BY seq")
    if case_id:
        rows = [r for r in all_rows if r["case_id"] == case_id]
    elif evidence_id:
        rows = [r for r in all_rows if r["evidence_id"] == evidence_id]
    else:
        rows = all_rows

    by_seq = {r["seq"]: r for r in all_rows}
    ok, issue = True, ""
    checked = 0
    for r in rows:
        if r["seq"] == 1:
            expected_prev = "GENESIS"
        elif (r["seq"] - 1) not in by_seq:
            ok, issue = False, f"Sequence gap at seq {r['seq']}: predecessor seq {r['seq'] - 1} missing."
            break
        else:
            expected_prev = by_seq[r["seq"] - 1]["record_hash"]
        if r["prev_hash"] != expected_prev:
            ok, issue = False, f"Broken link at seq {r['seq']}: prev_hash does not match the predecessor."
            break
        recomputed = _record_hash(
            r["seq"], r["evidence_id"] or "", r["case_id"], r["actor"], r["action"],
            r["reason"], r["ts"], r["prev_hash"],
        )
        if recomputed != r["record_hash"]:
            ok, issue = False, f"Record hash mismatch at seq {r['seq']} (record tampering detected)."
            break
        checked += 1
    return {
        "ok": ok,
        "issue": issue,
        "records_checked": checked,
        "records_total": len(rows),
        "head_hash": rows[-1]["record_hash"] if (ok and rows) else "",
        "algorithm": VERSION,
    }


def for_evidence(evidence_id: str) -> list:
    return query("SELECT * FROM custody_records WHERE evidence_id=? ORDER BY seq", (evidence_id,))


def for_case(case_id: str, limit: int = 500) -> list:
    return query(
        "SELECT * FROM custody_records WHERE case_id=? ORDER BY seq DESC LIMIT ?", (case_id, limit)
    )
