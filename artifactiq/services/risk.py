"""Deterministic, explainable risk triage (Phase 10).

Scoring policy risk-policy/2025a/1.0:
    risk = min(100, S*16 + T*14 + C*10 + A*10)

    S = highest finding severity actually present (1..5)          -> evidence-backed
    T = distinct mapped technique categories (0..4 -> 0..56 scaled) -> rules-backed
    C = corroborated breadth (hosts*users coverage 0..4)           -> evidence-backed
    A = analysis completeness (parsers OK fraction 0..4)           -> process-backed

Every input is labeled with its evidence. Asset criticality and business
impact are NEVER invented; if the operator has not provided them they stay
"unknown" and the report says so.
"""
from __future__ import annotations

from ..db import query, insert, execute, one, jdump
from ..util.ids import new_id, now_iso

POLICY_VERSION = "risk-policy/2025a/1.0"


def compute(case_id: str) -> dict:
    findings = query(
        "SELECT * FROM findings WHERE case_id=? AND status!='dismissed'", (case_id,))
    mappings = query("SELECT * FROM attack_mappings WHERE case_id=?", (case_id,))
    parsers = query("SELECT * FROM parser_runs WHERE case_id=?", (case_id,))
    events = query(
        "SELECT * FROM events WHERE case_id=? AND ts_utc IS NOT NULL", (case_id,))
    evidence_count = one("SELECT COUNT(*) AS n FROM evidence WHERE case_id=?", (case_id,))["n"]

    # S: highest severity present in evidence
    unsupported = one(
        "SELECT COUNT(*) AS n FROM parser_runs WHERE case_id=? AND status IN ('failed','unsupported')",
        (case_id,))
    unsupported = unsupported["n"] if unsupported else 0
    severities = [f["severity"] for f in findings] or [0]
    s = max(severities)

    # T: distinct tactic categories among flags
    tactics = sorted({m["tactic"] for m in mappings})
    t_buckets = min(4, len(tactics))

    # C: breadth across hosts/users
    hosts = {e["hostname"] for e in events if e["hostname"]}
    users = {e["username"] for e in events if e["username"]}
    breadth = 0
    if len(hosts) > 1:
        breadth += 2
    elif hosts:
        breadth += 1
    if len(users) > 3:
        breadth += 2
    elif users:
        breadth += 1
    c_buckets = breadth

    # A: analysis completeness -> fraction of parser runs that succeeded OK
    ok = sum(1 for r in parsers if r["status"] in ("completed", "completed_with_errors"))
    if evidence_count == 0:
        a_buckets = 0
    else:
        a_buckets = min(4, round(4 * ok / max(1, evidence_count)))

    score = min(100, s * 16 + t_buckets * 14 + c_buckets * 10 + a_buckets * 10)
    band = ("low" if score < 30 else
            "medium" if score < 55 else
            "high" if score < 80 else "critical")
    inputs = {
        "S_max_finding_severity": {
            "value": s, "evidence": "finding ids " + ", ".join(f["id"] for f in findings) or "none",
            "note": "highest severity actually present among evidence-backed findings",
        },
        "T_tactic_diversity": {
            "value": t_buckets, "of": 4,
            "evidence": [f"{m['technique_id']} {m['technique_name']}" for m in mappings][:12],
            "tactics": tactics,
            "note": "distinct ATT&CK tactics from rule-backed mappings",
        },
        "C_breadth": {
            "value": c_buckets, "of": 4,
            "evidence": {"hosts": sorted(hosts), "users": sorted(users)[:10]},
            "note": "scope of hosts/users touched by events",
        },
        "A_analysis_completeness": {
            "value": a_buckets, "of": 4,
            "evidence": {r["parser"]: r["status"] for r in parsers},
            "note": "fraction of parser runs that completed; failed/unsupported parsers "
            "reduce analysis confidence",
        },
        "D_unsupported_evidence": {
            "value": unsupported, "evidence": "parser_runs",
            "note": "count of failed/unsupported parser runs (uncertainty, reduces confidence)",
        },
        "operator_context": {
            "asset_criticality": "unknown",
            "business_impact": "unknown",
            "note": "supplied only by the investigator; never invented by the app",
        },
    }
    formula = ("risk = min(100, S*16 + T*14 + C*10 + A*10) under " + POLICY_VERSION
               + "; S<=5, T,C,A<=4. Score is a triage priority, not a probability of compromise.")
    execute("DELETE FROM risk_assessments WHERE case_id=?", (case_id,))
    row = {
        "id": new_id("rk"), "case_id": case_id, "version": POLICY_VERSION,
        "score": score, "band": band,
        "inputs": jdump(inputs), "formula": formula, "computed_at": now_iso(),
    }
    insert("risk_assessments", row)
    return row


def get(case_id: str):
    return one("SELECT * FROM risk_assessments WHERE case_id=? ORDER BY computed_at DESC LIMIT 1",
               (case_id,))
