"""Report generation: HTML, PDF, JSON, CSV timeline, evidence manifest,
custody report. Reports always carry tool versions, hashes, limitations, and
clearly labeled synthetic data."""
from __future__ import annotations

import csv as _csv
import io
import json
import os
from pathlib import Path

from ..config import Config, VERSION
from ..db import query, one, jload, jdump
from ..util.ids import new_id, now_iso, display_size
from ..util import hashing
from . import custody, evidence, explanation, risk, timeline as tsvc, phases
from .parsing import coverage_report
from .attack import RULES_VERSION as ATTACK_RULES_VERSION
from .prediction import RULES_VERSION as BRANCH_RULES_VERSION


DISCLAIMERS = [
    "Origin hash proves the preserved copy; it does not prove the original source was unmodified.",
    "Predictive branches, risk scores and ATT&CK mappings are investigative leads, not conclusions.",
    "Live acquisition is not zero-footprint; its traceability limits are documented in the docs.",
    "Unmapped techniques and absent findings are absence of evidence, not evidence of safety.",
]


def _case_ctx(case_id: str) -> dict:
    case = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        raise ValueError("Case not found.")
    ev_rows = evidence.case_evidence(case_id)
    ctx = {
        "case": dict(case),
        "evidence": [dict(r) for r in ev_rows],
        "events_total": one("SELECT COUNT(*) AS n FROM events WHERE case_id=?", (case_id,))["n"],
        "findings": [dict(r) for r in query(
            "SELECT * FROM findings WHERE case_id=? ORDER BY severity DESC", (case_id,))],
        "mappings": [dict(r) for r in query(
            "SELECT * FROM attack_mappings WHERE case_id=?", (case_id,))],
        "branches": [dict(r) for r in query(
            "SELECT * FROM branches WHERE case_id=? ORDER BY priority DESC", (case_id,))],
        "risk": risk.compute(case_id),
        "narrative": explanation.narrative(case_id),
        "phases": phases.status_map(case_id),
        "parser_runs": [dict(r) for r in query(
            "SELECT * FROM parser_runs WHERE case_id=? ORDER BY started_at DESC", (case_id,))],
        "custody": [dict(r) for r in custody.for_case(case_id, 400)],
        "custody_verify": custody.verify(case_id),
        "stats": tsvc.stats(case_id),
        "coverage": coverage_report(case_id),
        "generated_at": now_iso(),
        "tool_version": VERSION,
        "attack_rule_version": ATTACK_RULES_VERSION,
        "branch_rule_version": BRANCH_RULES_VERSION,
        "risk_policy_version": r"""risk-policy/2025a/1.0""",
        "disclaimers": DISCLAIMERS,
    }
    return ctx


def export_manifest(case_id: str) -> tuple[str, bytes]:
    import json as _json

    m = evidence.manifest(case_id, VERSION)
    data = _json.dumps(m, indent=2, ensure_ascii=False).encode()
    return "evidence_manifest.json", data


def export_custody_report(case_id: str) -> tuple[str, bytes]:
    import json as _json

    rep = {
        "generated_at": now_iso(),
        "tool": f"ArtifactIQ {VERSION}",
        "algorithm": "SHA-256 chain (local database alone is not immutable)",
        "verification": custody.verify(case_id),
        "records": [dict(r) for r in custody.for_case(case_id, 2000)],
        "warn": "Hash chaining protects against silent modification by the application. "
                "A database administrator can still rewrite the table; export and verify "
                "checkpoints to disagree with tampering.",
    }
    data = _json.dumps(rep, indent=2, ensure_ascii=False).encode()
    return "chain_of_custody.json", data


def export_timeline_csv(case_id: str) -> tuple[str, str]:
    data = tsvc.export_csv(case_id, {})
    return "timeline_export.csv", data


def export_findings_json(case_id: str) -> tuple[str, bytes]:
    import json as _json

    ctx = _case_ctx(case_id)
    doc = _json_case_doc(ctx)
    data = _json.dumps(doc, indent=2, ensure_ascii=False).encode()
    return "case_findings.json", data


def _json_case_doc(ctx: dict) -> dict:
    return {
        "tool": "ArtifactIQ " + VERSION,
        "generated_at": ctx["generated_at"],
        "disclaimers": ctx["disclaimers"],
        "case": {
            "id": ctx["case"]["id"], "case_number": ctx["case"]["case_number"],
            "title": ctx["case"]["title"], "investigator": ctx["case"]["investigator"],
            "mode": ctx["case"]["mode"], "scope": ctx["case"]["scope"],
            "authorization": ctx["case"]["authorization"],
        },
        "evidence_manifest": evidence.manifest(ctx["case"]["id"], VERSION),
        "custody_verification": ctx["custody_verify"],
        "findings": [
            {"id": f["id"], "title": f["title"], "severity": f["severity"],
             "rule": f["rule_id"] + "/" + str(f["rule_version"]),
             "evidence_ids": jload(f["evidence_ids"]),
             "event_ids": jload(f["event_ids"]), "description": f["description"]}
            for f in ctx["findings"]
        ],
        "attack_mappings": [
            {"technique_id": m["technique_id"], "name": m["technique_name"],
             "tactic": m["tactic"], "rationale": m["rationale"],
             "evidence_ids": jload(m["evidence_ids"]), "rule_version": m["rule_version"],
             "confidence": m["confidence"]}
            for m in ctx["mappings"]
        ],
        "investigation_branches": [
            {"question": b["question"], "why": b["why"],
             "priority": b["priority"], "priority_calc": jload(b["priority_calc"]),
             "missing_evidence": jload(b["missing_evidence"]),
             "status": b["status"]}
            for b in ctx["branches"]
        ],
        "risk": {
            "version": ctx["risk"]["version"], "score": ctx["risk"]["score"],
            "band": ctx["risk"]["band"], "formula": ctx["risk"]["formula"],
            "inputs": jload(ctx["risk"]["inputs"]),
        },
        "narrative": ctx["narrative"],
        "phase_status": ctx["phases"],
        "parser_runs": [
            {"id": r["id"], "evidence_id": r["evidence_id"], "parser": r["parser"],
             "status": r["status"], "events": r["events_added"],
             "errors": r["errors"], "message": r["message"]}
            for r in ctx["parser_runs"]
        ],
    }


def render_html(case_id: str) -> tuple[str, str]:
    """Professional HTML report rendered from a self-contained template."""
    from ..web.render import render_report_html

    ctx = _case_ctx(case_id)
    html = render_report_html(ctx)
    return "case_report.html", html


def render_pdf(case_id: str) -> tuple[str, bytes]:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as _canvas
    except Exception as exc:
        raise RuntimeError(f"PDF step needs the optional 'reportlab' package ({exc}).") from exc
    ctx = _case_ctx(case_id)
    buf = io.BytesIO()
    c = _canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 60
    maxy = 60
    def line(text, size=9, bold=False):
        nonlocal y
        if y < maxy:
            c.showPage()
            y = h - 60
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        for i in range(0, len(text), 95):
            c.drawString(40, y, text[i:i + 95])
            y -= size + 2
    line(f"ArtifactIQ {VERSION} - Case Report", 16, True)
    line(f"Generated {ctx['generated_at']} UTC")
    case = ctx["case"]
    line(f"Case {case['case_number']}: {case['title']}" .replace("\n", " "), 12, True)
    line(f"Investigator: {case['investigator']}  Mode: {case['mode']}  "
         f"Authorization: {(case['authorization'] or '(not recorded)')[:150]}")
    y -= 6
    line("Evidence inventory:", 11, True)
    for e in ctx["evidence"]:
        line(f"- {e['original_name']} ({e['media_type']}, {display_size(e['size'])}) "
             f"sha256={e['sha256'][:24]}... [{e['verify_status']}]", 8)
    y -= 4
    line("Findings:", 11, True)
    for f in ctx["findings"]:
        line(f"- [S{f['severity']}] {f['title']}", 9)
        for chunk in (f["description"][:300] + " ").split(".")[:6]:
            if chunk.strip():
                line("    " + chunk.strip()[:90], 8)
    y -= 4
    line("ATT&CK mappings:", 11, True)
    if not ctx["mappings"]:
        line("(none; absent evidence is not evidence of safety)", 8)
    for m in ctx["mappings"]:
        line(f"- {m['technique_id']} {m['technique_name']} [{m['tactic']}] conf={m['confidence']}", 8)
    y -= 4
    line("Branches:", 11, True)
    for b in ctx["branches"][:10]:
        line(f"- P{b['priority']} ({b['status']}) {b['question'][:150]}", 8)
    y -= 4
    line("Risk:", 11, True)
    line(f"Score {ctx['risk']['score']} ({ctx['risk']['band']}); {ctx['risk']['formula']}", 8)
    y -= 4
    for d in ctx["disclaimers"]:
        line("DISCLAIMER: " + d, 7)
    for de in DISCLAIMER_LIMITS:
        line("LIMITATION: " + de, 7)
    c.save()
    return "case_report.pdf", buf.getvalue()


DISCLAIMER_LIMITS = [
    "Chain-of-custody ledger is hash-chained inside this local database only; it does not make the database immutable.",
    "Untrusted parsers can parse incorrectly; preserve originals and verify independently for court use.",
    "Time-zone naive artifacts are stored with an explicit local-unparsed marker instead of being converted.",
]


def save_report(case_id: str, kind: str, actor: str = "user") -> dict:
    reports_dir = Path(Config.REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)
    if kind == "html":
        name, content = render_html(case_id)
        mode = "w"
    elif kind == "pdf":
        name, content = render_pdf(case_id)
        mode = "w"
    elif kind == "findings":
        name, content = export_findings_json(case_id)
        mode = "w"
    elif kind == "manifest":
        name, content = export_manifest(case_id)
        mode = "w"
    elif kind == "custody":
        name, content = export_custody_report(case_id)
        mode = "w"
    elif kind == "timeline_csv":
        name, data = export_timeline_csv(case_id)
        mode = "w"
    else:
        raise ValueError(f"Unknown report kind '{kind}'.")
    from ..db import insert

    rd = reports_dir / case_id
    rd.mkdir(parents=True, exist_ok=True)
    target = rd / name
    if kind in ("html", "timeline_csv") and isinstance(content, str):
        target.write_text(content, encoding="utf-8")
        sha = hashing.sha256_file(target)
    else:
        payload = content if isinstance(content, (bytes, bytearray)) else str(content).encode()
        target.write_bytes(payload)
        sha = hashing.sha256_file(target)
    row = {
        "id": new_id("rp"), "case_id": case_id, "kind": kind, "path": str(target.relative_to(reports_dir)),
        "created_at": now_iso(), "created_by": actor, "sha256": sha,
    }
    insert("reports", row)
    return row


def list_reports(case_id: str):
    return query("SELECT * FROM reports WHERE case_id=? ORDER BY created_at DESC", (case_id,))
