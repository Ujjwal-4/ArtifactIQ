"""JSON API blueprints: cases, evidence, parsing, analysis, reports, audit."""
from __future__ import annotations

import json as _json
import os
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, request, abort, current_app, redirect, send_file

from ..db import query, one, insert, update, execute, jdump, jload
from ..util.ids import new_id, now_iso
from ..util.validation import validate_case_payload, CAPABILITIES
from ..util.pathsafety import safe_original_name
from ..util.audit import audit
from ..services import custody, evidence as ev_service, parsing, timeline as tsvc, \
    graph as graphsvc, attack as attacksvc, prediction as predsvc, risk as risksvc, \
    explanation as expl, phases, reports as repotsv, simulation as simsvc
from ..acquisition import live as acq
from ..config import Config

api_bp = Blueprint("api", __name__)


def err(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


def ok(**kw):
    kw.setdefault("ok", True)
    return jsonify(kw)


# ---------------------------------------------------------------- cases

@api_bp.post("/cases")
def create_case():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        # fall back to form-submitted fields (tests, non-JSON clients)
        data = request.form.to_dict()
    payload, error = validate_case_payload(data)
    if error:
        return err(error)
    dup = one("SELECT id FROM cases WHERE case_number=?", (payload["case_number"],))
    if dup:
        return err(f"Case number '{payload['case_number']}' is already in use.")
    cid = new_id("cs")
    insert("cases", {
        "id": cid, **payload, "status": "active",
        "created_at": now_iso(), "updated_at": now_iso(),
    })
    phases.record_case_intake(cid, {"case_number": payload["case_number"]})
    custody.append("case_created", cid, None, actor=payload["investigator"],
                   reason=f"Case '{payload['case_number']}' created (mode={payload['mode']}).")
    audit("case_created", target=cid, detail=payload["case_number"])
    return ok(case_id=cid)


@api_bp.get("/cases")
def list_cases():
    rows = query("SELECT * FROM cases ORDER BY created_at DESC")
    return ok(cases=[dict(r) for r in rows])


@api_bp.get("/cases/<case_id>")
def get_case(case_id):
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    return ok(case=dict(c))


@api_bp.post("/cases/<case_id>/update")
def update_case(case_id):
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    data = request.get_json(silent=True) or {}
    changes = {}
    for f in ("title", "description", "scope", "authorization", "investigator"):
        if f in data and isinstance(data[f], str):
            if len(data[f]) > 4000:
                return err(f"{f} too long.")
            changes[f] = data[f].strip()
    if changes:
        changes["updated_at"] = now_iso()
        update("cases", case_id, changes)
        custody.append("case_updated", case_id, None, actor=c["investigator"] or "user",
                       reason=f"Case metadata updated: {', '.join(changes)}")
        audit("case_updated", target=case_id)
    return ok()


@api_bp.post("/cases/<case_id>/archive")
def archive_case(case_id):
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    update("cases", case_id, {"status": "archived" if c["status"] == "active" else "active",
                              "updated_at": now_iso()})
    custody.append("case_archive_toggled", case_id, None,
                   reason=f"Case status set to {one('SELECT status FROM cases WHERE id=?', (case_id,))['status']}")
    if not request.is_json:
        # plain form submission (no fetch JS): land back on the case list, never raw JSON
        return redirect("/cases", code=303)
    return ok(status=one("SELECT status FROM cases WHERE id=?", (case_id,))["status"])


@api_bp.post("/cases/<case_id>/delete")
def delete_case(case_id):
    """Authorized deletion with documented retention semantics."""
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    data = request.get_json(silent=True) if request.is_json else request.form
    confirm = (data or {}).get("confirm")
    if confirm != (case_id + ":DELETE"):
        return err("Deletion requires confirm == case_id + ':DELETE'. "
                   "Evidence copies go to the trash retention folder; custody records are kept.")
    rows = query("SELECT id FROM evidence WHERE case_id=?", (case_id,))
    notes = []
    for e in rows:
        try:
            notes.append(ev_service.remove_with_retention(e["id"], actor="user")["note"])
        except ValueError as exc:
            return err(str(exc))
    execute("DELETE FROM cases WHERE id=?", (case_id,))
    audit("case_deleted", target=case_id, detail=";".join(notes)[:2000])
    if not request.is_json:
        # plain form submission (no fetch JS): land on the case list, never raw JSON
        return redirect("/cases", code=303)
    return ok(removed_evidence=len(rows), retention_notes=notes)


# ---------------------------------------------------------------- evidence

ALLOWED_EXT = set(ev_service.MEDIA_BY_EXT.keys()) | {".log", ".log1", ".log2", ".history"}


@api_bp.post("/cases/<case_id>/evidence")
def upload_evidence(case_id):
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    f = request.files.get("file")
    if not f or not f.filename:
        return err("multipart field 'file' is required")
    original = safe_original_name(f.filename)
    ext = Path(original).suffix.lower()
    if ext and ext not in ALLOWED_EXT:
        return err(f"Files ending '{ext}' are not on the allow-list.")
    declared = (request.form.get("media_type") or "").strip() or None
    if declared and declared not in set(ev_service.MEDIA_BY_EXT.values()) | {"text", "csv", "json"}:
        return err("Unknown declared media type.")
    investigator = (request.form.get("investigator") or c["investigator"] or "user").strip() or "user"
    method = "snapshot" if (request.form.get("acquisition_method") == "snapshot") else "offline_upload"
    source_desc = (request.form.get("source_desc") or "")[:500]
    notes = (request.form.get("notes") or "")[:2000]
    source_hash = (request.form.get("source_hash") or "").strip() or None
    if source_hash and len(source_hash) not in (16, 40, 64):
        return err("source_hash must be a 16/40/64-hex fragment.")
    # stream to a safe temp path, then preserve as evidence
    tmpdir = Path(Config.WORK_DIR)
    tmpdir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkstemp(prefix="up_", dir=str(tmpdir))[1])
    try:
        f.save(str(tmp))
        size = tmp.stat().st_size
        if size == 0:
            return err("Refusing to register an empty file.")
        if size > Config.MAX_CONTENT_LENGTH:
            return err("File exceeds the configured size limit.")
        row = ev_service.store_copy(
            case_id, str(tmp), original, declared, investigator,
            source_desc=source_desc, notes=notes,
            acquisition_method=method, source_hash=source_hash,
        )
        row["display_size"] = (f"{size / 1024 / 1024:.1f} MB" if size > 1e6 else f"{size / 1024:.1f} KB")
    except ValueError as exc:
        return err(str(exc))
    except OSError as exc:
        return err(f"Upload storage failed: {exc}", 500)
    finally:
        try:
            tmp.unlink()
        except OSError:
            current_app.logger.warning("temp upload cleanup failed for %s", tmp)
    return ok(evidence=row)


@api_bp.get("/cases/<case_id>/evidence")
def get_evidence(case_id):
    rows = query("SELECT * FROM evidence WHERE case_id=? ORDER BY created_at DESC", (case_id,))
    return ok(evidence=[dict(r) for r in rows])


@api_bp.post("/evidence/<evidence_id>/verify")
def verify_evidence(evidence_id):
    try:
        res = ev_service.verify_evidence(evidence_id, actor="user")
    except ValueError as exc:
        return err(str(exc))
    return ok(**res)


@api_bp.get("/evidence/<evidence_id>/preview")
def evidence_preview(evidence_id):
    try:
        return ok(preview=ev_service.preview(evidence_id))
    except ValueError as exc:
        return err(str(exc), 404)


@api_bp.post("/evidence/<evidence_id>/remove")
def remove_evidence(evidence_id):
    try:
        res = ev_service.remove_with_retention(evidence_id, actor="user")
    except ValueError as exc:
        return err(str(exc))
    return ok(**res)


@api_bp.get("/cases/<case_id>/custody")
def custody_chain(case_id):
    res = custody.verify(case_id)
    records = [dict(r) for r in custody.for_case(case_id, limit=2000)]
    return ok(verification=res, records=records)


@api_bp.post("/custody/<evidence_id>/verify_evidence_chain")
def evidence_chain(evidence_id):
    return ok(**custody.verify(evidence_id=evidence_id))


# ---------------------------------------------------------------- parsing

@api_bp.post("/cases/<case_id>/parse")
def parse_case(case_id):
    c = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not c:
        return err("Case not found.", 404)
    data = request.get_json(silent=True) or {}
    ev_id = (data.get("evidence_id") or "").strip()
    if ev_id:
        ev = ev_service.get_evidence(ev_id)
        if not ev or ev["case_id"] != case_id:
            return err("Evidence not found in this case.", 404)
        run = parsing.run_parser(ev)
        phases.refresh_phase_status(case_id, "p04_parsing")
        return ok(run=dict(run))
    res = parsing.run_all_parsers(case_id)
    phases.refresh_phase_status(case_id, "p04_parsing")
    return ok(**res)


@api_bp.get("/cases/<case_id>/parser_runs")
def parser_runs(case_id):
    rows = query("SELECT * FROM parser_runs WHERE case_id=? ORDER BY started_at DESC", (case_id,))
    out = []
    for r in rows:
        d = dict(r)
        d["detail_json"] = jload(r["detail"], {})
        out.append(d)
    return ok(runs=out, coverage=parsing.coverage_report(case_id))


# ---------------------------------------------------------------- timeline

@api_bp.get("/cases/<case_id>/timeline")
def timeline(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    args = {k: request.args.get(k, "") for k in
            ("q", "event_type", "category", "user", "host", "evidence_id", "from", "to", "sort", "dir")}
    page = int(request.args.get("page") or 1)
    per = int(request.args.get("per_page") or 100)
    return ok(**tsvc.search(case_id, args, page, per))


@api_bp.get("/cases/<case_id>/timeline/clusters")
def timeline_clusters(case_id):
    return ok(clusters=tsvc.cluster(case_id), stats=tsvc.stats(case_id))


@api_bp.get("/cases/<case_id>/timeline/export")
def timeline_export(case_id):
    args = {k: request.args.get(k, "") for k in
            ("q", "event_type", "category", "user", "host", "evidence_id", "from", "to")}
    data = tsvc.export_csv(case_id, args)
    resp = current_app.response_class(data, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="timeline_{case_id}.csv"'
    return resp


@api_bp.get("/events/<event_id>")
def event_detail(event_id):
    e = one("SELECT * FROM events WHERE id=?", (event_id,))
    if not e:
        return err("Event not found.", 404)
    d = dict(e)
    d["tags"] = jload(e["tags"], [])
    ev = ev_service.get_evidence(e["evidence_id"])
    d["evidence"] = dict(ev) if ev else None
    run = one("SELECT * FROM parser_runs WHERE id=?", (e["run_id"],))
    d["parser_run"] = dict(run) if run else None
    return ok(event=d)


# ---------------------------------------------------------------- graph & attack

@api_bp.post("/cases/<case_id>/analyze")
def analyze(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    g = graphsvc.build_graph(case_id)
    a = attacksvc.build_mappings(case_id)
    phases.refresh_phase_status(case_id, "p08_graph_attack")
    return ok(graph=g, attack=a)


@api_bp.get("/cases/<case_id>/graph")
def graph_view(case_id):
    focus = request.args.get("focus") or None
    hop_limit = max(1, min(3, int(request.args.get("hops") or 1)))
    return ok(graph=graphsvc.get_graph(case_id, focus, hop_limit), hops=hop_limit)


@api_bp.get("/cases/<case_id>/attack")
def attack_view(case_id):
    rows = query("SELECT * FROM attack_mappings WHERE case_id=?", (case_id,))
    findings = query("SELECT * FROM findings WHERE case_id=? ORDER BY severity DESC", (case_id,))
    return ok(version=attacksvc.RULES_VERSION,
              mappings=[dict(r) for r in rows],
              findings=[dict(f) for f in findings])


# ---------------------------------------------------------------- prediction

@api_bp.post("/cases/<case_id>/branches/generate")
def branches_generate(case_id):
    res = predsvc.generate(case_id)
    phases.refresh_phase_status(case_id, "p09_branches")
    return ok(**res)


@api_bp.get("/cases/<case_id>/branches")
def branches_view(case_id):
    rows = query("SELECT * FROM branches WHERE case_id=? ORDER BY priority DESC", (case_id,))
    return ok(branches=[{**dict(r), "evidence_ids": jload(r["evidence_ids"]),
                         "event_ids": jload(r["event_ids"]),
                         "missing_evidence": jload(r["missing_evidence"]),
                         "steps": jload(r["steps"]),
                         "priority_calc": jload(r["priority_calc"])} for r in rows],
              version=predsvc.RULES_VERSION)


@api_bp.post("/branches/<branch_id>/decide")
def branch_decide(branch_id):
    data = request.get_json(silent=True) or {}
    try:
        res = predsvc.decide(branch_id, data.get("status", ""), data.get("note", ""))
    except ValueError as exc:
        return err(str(exc))
    if not res:
        return err("Branch not found.", 404)
    return ok(**res, decision_by="investigator-authoritative")


# --------------------------------------------------- simulation (attack chains)

@api_bp.post("/cases/<case_id>/simulation/generate")
def simulation_generate(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    res = simsvc.generate(case_id)
    return ok(**{k: v for k, v in res.items() if k != "ok"})


@api_bp.get("/cases/<case_id>/simulation")
def simulation_view(case_id):
    rows = query("SELECT * FROM simulations WHERE case_id=? ORDER BY priority DESC", (case_id,))
    return ok(scenarios=[{**dict(r), "nodes": jload(r["nodes"]),
                          "trigger_event_ids": jload(r["trigger_event_ids"]),
                          "evidence_ids": jload(r["evidence_ids"]),
                          "priority_calc": jload(r["priority_calc"])} for r in rows],
              version=simsvc.RULES_VERSION)

# ---------------------------------------------------------------- risk

@api_bp.post("/cases/<case_id>/risk")
def risk_compute(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    row = risksvc.compute(case_id)
    phases.refresh_phase_status(case_id, "p10_risk")
    return ok(risk={**dict(row), "inputs": jload(row["inputs"])}, version=row["version"])


@api_bp.get("/cases/<case_id>/risk")
def risk_view(case_id):
    row = risksvc.get(case_id)
    return ok(risk={**dict(row), "inputs": jload(row["inputs"])} if row else None)


# ---------------------------------------------------------------- explanation

@api_bp.get("/cases/<case_id>/explanation")
def explanation(case_id):
    res = expl.narrative(case_id)
    # p11 is completed on demand: the explanation was actually built + shown
    last_p11 = one(
        "SELECT status FROM phase_runs WHERE case_id=? AND phase='p11_explain' "
        "ORDER BY started_at DESC, rowid DESC LIMIT 1", (case_id,))
    if res.get("sentences") and (not last_p11 or last_p11["status"] != "completed"):
        phases.record_explanation(case_id, {
            "sentences": len(res.get("sentences", [])),
            "findings": res.get("findings_count"),
            "mappings": res.get("mappings_count"),
            "branches": res.get("branches_count"),
        })
    # merge narrative fields so clients can read "sentences"/"cites" directly
    return ok(explanation=res, llm_active=expl.llm_active(), **res)


@api_bp.post("/cases/<case_id>/explanation/llm")
def explanation_llm(case_id):
    if not expl.llm_active():
        return err(
            "Remote LLM assist is disabled. Set ARTIFACTIQ_LLM_ENABLED=1 and "
            "ARTIFACTIQ_LLM_URL to enable; only derived narrative text is sent.",
            409)
    return ok(**expl.llm_summarize(case_id))


# ---------------------------------------------------------------- phases

@api_bp.get("/cases/<case_id>/phases")
def phase_status(case_id):
    return ok(phases=phases.status_map(case_id))


@api_bp.post("/cases/<case_id>/phases/refresh")
def phase_refresh(case_id):
    return ok(phases=phases.refresh_case(case_id))


# ---------------------------------------------------------------- acquisition

@api_bp.get("/acquisition/sources")
def acq_sources():
    return ok(sources=[{"id": k, **v} for k, v in acq.SOURCES.items()],
              live_enabled=Config.LIVE_ACQUISITION_ENABLED)


@api_bp.post("/cases/<case_id>/acquisition/sessions")
def acq_plan(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    data = request.get_json(silent=True) or {}
    try:
        sid = acq.start_session(
            case_id,
            operator=(data.get("operator") or "user"),
            plan=data.get("sources") or [],
            authorization_ack=bool(data.get("authorization_ack")),
            impact_ack=bool(data.get("impact_ack")),
        )
        if data.get("run", True):
            res = acq.run_session(sid)
            phases.refresh_phase_status(case_id, "p03_acquisition")
            res.pop("session_id", None)  # route already returns session_id
            return ok(session_id=sid, **res)
        return ok(session_id=sid, status="planned")
    except ValueError as exc:
        return err(str(exc))


@api_bp.post("/acquisition/<session_id>/cancel")
def acq_cancel(session_id):
    try:
        acq.cancel_session(session_id)
    except Exception as exc:
        return err(str(exc), 500)
    return ok(cancelled=session_id)


@api_bp.get("/cases/<case_id>/acquisition")
def acq_status(case_id):
    return ok(sessions=[dict(r) for r in query(
        "SELECT * FROM acquisition_sessions WHERE case_id=? ORDER BY started_at DESC", (case_id,))],
        artifacts=acq.list_detailed_for_case(case_id))


# ------------------------------------------------------------ disk image (p06)

@api_bp.get("/cases/<case_id>/image")
def image_status(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    from ..services import image_analysis as img
    runs = img.runs_for_case(case_id)
    latest = runs[0]["id"] if runs else None
    e = img.engine()
    return ok(engine=e, images=img.disk_images(case_id), runs=runs,
              files=img.files_for_run(latest, 300) if latest else [])


@api_bp.post("/cases/<case_id>/image/analyze")
def image_analyze(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    data = request.get_json(silent=True) or {}
    from ..services import image_analysis as img
    try:
        res = img.analyze(case_id, (data.get("evidence_id") or "").strip() or None)
    except ValueError as exc:
        return err(str(exc))
    phases.refresh_phase_status(case_id, "p06_image")
    audit("image_analysis_run", target=case_id,
          detail=f"{len(res['runs'])} image(s) analyzed via {res['engine']['version']}")
    return ok(**res)


# ---------------------------------------------------------------- reports

@api_bp.post("/cases/<case_id>/reports")
def make_report(case_id):
    if not one("SELECT id FROM cases WHERE id=?", (case_id,)):
        return err("Case not found.", 404)
    data = request.get_json(silent=True) or {}
    kind = data.get("kind") or "html"
    try:
        row = repotsv.save_report(case_id, kind)
    except ValueError as exc:
        return err(str(exc))
    except RuntimeError as exc:
        return err(str(exc), 501)
    phases.refresh_phase_status(case_id, "p12_reports")
    return ok(report=dict(row))


@api_bp.get("/cases/<case_id>/reports")
def list_reports(case_id):
    return ok(reports=[dict(r) for r in repotsv.list_reports(case_id)])


@api_bp.get("/reports/<report_id>/download")
def download_report(report_id):
    r = one("SELECT * FROM reports WHERE id=?", (report_id,))
    if not r:
        return err("Report not found.", 404)
    from pathlib import Path
    from ..util.pathsafety import resolve_within
    try:
        fpath = resolve_within(str(Config.REPORTS_DIR), r["path"])
    except ValueError as exc:
        return err(f"Stored report path failed containment check: {exc}", 500)
    if not fpath.is_file():
        return err("Report file missing on disk.", 404)
    return send_file(fpath, as_attachment=True, download_name=Path(r["path"]).name)


# ---------------------------------------------------------------- audit

@api_bp.get("/audit")
def audit_log():
    rows = query("SELECT * FROM audit_events ORDER BY id DESC LIMIT 300")
    return ok(audit=[dict(r) for r in rows])


# ---------------------------------------------------------------- demo

@api_bp.post("/demo/load")
def demo_load():
    from ..demo_loader import build_demo_case, build_targeted_demo

    mode = (request.get_json(silent=True) or {}).get("mode") or "full"
    try:
        if mode == "targeted":
            cid, caps = build_targeted_demo()
        else:
            cid = build_demo_case()
    except Exception as exc:  # demo loader must never lie about failure
        return err(f"Demo build failed: {exc}", 500)
    if not request.is_json:
        # real form submission (no fetch JS): land the user on the new case,
        # never a raw JSON page
        return redirect(f"/cases/{cid}", code=303)
    return ok(case_id=cid)
