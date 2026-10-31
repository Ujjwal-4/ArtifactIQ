"""Server-rendered pages (thin controllers; data comes from JSON APIs)."""
from __future__ import annotations

from flask import Blueprint, render_template, redirect, url_for, request, abort, current_app

from ..db import query, one, jload
from ..util.validation import CAPABILITIES
from ..util.ids import display_size
from ..util import hashing
from ..services import custody
from ..config import Config

pages_bp = Blueprint("pages", __name__)


@pages_bp.context_processor
def inject_globals():
    return {"APP_NAME": "ArtifactIQ", "APP_VERSION": current_app.config["VERSION"],
            "capabilities": CAPABILITIES, "display_size": display_size}


@pages_bp.get("/")
def landing():
    cases = query("SELECT * FROM cases WHERE status='active' ORDER BY created_at DESC LIMIT 6")
    stats = {
        "cases": one("SELECT COUNT(*) AS n FROM cases")["n"],
        "evidence": one("SELECT COUNT(*) AS n FROM evidence")["n"],
        "events": one("SELECT COUNT(*) AS n FROM events")["n"],
        "audit": one("SELECT COUNT(*) AS n FROM audit_events")["n"],
    }
    return render_template("landing.html", recent_cases=[dict(c) for c in cases], stats=stats)


@pages_bp.get("/cases")
def cases():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    sql = "SELECT * FROM cases WHERE 1=1"
    params: list = []
    if q:
        sql += " AND (title LIKE ? OR case_number LIKE ? OR investigator LIKE ?)"
        params += [f"%{q}%"] * 3
    if status in ("active", "archived"):
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY created_at DESC"
    rows = query(sql, params)
    return render_template("cases.html", cases=[dict(r) for r in rows], q=q, status=status)


@pages_bp.get("/cases/<case_id>")
def case_home(case_id: str):
    case = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        abort(404)
    return redirect(url_for("pages.case_tab", case_id=case_id, tab="overview"))


@pages_bp.get("/cases/<case_id>/<tab>")
def case_tab(case_id: str, tab: str):
    case = one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        abort(404)
    tabs = {
        "overview", "evidence", "acquisition", "timeline", "graph", "attack",
        "branches", "simulation", "risk", "assistant", "reports", "audit",
    }
    if case["mode"] == "targeted":
        tabs.add("capability")
        if tab not in tabs:
            abort(404)
    elif tab == "capability":
        # the "Targeted Result" tab only exists for targeted cases; a full-case
        # URL is redirected, not 404
        from flask import redirect as _redirect
        return _redirect(url_for("pages.case_tab", case_id=case_id, tab="overview"))
    elif tab not in tabs:
        abort(404)
    # file-input accept hints per targeted capability (upload UX only; the
    # server-side extension allow-list stays the real gate)
    cap_hints = {
        "usb_check": {"accept": ".log,.reg", "media_type": "usb_history"},
        "evtx_check": {"accept": ".evtx,.evt", "media_type": "evtx"},
        "browser_check": {"accept": ".sqlite,.sqlite3,.db,.historysqlite,History",
                          "media_type": "browser_sqlite"},
        "registry_check": {"accept": ".reg,.hiv,.LOG1", "media_type": "registry_export"},
        "integrity_check": {"accept": "*/*", "media_type": ""},
    }
    hints = cap_hints.get(case["capability"], {"accept": "*/*", "media_type": ""})

    ev = query("SELECT * FROM evidence WHERE case_id=? ORDER BY created_at DESC", (case_id,))
    phases = query(
        "SELECT * FROM phase_runs WHERE case_id=? ORDER BY started_at DESC LIMIT 40", (case_id,))
    return render_template(
        "case_workspace.html", case=dict(case), tab=tab,
        evidence=[dict(r) for r in ev],
        phase_rows=[dict(r) for r in phases],
        reports=[dict(r) for r in query(
            "SELECT * FROM reports WHERE case_id=? ORDER BY created_at DESC", (case_id,))],
        cap_accept=hints["accept"], cap_media_type=hints["media_type"],
        tab_titles=TAB_TITLES,
    )


TAB_TITLES = {
    "overview": "Overview & Phases",
    "evidence": "Evidence & Integrity",
    "acquisition": "Acquisition",
    "timeline": "Timeline",
    "graph": "Event Graph",
    "attack": "ATT&CK Mapping",
    "branches": "Investigation Branches",
    "simulation": "Scenario Simulator",
    "risk": "Risk Triage",
    "assistant": "Explanation Assistant",
    "reports": "Reports",
    "audit": "Custody Ledger",
    "capability": "Targeted Result",
}


@pages_bp.get("/targeted")
def targeted_home():
    return render_template("targeted.html")


@pages_bp.get("/targeted<int:__x>")  # guard against typo scanners
def targeted_bad(__x: int):
    abort(404)


@pages_bp.get("/settings")
def settings():
    audit_rows = query("SELECT * FROM audit_events ORDER BY id DESC LIMIT 120")
    parsers = from_parsers()
    return render_template("settings.html",
                           audit=[dict(r) for r in audit_rows],
                           parsers=parsers,
                           limits={
                               "MAX_UPLOAD_MB": Config.MAX_CONTENT_LENGTH // (1024 * 1024),
                               "MAX_EVENTS": Config.MAX_EVENTS_PER_EVIDENCE,
                               "PARSER_TIMEOUT_S": Config.PARSER_TIMEOUT_S,
                               "DATA_DIR": str(Config.DB_PATH),
                           })


def from_parsers():
    from ..parsers import all_parsers

    return [{"name": p.name, "media": ", ".join(p.media_types), "needs": ", ".join(p.needs)}
            for p in all_parsers()]


@pages_bp.get("/live")
def acquisition_console():
    """Live acquisition page: sources + explicit impact + acks."""
    from ..acquisition.live import SOURCES

    return render_template(
        "acquisition.html",
        sources=[{"id": k, **v} for k, v in SOURCES.items()],
        live_enabled=Config.LIVE_ACQUISITION_ENABLED,
    )


@pages_bp.get("/report_html/<case_id>")
def report_html(case_id: str):
    row = one("SELECT * FROM reports WHERE case_id=? AND kind='html'", (case_id,))
    if not row:
        abort(404)
    path = jload(None) and None
    from pathlib import Path

    f = Path(Config.REPORTS_DIR) / row["path"]
    if not f.is_file():
        abort(404)
    html = f.read_text(encoding="utf-8")
    return html
