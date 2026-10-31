"""Renders the standalone HTML case report (self-contained, evidence-cited)."""
from __future__ import annotations

import html as _html


def esc(s):
    return _html.escape(str(s if s is not None else ""), quote=True)


def render_report_html(ctx: dict) -> str:
    case = ctx["case"]
    ev_rows = ctx["evidence"]
    risk = ctx["risk"]
    ph_rows = ""
    for key, p in ctx["phases"].items():
        cls = "opacity:.85"
        ph_rows += (
            "<tr><td class='mono'>" + esc(p["title"]) + "</td><td><span class='badge " +
            esc(p["status"]) + "'>" + esc(p["status"]) + "</span></td><td class='muted small'>" +
            esc((p["at"] or "")[:19].replace("T", " ")) + "</td></tr>"
        )
    ev_html = "".join(
        "<tr><td><b>" + esc(e["original_name"]) + "</b></td><td>" + esc(e["media_type"]) +
        "</td><td>" + esc(e["acquired_at"][:19]) + "</td><td><code>" + esc(e["sha256"][:24]) +
        "…</code></td><td>" + esc(e["verify_status"]) + "</td></tr>"
        for e in ev_rows
    ) or "<tr><td colspan='5' class='muted'>No evidence registered.</td></tr>"
    findings_html = "".join(
        "<tr><td>S" + str(f["severity"]) + "</td><td><b>" + esc(f["title"]) + "</b><div class='muted small'>" +
        esc(f["description"]) + "</div><div class='mono tiny faint'>events: " +
        esc(", ".join(__import__("json").loads(f["event_ids"])[:8])) +
        " · evidence: " + esc(", ".join(__import__("json").loads(f["evidence_ids"]))) +
        "</div></td></tr>"
        for f in ctx["findings"]
    ) or "<tr><td class='muted'>No evidence-backed findings; absence is not safety.</td></tr>"
    maps_html = "".join(
        "<tr><td><code>" + esc(m["technique_id"]) + "</code> " + esc(m["technique_name"]) +
        "</td><td>" + esc(m["tactic"]) + "</td><td class='muted small'>" + esc(m["rationale"]) +
        "</td><td>" + esc(m["confidence"]) + "</td></tr>"
        for m in ctx["mappings"]
    ) or "<tr><td colspan='4' class='muted'>No mappings supported by the evidence.</td></tr>"
    branches_html = "".join(
        "<tr><td><b>P" + str(b["priority"]) + "</b></td><td><b>" + esc(b["question"]) +
        "</b><div class='muted small'>" + esc(b["why"]) + "</div><div class='tiny faint'>missing: " +
        esc(", ".join(__import__("json").loads(b["missing_evidence"]))) +
        "</div><div class='mono tiny faint'>calc " + esc(b["priority_calc"]) +
        " · rule " + esc(str(b["rule_id"]) + " / " + str(b["rule_version"])) + "</div></td>" +
        "<td>" + esc(b["status"]) + "</td></tr>"
        for b in ctx["branches"]
    ) or "<tr><td colspan='3' class='muted'>No branches recorded.</td></tr>"
    run_errors = ctx["parser_runs"]
    runs_html = "".join(
        "<tr><td>" + esc(r["parser"]) + "</td><td>" + esc(r["status"]) + "</td><td class='num'>" +
        str(r["events_added"]) + "</td><td class='muted small'>" + esc(r["message"]) + "</td></tr>"
        for r in run_errors
    ) or "<tr><td colspan='4' class='muted'>No parser runs recorded.</td></tr>"
    custody_html = "".join(
        "<tr><td>#</td></tr>".replace("<tr><td>#</td></tr>", "<tr><td class='num'>" + str(c["seq"]) +
        "</td><td class='tiny mono'>" + esc(c["ts"][:19]) + "</td><td>" + esc(c["actor"]) +
        "</td><td><span class='chip'>" + esc(c["action"]) + "</span></td><td class='tiny mono'>" +
        esc(str(c["evidence_id"] or "—")) + "</td><td class='small'>" + esc(c["reason"]) +
        "</td><td class='mono tiny'>" + esc(c["record_hash"][:16]) + "…</td></tr>")
        for c in ctx["custody"][:120]
    ) or "<tr><td colspan='7' class='muted'>No custody records.</td></tr>"
    narrative_html = "".join(
        "<p class='small' style='margin:.35rem 0'>◈ " + esc(s) + "</p>" for s in ctx["narrative"]["sentences"]
    )
    risk_inputs_kses = __import__("json").loads(risk["inputs"])
    risk_inputs_rows = "".join(
        "<tr><td class='mono small'>" + esc(k) + "</td><td>" + esc(str(v.get("value", ""))) +
        "</td><td class='muted small'>" + esc(
            __import__("json").dumps(v.get("evidence", ""))[:180] if isinstance(v.get("evidence"), (dict, list))
            else str(v.get("evidence", ""))) +
        "</td></tr>"
        for k, v in risk_inputs_kses.items()
    )
    stat = ctx["stats"]
    day_rows = "".join("<li>" + esc(d["day"]) + " — " + str(d["n"]) + " events</li>" for d in stat["per_day"][:20])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Case report {esc(case['case_number'])}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/static/css/app.css">
<style>.report-standalone .content {{ max-width:none }}</style>
</head><body class="report-standalone">
<div class="app"><main class="content">
<div class="page-title"><h1>ArtifactIQ case report</h1><span class="muted">tool version {esc(ctx['tool_version'])} · generated {esc(ctx['generated_at'])} UTC</span></div>

<div class="panel">
<h2>Case</h2>
<dl class="kv">
<dt>Case number</dt><dd class="mono">{esc(case['case_number'])}</dd>
<dt>Title</dt><dd>{esc(case['title'])}</dd>
<dt>Investigator</dt><dd>{esc(case['investigator'])}</dd>
<dt>Mode</dt><dd>{esc(case['mode'])}{(' — ' + esc(case['capability'])) if case['capability'] else ''}</dd>
<dt>Scope</dt><dd>{esc(case['scope']) or '—'}</dd>
<dt>Authorization</dt><dd>{esc(case['authorization']) or '—'}</dd>
</dl>
</div>

<div class="panel">
<h2>Methodology &amp; disclaimers</h2>
<p class="small muted">
Evidence was hashed with SHA-256 at registration; custody is an append-only hash-chained ledger inside the
local database. Timestamps are stored as UTC where the artifact provides a defined time base; naive or missing
timestamps are preserved as-is and never fabricated. Findings, ATT&amp;CK mappings, branches, and the risk score
are <b>investigative leads</b>, not conclusions. Reports never claim authenticity beyond the preserved copy.
</p>
<ul class="small muted">
{''.join('<li>' + esc(d) + '</li>' for d in ctx['disclaimers'])}
</ul>
</div>

<div class="panel">
<h2>Evidence inventory</h2>
<div class="table-wrap"><table><thead><tr><th>Original name</th><th>Type</th><th>Acquired (UTC)</th><th>SHA-256 (screened)</th><th>Integrity</th></tr></thead>
<tbody>{ev_html}</tbody></table></div>
</div>

<div class="panel">
<h2>Parser runs &amp; errors</h2>
<div class="table-wrap"><table><thead><tr><th>Parser</th><th>Status</th><th>Events</th><th>Message</th></tr></thead>
<tbody>{runs_html}</tbody></table></div>
</div>

<div class="panel">
<h2>Findings</h2>
<div class="table-wrap"><table><tbody>{findings_html}</tbody></table></div>
</div>

<div class="panel">
<h2>MITRE ATT&amp;CK mappings <span class="faint tiny">{esc(ctx['attack_rule_version'])}</span></h2>
<div class="table-wrap"><table><thead><tr><th>Technique</th><th>Tactic</th><th>Rationale</th><th>Confidence</th></tr></thead>
<tbody>{maps_html}</tbody></table></div>
</div>

<div class="panel">
<h2>Predictive investigation branches <span class="faint tiny">{esc(ctx['branch_rule_version'])}</span></h2>
<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Branch</th><th>Status</th></tr></thead>
<tbody>{branches_html}</tbody></table></div>
</div>

<div class="panel">
<h2>Risk triage <span class="faint tiny">{esc(ctx['risk_policy_version'])}</span></h2>
<p class="num large" style="font-size:1.6rem">{risk['score']} <span class="badge {esc(risk['band'])}">{esc(risk['band'])}</span></p>
<p class="small muted">{esc(risk['formula'])}</p>
<div class="table-wrap"><table><thead><tr><th>Input</th><th>Value</th><th>Evidence</th></tr></thead><tbody>{risk_inputs_rows}</tbody></table></div>
</div>

<div class="panel">
<h2>Evidence-grounded narrative</h2>
{narrative_html}
<p class="tiny faint">{esc(ctx['narrative']['disclaimer'])}</p>
</div>

<div class="panel">
<h2>Chain of custody <span class="faint tiny">verification: {esc(ctx['custody_verify']['ok'] and 'chain OK' or ctx['custody_verify']['issue'])}</span></h2>
<div class="table-wrap"><table><thead><tr><th>#</th><th>Timestamp (UTC)</th><th>Actor</th><th>Action</th><th>Evidence</th><th>Reason</th><th>Record hash</th></tr></thead>
<tbody>{custody_html}</tbody></table></div>
<p class="tiny faint">Ledger immutability caveat: hash chaining detects silent modification by the application; it does not make the SQLite file tamper-proof. Export this report for external anchoring.</p>
</div>

<div class="panel">
<h2>Phase status</h2>
<div class="table-wrap"><table><thead><tr><th>Phase</th><th>Status</th><th>At (UTC)</th></tr></thead><tbody>{ph_rows}</tbody></table></div>
</div>

<div class="panel">
<h2>Timeline overview</h2>
<ul class="small">{day_rows}</ul>
</div>

</main>
<footer class="footer"><span>ArtifactIQ {esc(ctx['tool_version'])}</span>
<span class="muted">Synthetic demo data, if present, is labeled SYNTHETIC in the UI. Press export to also emit JSON outputs.</span></footer>
</div>
</body></html>"""
