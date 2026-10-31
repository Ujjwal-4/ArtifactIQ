/* Tab script 'simulation' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config in tabs/simulation.html. */
var CFG = JSON.parse(document.getElementById("cfg-simulation").textContent);
document.addEventListener("DOMContentLoaded", function () {

  var SIM_DISCLAIMER = "Nodes marked <b>predicted</b> describe typical attacker behavior " +
    "from knowledge base " + "sim-rules — they must be verified in evidence before any " +
    "narrative states them as fact. Observed nodes cite events from this case.";

  function statusBadge(st) {
    return st === "observed"
      ? '<span class="badge ok" title="matching events exist in this case">observed</span>'
      : '<span class="badge blocked" title="no matching artifact in this case yet">predicted</span>';
  }

  function renderNode(n) {
    var isObs = n.status === "observed";
    var t = n.technique || {};
    var html = '<div class="sim-node ' + (isObs ? "obs" : "pred") + '">' +
      '<div class="sim-node-head">' +
        '<span class="sim-step">' + n.idx + '</span>' +
        '<div style="flex:1">' +
          '<div class="sim-title">' + esc(n.title) + '</div>' +
          '<div class="tiny"><span class="badge neutral">' + esc(t.technique_id || "-") + '</span> ' +
            esc(t.technique_name || "") + ' <span class="faint">· ' + esc(t.tactic || "") + '</span></div>' +
        '</div>' +
        '<div class="btn-row" style="flex-direction:column;align-items:flex-end;gap:4px">' +
          statusBadge(n.status) +
          (isObs && n.evidence_ids.length
            ? '<span class="tiny faint mono">' + esc(n.evidence_ids.join(", ")) + '</span>' : "") +
        '</div>' +
      '</div>' +
      '<div class="tiny muted" style="margin-top:6px">' + esc(n.description) + '</div>' +
      '<div class="sim-grid">' +
        '<div><div class="sim-k">Artifacts to look for</div><ul>' +
          n.expected_artifacts.map(function (a) { return '<li>' + esc(a) + '</li>'; }).join("") +
        '</ul></div>' +
        '<div><div class="sim-k">Possible consequence</div><div class="tiny">' + esc(n.consequence) + '</div>' +
        '<div class="sim-k" style="margin-top:6px">Impact</div><div class="tiny">' + esc(n.impact) + '</div></div>' +
        '<div><div class="sim-k">Prevention <span class="faint tiny">(generic, ATT&CK M-codes)</span></div>' +
          '<div class="chip-row">' +
          n.prevention.map(function (m) { return '<span class="chip">' + esc(m) + '</span>'; }).join("") +
          '</div></div>' +
      '</div>' +
      (n.honesty_note && n.honesty_note.length
        ? '<div class="sim-note">' + esc(n.honesty_note) + '</div>' : "") +
      (isObs && n.event_ids.length
        ? '<div class="tiny faint" style="margin-top:6px">matching events: <span class="mono">' +
          esc(n.event_ids.join(", ")) + '</span></div>' : "") +
    '</div>';
    return html;
  }

  function renderChain(s) {
    var html = '<div class="sim-card">' +
      '<div class="btn-row" style="justify-content:space-between;align-items:flex-start">' +
        '<div><div class="q">' + esc(s.title) + '</div>' +
        '<div class="why">Trigger: <b>' + esc(s.trigger_rule) + '</b> — ' + esc(s.trigger_summary) + '</div></div>' +
        '<div style="text-align:right">' +
          '<div class="prio ' + (s.priority >= 80 ? "p-crit" : s.priority >= 60 ? "p-high" : "") + '">' + s.priority + '</div>' +
          '<span class="badge neutral">' + esc(s.scenario_id) + '</span>' +
          '<div class="tiny faint">' + s.observed_count + ' of ' + s.depth + ' nodes observed</div>' +
        '</div>' +
      '</div>' +
      '<div class="sim-chain">' +
        s.nodes.map(renderNode).join('<div class="sim-link"><span class="tiny faint">▼ then typically</span></div>') +
      '</div>' +
      '<div class="tiny faint">calc: <span class="mono">' + esc(JSON.stringify(s.priority_calc)) + '</span></div>' +
      '<div class="sim-note" style="margin-top:8px">' + SIM_DISCLAIMER + '</div>' +
    '</div>';
    return html;
  }

  api(CFG.sim_view).then(function (j) {
    document.getElementById("sim-version").textContent = j.version;
    var el = document.getElementById("sim-list");
    if (!j.scenarios.length) {
      el.innerHTML = '<div class="empty"><span class="icon">🧭</span>No incident triggers in this case yet. ' +
        'Parse evidence first; simulation only runs from findings that actually exist.</div>';
      return;
    }
    el.innerHTML = j.scenarios.map(renderChain).join("");
  }).catch(function (er) {
    document.getElementById("sim-list").innerHTML = '<div class="empty">' + esc(er.message) + '</div>';
  });
});
