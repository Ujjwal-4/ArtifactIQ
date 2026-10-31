/* Tab script 'acquisition' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-acquisition").textContent);
document.addEventListener("DOMContentLoaded", function () {

  var state = { sources: [], statuses: {}, selected: {}, running: false };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function $(id) { return document.getElementById(id); }

  // ---------------------------------------------------------------- sources
  function badgeFor(status) {
    if (!status) return '<span class="badge neutral">never collected</span>';
    return '<span class="badge ' + esc(status) + '">' + esc(status.replace(/_/g, " ")) + '</span>';
  }

  function card(s) {
    var sel = !!state.selected[s.id];
    var flag = s.requires_windows ? '<span class="chip" title="This source exists only on Windows">Windows only</span>' : "";
    return '<div class="acq-card' + (sel ? " selected" : "") + '" data-card="' + esc(s.id) + '">' +
      '<div class="acq-head"><span class="acq-id"><span class="acq-icon">▣</span>' + esc(s.id) + '</span>' +
      badgeFor(state.statuses[s.id]) + '</div>' +
      '<div class="acq-label">' + esc(s.label) + '</div>' +
      '<div class="acq-impact tiny">' + esc(s.impact) + '</div>' +
      '<div class="acq-foot"><label class="acq-include">' +
      '<input type="checkbox" data-source="' + esc(s.id) + '"' + (sel ? " checked" : "") + '> include' +
      '</label>' + flag + '</div>' +
      '</div>';
  }

  function selectedIds() {
    return state.sources.filter(function (s) { return state.selected[s.id]; }).map(function (s) { return s.id; });
  }

  function updateRun() {
    var n = selectedIds().length;
    var acks = $("ack-auth").checked && $("ack-impact").checked;
    var btn = $("acq-run");
    btn.disabled = !(acks && n > 0 && !state.running);
    btn.textContent = state.running ? "Collecting…" : ("Run selected collection" + (n ? " (" + n + ")" : ""));
    $("acq-count").textContent = n
      ? (n + " of " + state.sources.length + " sources selected")
      : (state.sources.length + " sources available — nothing collected by default");
    document.querySelectorAll(".acq-card").forEach(function (c) {
      var id = c.dataset.card;
      c.classList.toggle("selected", !!state.selected[id]);
    });
  }

  function render() {
    $("source-list").innerHTML = state.sources.map(card).join("");
    document.querySelectorAll("[data-source]").forEach(function (cb) {
      cb.disabled = state.running;
      cb.addEventListener("change", function () {
        state.selected[cb.dataset.source] = cb.checked;
        updateRun();
      });
    });
    updateRun();
  }

  function loadStatus(cb) {
    api(CFG.acq_status).then(function (j) {
      (j.artifacts || []).forEach(function (a) {
        state.statuses[a.source_id] = a.status;
      });
      renderArtifacts(j);
      cb();
    }).catch(function () { cb(); });
  }

  function renderArtifacts(j) {
    var rows = (j.artifacts || []).map(function (a) {
      return '<tr><td class="tiny"><b>' + esc(a.source_id) + '</b></td>' +
        '<td>' + badgeFor(a.status) + '</td>' +
        '<td class="mono tiny">' + esc(a.evidence_id || "—") + '</td>' +
        '<td class="mono tiny">' + esc(fmtLocal(a.started_at || "")) + '</td>' +
        '<td class="tiny muted wrap">' + esc(a.message) + '</td></tr>';
    }).join("");
    $("acq-artifacts").innerHTML = rows ||
      '<tr><td colspan="5"><div class="empty" style="border:none">No acquisition attempts recorded yet. Select sources above to build a plan.</div></td></tr>';
    if (j.sessions && j.sessions.length) {
      var s = j.sessions[0];
      $("acq-count").textContent += " · last session " + s.status.replace(/_/g, " ");
    }
  }

  api(CFG.acq_sources).then(function (j) {
    state.sources = j.sources || [];
    if (!j.live_enabled) {
      $("acq-count").textContent = "Live acquisition disabled (ARTIFACTIQ_ALLOW_LIVE) — sources shown read-only";
    }
    loadStatus(function () { render(); });
  }).catch(function (er) {
    $("source-list").innerHTML = '<div class="empty">Could not load acquisition sources: ' + esc(er.message) + '</div>';
    updateRun();
  });

  // ---------------------------------------------------------------- actions
  $("acq-selectall").addEventListener("click", function () {
    if (state.running) return;
    state.sources.forEach(function (s) { state.selected[s.id] = true; });
    render();
  });
  $("acq-clear").addEventListener("click", function () {
    if (state.running) return;
    state.selected = {};
    render();
  });
  ["ack-auth", "ack-impact"].forEach(function (id) {
    $(id).addEventListener("change", updateRun);
  });

  $("acq-run").addEventListener("click", function () {
    if (state.running) return;
    state.running = true;
    $("acq-progress").hidden = false;
    $("acq-progress-bar").style.width = "40%";
    $("acq-progress").classList.add("indeterminate");
    updateRun();
    document.querySelectorAll("[data-source]").forEach(function (c) { c.disabled = true; });

    api(CFG.acq_plan, {
      method: "POST",
      data: {
        operator: $("acq-operator").value || "user",
        sources: selectedIds(),
        authorization_ack: $("ack-auth").checked,
        impact_ack: $("ack-impact").checked,
        run: true
      }
    }).then(function (j) {
      state.running = false;
      $("acq-progress").hidden = true;
      $("acq-progress").classList.remove("indeterminate");
      var ok2 = (j.artifacts || []).filter(function (a) { return a.status === "completed"; }).length;
      var bad = (j.artifacts || []).filter(function (a) { return a.status !== "completed" && a.status !== "skipped_with_reason"; }).length;
      var msg = "Session " + j.session_id + ": " + ok2 + " collected" +
        (bad ? ", " + bad + " denied/failed (logged — see table)" : "");      toast(msg, bad ? "warn" : "ok");
      state.selected = {};
      state.statuses = {};
      $("ack-auth").checked = $("ack-impact").checked = false;
      loadStatus(function () { render(); });
    }).catch(function (er) {
      state.running = false;
      $("acq-progress").hidden = true;
      $("acq-progress").classList.remove("indeterminate");
      toast(er.message, "err");
      render();
    });
  });
});
