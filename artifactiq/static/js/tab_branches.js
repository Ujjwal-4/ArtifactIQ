/* Tab script 'branches' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-branches").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    function severityClass(p) {
      return p >= 80 ? "p-crit" : p >= 60 ? "p-high" : "";
    }
    function render(j) {
      document.getElementById("br-version").textContent = j.version;
      var el_ = document.getElementById("br-list");
      if (!j.branches.length) {
        el_.innerHTML = '<div class="empty"><span class="icon">🌿</span>No branches yet. Generate after parsing evidence.</div>';
        return;
      }
      el_.innerHTML = j.branches.map(function (b) {
        return '<div class="branch-card" data-branch="' + b.id + '">' +
          '<div class="btn-row" style="justify-content:space-between; align-items:flex-start">' +
          '<div><div class="q">Q: ' + esc(b.question) + '</div>' +
          '<div class="why">' + esc(b.why) + '</div></div>' +
          '<div style="text-align:right"><div class="prio ' + severityClass(b.priority) + '">' + b.priority + '</div>' +
          '<span class="badge neutral">' + esc(b.rule_id) + '</span>' +
          '<div class="tiny faint">priority by formula</div></div></div>' +
          '<div class="tiny muted">Supporting evidence: <span class="mono">' + esc(b.evidence_ids.join(", ")) + '</span></div>' +
          (b.missing_evidence.length ? '<div class="tiny" style="color:#ecc169">Missing evidence: ' + esc(b.missing_evidence.join("; ")) + '</div>' : '') +
          '<div class="tiny faint" style="margin:7px 0 4px">Steps: <ol style="margin:4px 0 0 18px; padding:0">' +
          b.steps.map(function (s) { return '<li style="margin-bottom:2px">' + esc(s) + '</li>'; }).join("") + '</ol></div>' +
          '<div class="tiny faint">calc: <span class="mono">' + esc(JSON.stringify(b.priority_calc)) + '</span></div>' +
          '<div class="btn-row" style="margin-top:9px" data-branch-row="' + b.id + '">' +
          '<span class="badge ' + (b.status === "open" ? "info" : b.status === "confirmed" ? "ok" : b.status === "rejected" ? "err" : "blocked") + '" data-status-badge>' + esc(b.status) + '</span>' +
          '<button class="btn btn-sm" data-decide="confirmed">Mark confirmed</button>' +
          '<button class="btn btn-sm" data-decide="rejected">Rejected</button>' +
          '<button class="btn btn-sm" data-decide="inconclusive">Inconclusive</button>' +
          '<button class="btn btn-sm" data-decide="deferred">Deferred</button>' +
          '</div></div>';
      }).join("");
      el_.querySelectorAll("[data-decide]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var id = btn.closest(".branch-card").dataset.branch;
          api(CFG.branch_decide.replace("__ID__", id),
              { method: "POST", data: { status: btn.dataset.decide, note: "" } })
            .then(function () { toast("Branch " + btn.dataset.decide + " ✔"); window.location.reload(); })
            .catch(function (er) { toast(er.message, "err"); });
        });
      });
    }
    api(CFG.branches_view).then(render)
      .catch(function (er) { document.getElementById("br-list").innerHTML = '<div class="empty">' + esc(er.message) + '</div>'; });
  })();
});
