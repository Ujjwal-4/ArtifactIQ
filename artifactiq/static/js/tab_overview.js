/* Tab script 'overview' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-overview").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    api(CFG.phase_status).then(function (j) {
      var list = document.getElementById("phase-list");
      list.outerHTML = '<dl class="kv" style="column-gap:34px">' + Object.values(j.phases).map(function (p) {
        return '<dt>' + esc(p.title) + '</dt><dd><span class="badge ' + esc(p.status) + '">' +
          esc(p.status.replace(/_/g, " ")) + '</span></dd>';
      }).join("") + '</dl>';
      var all = Object.values(j.phases);
      var done = all.filter(function (p) { return p.status.indexOf("completed") === 0; }).length;
      var ready = all.filter(function (p) { return p.status === "ready"; }).length;
      var blocked = all.filter(function (p) { return p.status === "blocked"; }).length;
      var later = all.length - done - ready - blocked;
      var bits = ["done = completed (± warnings)"];
      if (ready) bits.push(ready + " awaiting optional input");
      if (blocked) bits.push(blocked + " blocked (not implemented capability)");
      if (later) bits.push(later + " not started yet");
      document.getElementById("ov-events").textContent = done + "/" + all.length;
      document.getElementById("ov-phases-note").textContent = bits.join(" · ");
    }).catch(function (er) {
      document.getElementById("phase-list").innerHTML = '<div class="empty">' + esc(er.message) + '</div>';
    });
    api(CFG.get_evidence).then(function (j) {
      var bad = j.evidence.filter(function (e) { return e.verify_status === "mismatch"; }).length;
      document.getElementById("ov-hash-status").textContent = bad ? bad + " hash mismatch(es)!" : "hashes consistent";
    });
    api(CFG.attack_view).then(function (j) {
      document.getElementById("ov-findings").textContent = j.findings.length + "/" + j.mappings.length;
      document.getElementById("ov-findings-note").textContent = "findings / ATT&CK mappings";
    }).catch(function () {});
  })();
});
