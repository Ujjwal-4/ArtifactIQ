/* Tab script 'custody' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-custody").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
    document.getElementById("custody-verify").addEventListener("click", function () {
      api(CFG.custody_chain).then(function (j) {
        var v = j.verification;
        document.getElementById("custody-status").textContent =
          v.ok ? "chain OK · head " + v.head_hash.slice(0, 14) + "…" : "BROKEN: " + v.issue;
        document.getElementById("custody-status").className = "badge " + (v.ok ? "ok" : "err");
        document.getElementById("custody-body").innerHTML = j.records.map(function (r) {
          return '<tr><td class="num tiny">' + r.seq + '</td>' +
            '<td class="mono tiny">' + esc(fmtLocal(r.ts)) + '</td>' +
            '<td class="tiny">' + esc(r.actor) + '</td>' +
            '<td><span class="chip">' + esc(r.action) + '</span></td>' +
            '<td class="mono tiny">' + esc(r.evidence_id || "—") + '</td>' +
            '<td class="tiny muted wrap">' + esc(r.reason) + '</td>' +
            '<td class="hash tiny">' + r.record_hash.slice(0, 14) + '…</td></tr>';
        }).join("") || '<tr><td colspan="7"><div class="empty" style="border:none">No custody records yet.</div></td></tr>';
      }).catch(function (er) { toast(er.message, "err"); });
    });
  })();
});
