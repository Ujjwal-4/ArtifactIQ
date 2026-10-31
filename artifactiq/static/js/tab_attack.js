/* Tab script 'attack' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-attack").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    document.getElementById("at-version").textContent = "pinned rules: mentioned per mapping";
    api(CFG.attack_view).then(function (j) {
      document.getElementById("at-version").textContent = j.version;
      document.querySelector("#at-findings tbody").innerHTML = j.findings.length
        ? j.findings.map(function (f) {
            return '<tr><td><span class="badge severity-' + f.severity + '">' + "S" + f.severity + '</span></td>' +
              '<td class="wrap"><b>' + esc(f.title) + '</b><div class="tiny muted">' + esc(f.description) + '</div></td>' +
              '<td class="mono tiny">' + esc(f.rule_id || "") + '</td>' +
              '<td class="mono tiny">' + esc(JSON.parse(f.evidence_ids).join(" ")) + '</td></tr>';
          }).join("")
        : '<tr><td colspan="4"><div class="empty" style="border:none">No evidence-backed findings. This can mean the rules did not fire — absence of findings is not safety.</div></td></tr>';
      document.querySelector("#at-maps tbody").innerHTML = j.mappings.length
        ? j.mappings.map(function (m) {
            return '<tr><td class="mono"><b>' + esc(m.technique_id) + '</b> ' + esc(m.technique_name) + '</td>' +
              '<td><span class="chip">' + esc(m.tactic) + '</span></td>' +
              '<td class="wrap tiny muted">' + esc(m.rationale) + '</td>' +
              '<td><span class="badge ' + m.confidence + '">' + esc(m.confidence) + '</span><div class="tiny faint mono">' + esc(m.rule_version) + '</div></td>' +
              '<td class="mono tiny">' + esc(JSON.parse(m.evidence_ids).join(" ")) + '</td></tr>';
          }).join("")
        : '<tr><td colspan="5"><div class="empty" style="border:none">No mappings supported by the evidence in this case.</div></td></tr>';
    }).catch(function (er) { toast(er.message, "err"); });
  })();
});
