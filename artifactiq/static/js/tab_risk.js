/* Tab script 'risk' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-risk").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
    function render(r) {
      var el_ = document.getElementById("risk-body");
      if (!r) {
        el_.innerHTML = '<div class="empty"><span class="icon">📉</span>No risk assessment yet. Recompute after analysis.</div>';
        return;
      }
      var inputs = r.inputs || {};
      var rows = Object.keys(inputs).map(function (k) {
        var v = inputs[k];
        return '<tr><td class="mono tiny">' + esc(k) + '</td><td><span class="badge info">' + esc(String(v.value)) + '</span></td>' +
          '<td class="tiny muted wrap">' +
          (typeof v.evidence === "object" ? esc(JSON.stringify(v.evidence).slice(0, 240)) : esc(String(v.evidence))) + '</td>' +
          '<td class="tiny faint wrap">' + esc(v.note || "") + '</td></tr>';
      }).join("");
      el_.innerHTML =
        '<div class="grid g3">' +
        '<div class="panel stat"><div class="num">' + r.score + '</div><div class="lbl">Risk score</div></div>' +
        '<div class="panel stat"><div><span class="badge ' + r.band + '" style="padding:6px 16px; font-size:.9rem">' + esc(r.band) + '</span></div>' +
        '<div class="lbl" style="margin-top:8px">Band</div></div>' +
        '<div class="panel stat"><div class="num tiny" style="font-weight:400; font-family:var(--mono)">' + esc(r.version) + '</div><div class="lbl">Policy version</div></div>' +
        '</div>' +
        '<div class="log-box" style="margin-top:12px">' + esc(r.formula) + '</div>' +
        '<div class="table-wrap" style="margin-top:14px"><table><thead><tr><th>Input</th><th>Value</th><th>Evidence used</th><th>Note</th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div>';
    }
    api(CFG.risk_view).then(function (j) {
      render(j.risk ? Object.assign({}, j.risk, { computed_at: "" }) : null);
      if (j.risk) {
        // keep score/band/version/formula/inputs
      }
    }).catch(function (er) {
      document.getElementById("risk-body").innerHTML = '<div class="empty">' + esc(er.message) + '</div>';
    });
  })();
});
