/* Page script 'acquisition' — externalized for CSP (script-src 'self').
   URLs come from the JSON config block in the page. */
var CFG = JSON.parse(document.getElementById("cfg-page-acquisition").textContent);

(function () {
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  api(CFG.acq_sources).then(function (j) {
    var sources = j.sources || [];
    var cnt = document.getElementById("src-count");
    cnt.hidden = false;
    cnt.innerHTML = '<span class="tiny faint">' + sources.length +
      ' sources available — ' + (j.live_enabled
        ? "live acquisition is enabled; nothing is collected by default"
        : "live acquisition is disabled (ARTIFACTIQ_ALLOW_LIVE)") + '</span>' +
      '<span class="spacer"></span><span class="chip">per-case selection &mdash; read-only copies</span>';
    document.getElementById("src-cards").innerHTML = sources.map(function (s) {
      return '<div class="acq-card">' +
        '<div class="acq-head"><span class="acq-id"><span class="acq-icon">&#9633;</span>' +
        esc(s.id) + '</span>' +
        (s.requires_windows ? '<span class="badge neutral">Windows</span>'
                            : '<span class="badge info">any OS</span>') + '</div>' +
        '<div class="acq-label">' + esc(s.label) + '</div>' +
        '<div class="acq-impact tiny">' + esc(s.impact) + '</div>' +
        '</div>';
    }).join("");
  }).catch(function (er) {
    document.getElementById("src-cards").innerHTML =
      '<div class="empty">Could not load acquisition sources: ' + esc(er.message) + '</div>';
  });
})();
