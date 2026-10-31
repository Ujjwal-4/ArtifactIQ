/* Tab script 'assistant' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-assistant").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
    document.getElementById("as-refresh").addEventListener("click", function () {
      refresh();
    });
    function refresh() {
      api(CFG.explanation).then(function (j) {
        var e = j.explanation;
        document.getElementById("as-body").innerHTML =
          '<div class="log-box">' + e.sentences.map(function (s) { return "◈ " + esc(s); }).join("\n") + '</div>' +
          '<div class="attach-note" style="margin-top:10px">' + esc(e.disclaimer) +
          ' <span class="mono tiny">' + esc(e.version) + '</span></div>' +
          (j.llm_active ? '<span class="badge ok">remote AI: enabled</span>' : '<span class="badge blocked" id="llm-badge">remote AI: disabled by config</span>');
      }).catch(function (er) {
        document.getElementById("as-body").innerHTML = '<div class="empty">' + esc(er.message) + '</div>';
      });
    }
    document.getElementById("as-llm").addEventListener("click", function () {
      api(CFG.explanation_llm, { method: "POST", data: {} })
        .then(function (j) {
          if (j.llm_used) {
            showDrawer("Remote AI clarification (advisory)", '<div class="log-box">' + esc(j.response) + '</div>' +
              '<div class="attach-note">Grounded in: ' + esc(j.grounded_in.map(function (c) { return c.sentence; }).join(" ").slice(0, 400)) + '</div>');
          } else {
            toast(j.note || "Remote AI disabled.", "warn");
          }
        })
        .catch(function (er) { toast(er.message, "warn"); });
    });
    refresh();
  })();
});
