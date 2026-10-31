/* Page script 'case_new' — externalized for CSP (script-src 'self').
   URLs come from the JSON config block in the page. */
var CFG = JSON.parse(document.getElementById("cfg-page-case-new").textContent);

(function () {
  var modeSel = document.getElementById("nc-mode"), capSel = document.getElementById("nc-cap");
  modeSel.addEventListener("change", function () { capSel.disabled = modeSel.value !== "targeted"; });
  document.getElementById("new-case-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var btn = e.target.querySelector("button[type=submit]");
    btn.disabled = true;
    var payload = {
      case_number: document.getElementById("nc-case-number").value.trim(),
      title: document.getElementById("nc-title").value,
      investigator: document.getElementById("nc-investigator").value,
      description: document.getElementById("nc-desc").value,
      scope: document.getElementById("nc-scope").value,
      authorization: document.getElementById("nc-auth").value,
      mode: modeSel.value,
      capability: modeSel.value === "targeted" ? capSel.value : null,
    };
    api(CFG.create_case, { method: "POST", data: payload })
      .then(function (j) { window.location.href = "/cases/" + j.case_id; })
      .catch(function (er) { toast(er.message, "err"); btn.disabled = false; });
  });
  document.getElementById("nc-title").focus();
})();
