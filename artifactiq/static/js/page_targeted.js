/* Page script 'targeted' — externalized for CSP (script-src 'self').
   URLs come from the JSON config block in the page. */
var CFG = JSON.parse(document.getElementById("cfg-page-targeted").textContent);

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-targeted]");
    if (!btn) return;
    var cap = btn.dataset.targeted;
    var title = "Targeted: " + cap.replace(/_/g, " ");
    var num = "TARGETED-" + cap.toUpperCase().slice(0, 8) + "-" + Date.now().toString(36).toUpperCase();
    api(CFG.create_case, { method: "POST", data: {
      case_number: num, title: title,
      investigator: "targeted-operator",
      description: "Isolated targeted capability run. Import to a full case only if needed.",
      scope: "single capability: " + cap,
      mode: "targeted", capability: cap,
    }}).then(function (j) {
      window.location.href = "/cases/" + j.case_id + "/capability";
    }).catch(function (er) { toast(er.message, "err"); });
  });
