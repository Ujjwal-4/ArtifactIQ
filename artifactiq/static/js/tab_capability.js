/* Tab script 'capability' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-capability").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
    function refresh() {
      api(CFG.parser_runs).then(function (j) {
        document.getElementById("cap-runs").innerHTML = (j.runs || []).map(function (r) {
          return '<tr><td>' + esc(r.parser) + '<div class="tiny faint">' + esc((r.detail_json && r.detail_json.reason) || "") + '</div></td>' +
            '<td><span class="badge ' + esc(r.status) + '">' + esc(r.status.replace(/_/g, " ")) + '</span></td>' +
            '<td class="num">' + r.events_added + '</td>' +
            '<td class="tiny muted wrap">' + esc(r.message) + '</td></tr>';
        }).join("") || '<tr><td colspan="4"><div class="empty" style="border:none">Not executed yet.</div></td></tr>';
        api(CFG.timeline + "?per_page=20").then(function (tj) {
          document.getElementById("cap-events").innerHTML = tj.items.map(function (e) {
            return '<div class="tl-item"><div class="tl-time">' + esc(e.ts_utc ? fmtLocal(e.ts_utc) + " <span class='faint tiny'>(local)</span>" : "(no trustworthy timestamp)") + '</div>' +
              '<div class="tiny">' + esc(e.event_type) + ' — ' + esc(String(e.process_name || e.source_path || e.destination_path || "").slice(0, 100)) + '</div></div>';
          }).join("") || '<span class="tiny faint">No events parsed yet.</span>';
        });
      });
    }

    // Upload an artifact for this capability, then run it automatically.
    var form = document.getElementById("cap-upload-form");
    if (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var file = document.getElementById("cap-file").files[0];
        if (!file) { toast("Choose an artifact file first.", "err"); return; }
        var fd = new FormData();
        fd.append("file", file, file.name);
        var notes = document.getElementById("cap-notes").value || "";
        if (notes) fd.append("notes", notes);
        if (CFG.media_type) fd.append("media_type", CFG.media_type);
        var btn = document.getElementById("cap-up-submit");
        btn.disabled = true;
        var xhr = new XMLHttpRequest();
        xhr.open("POST", CFG.upload);
        xhr.setRequestHeader("X-CSRF-Token", window.CSRF);
        xhr.onload = function () {
          btn.disabled = false;
          var j;
          try { j = JSON.parse(xhr.responseText); } catch (er) { toast("Upload failed (HTTP " + xhr.status + ")", "err"); return; }
          if (xhr.status >= 200 && xhr.status < 300 && j.ok) {
            toast("Artifact registered (sha256 " + j.evidence.sha256.slice(0, 12) + "…) — running capability");
            api(CFG.parse, { method: "POST", data: {} }).then(function () {
              setTimeout(function () { window.location.reload(); }, 700);
            }).catch(function (er) { toast(er.message, "err"); });
          } else {
            toast(j.error || "Registration failed", "err");
          }
        };
        xhr.onerror = function () { btn.disabled = false; toast("Upload failed", "err"); };
        xhr.send(fd);
      });
    }

    refresh();
    document.addEventListener("click", function (ev) {
      if (ev.target.closest("[data-action='parse-evidence']")) setTimeout(refresh, 900);
    });
  })();
});
