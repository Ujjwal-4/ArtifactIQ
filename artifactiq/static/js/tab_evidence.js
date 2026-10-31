/* Tab script 'evidence' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-evidence").textContent);
document.addEventListener("DOMContentLoaded", function () {

  // ------------------------------------------------ read-only evidence preview
  (function () {
    var modal = document.getElementById("ev-modal");
    if (!modal) return;
    var title = document.getElementById("ev-modal-title");
    var meta = document.getElementById("ev-modal-meta");
    var body = document.getElementById("ev-modal-body");
    var extBox = document.getElementById("ev-modal-extracted");

    function fmtSize(n) {
      if (n < 1024) return n + " B";
      if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
      if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
      return (n / 1073741824).toFixed(2) + " GB";
    }
    function esc(s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }
    function close() { modal.hidden = true; }
    modal.addEventListener("click", function (e) { if (e.target === modal) close(); });
    document.getElementById("ev-modal-close").addEventListener("click", close);
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });

    document.addEventListener("click", function (e) {
      var b = e.target.closest("[data-preview-id]");
      if (!b) return;
      e.preventDefault();
      var eid = b.dataset.previewId;
      title.textContent = "Preview — " + (b.dataset.evName || eid);
      meta.textContent = "opening…";
      body.textContent = "";
      extBox.textContent = "";
      modal.hidden = false;
      var url = CFG.preview.replace("__EVID__", encodeURIComponent(eid));
      fetch(url, { headers: { "Accept": "application/json" } })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (!j.ok) { meta.textContent = j.error || "Preview failed"; return; }
          var d = j.preview || {};
          var bits = [];
          bits.push(esc(d.media_type || "unknown") + " · " + fmtSize(d.size || 0));
          if (d.truncated) bits.push("first " + (d.snippet || "").length + " chars shown");
          if (d.hash_check && d.hash_check.status.indexOf("skipped") === -1) {
            if (d.hash_check.match) {
              bits.push("SHA-256 of preserved copy re-verified \u2713");
            } else {
              bits.push("SHA-256 MISMATCH on preserved copy \u2014 do not trust parse output");
            }
          }
          meta.innerHTML = bits.map(esc).join(" · ") + " " +
            '<span class="badge neutral">read-only</span>';
          body.textContent = d.snippet || "(no content available)";
          var ext = d.extracted || {};
          var lines = [];
          if (ext.total_events) {
            lines.push("<b>What the parsers extracted from THIS file:</b> " +
              ext.total_events + " event(s) — these feed the Timeline, Graph, Branches and Scenario Simulator.");
            (ext.by_event_type || []).forEach(function (r) {
              lines.push("• " + esc(r.event_type) + " × " + r.n);
            });
          } else {
            lines.push("Not parsed yet — run <b>Parse</b> on the row above; the extracted " +
              "events will appear here and on the Timeline.");
          }
          if (d.note) lines.push("<i>" + esc(d.note) + "</i>");
          extBox.innerHTML = lines.join("<br>");
        })
        .catch(function (er) { meta.textContent = "Preview failed: " + er.message; });
    });
  })();

  (function () {
    var form = document.getElementById("upload-form");
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var fd = new FormData(form);
      fd.append("csrf_token", window.CSRF);
      var submit = document.getElementById("up-submit"), bar = document.getElementById("up-progress");
      submit.disabled = true;
      var xhr = new XMLHttpRequest();
      xhr.open("POST", CFG.upload_evidence);
      xhr.setRequestHeader("X-CSRF-Token", window.CSRF);
      xhr.upload.addEventListener("progress", function (pe) {
        if (pe.lengthComputable) bar.style.width = Math.round(pe.loaded / pe.total * 100) + "%";
      });
      xhr.onload = function () {
        submit.disabled = false;
        try { var j = JSON.parse(xhr.responseText); }
        catch (err) { toast("Upload failed (HTTP " + xhr.status + ")", "err"); return; }
        if (xhr.status >= 200 && xhr.status < 300 && j.ok) {
          toast("Evidence registered with SHA-256 " + j.evidence.sha256.slice(0, 12) + "…");
          setTimeout(function () { window.location.reload(); }, 600);
        } else {
          toast(j.error || "Registration failed", "err");
        }
      };
      xhr.onerror = function () { submit.disabled = false; toast("Upload failed", "err"); };
      xhr.send(fd);
    });
  })();

  // ------------------------------------------------ disk image analysis (p06)
  (function () {
    var panel = document.getElementById("image-analysis-panel");
    var btn = document.getElementById("image-analyze-btn");
    var statusLbl = document.getElementById("image-analysis-status");
    var engineNote = document.getElementById("image-engine-note");
    var runBody = document.getElementById("image-run-body");
    var filesHead = document.getElementById("image-files-head");
    var fileBody = document.getElementById("image-file-body");
    if (!panel) return;

    function fmtSize(n) {
      if (n === null || n === undefined) return "—";
      if (n < 1024) return n + " B";
      if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
      if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
      return (n / 1073741824).toFixed(2) + " GB";
    }
    function badge(cls, text) {
      var s = document.createElement("span");
      s.className = "badge " + cls;
      s.textContent = text;
      return s;
    }
    function statusBadge(status) {
      if (status === "completed") return badge("ok", status);
      if (status === "completed_with_warnings") return badge("warn", status);
      if (status === "failed") return badge("err", status);
      if (status === "running") return badge("info", "running…");
      return badge("neutral", status);
    }
    function td(txt, cls) {
      var c = document.createElement("td");
      if (cls) c.className = cls;
      c.textContent = (txt === null || txt === undefined) ? "—" : String(txt);
      return c;
    }

    function render(j) {
      var eng = j.engine || {};
      if (!j.images || !j.images.length) { panel.hidden = true; return; }
      panel.hidden = false;
      if (eng.installed) {
        engineNote.textContent = "Engine available: " + eng.version +
          " · " + j.images.length + " disk image(s) registered in this case.";
        btn.disabled = false;
      } else {
        engineNote.textContent = "Disk-image engine (pytsk3 / The Sleuth Kit) is NOT installed " +
          "in this environment — the phase stays blocked. Install it into the project venv: " +
          ".venv\\Scripts\\python -m pip install pytsk3";
        btn.disabled = true;
      }
      runBody.textContent = "";
      (j.images || []).forEach(function (im) {
        var tr = document.createElement("tr");
        tr.appendChild(td(im.original_name));
        tr.appendChild(td(im.media_type));
        var run = null;
        (j.runs || []).forEach(function (r) {
          if (r.evidence_id === im.id && (!run || r.started_at > run.started_at)) run = r;
        });
        var c1 = document.createElement("td");
        c1.appendChild(run ? statusBadge(run.status) : badge("neutral", "not analyzed"));
        tr.appendChild(c1);
        if (run) {
          var num1 = td(run.files, "num"); tr.appendChild(num1);
          tr.appendChild(td(run.dirs, "num"));
          tr.appendChild(td(run.deleted, "num"));
          var dc = document.createElement("td");
          dc.className = "tiny";
          var parts = run.partitions || [];
          var txt = parts.map(function (p) {
            return (p.desc || "partition") + (p.fs_type ? " · " + p.fs_type : "") +
              (p.status ? " (" + p.status + ")" : "");
          }).join(" · ") || run.message || "";
          if (txt.length > 160) txt = txt.slice(0, 160) + "…";
          dc.textContent = txt;
          dc.title = run.message || "";
          tr.appendChild(dc);
        } else {
          tr.appendChild(td("0", "num")); tr.appendChild(td("0", "num"));
          tr.appendChild(td("0", "num"));
          tr.appendChild(td("run analysis to enumerate the filesystem", "tiny"));
        }
        runBody.appendChild(tr);
      });
      // latest run file listing
      fileBody.textContent = "";
      if (j.files && j.files.length) {
        filesHead.hidden = false;
        j.files.forEach(function (f) {
          var tr = document.createElement("tr");
          tr.appendChild(td(f.path));
          var c = document.createElement("td");
          c.appendChild(badge(f.is_dir ? "info" : "neutral", f.is_dir ? "dir" : (f.deleted ? "file (deleted)" : "file")));
          tr.appendChild(c);
          tr.appendChild(td(fmtSize(f.size), "num"));
          tr.appendChild(td(f.mtime || "", "tiny"));
          fileBody.appendChild(tr);
        });
      } else {
        filesHead.hidden = true;
      }
    }

    function refresh() {
      fetch(CFG.image_status, { headers: { "Accept": "application/json" } })
        .then(function (r) { return r.json(); })
        .then(function (j) { if (j.ok) render(j); })
        .catch(function () { /* tab still works without the panel */ });
    }
    btn.addEventListener("click", function () {
      btn.disabled = true;
      statusLbl.textContent = "Opening image with the Sleuth Kit engine…";
      fetch(CFG.image_analyze, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": window.CSRF || "" },
        body: JSON.stringify({})
      }).then(function (r) { return r.json(); }).then(function (j) {
        if (j.ok) {
          var fail = (j.runs || []).filter(function (r) { return r.status === "failed"; }).length;
          toast(fail ? fail + " image run(s) failed — see details in the table" :
                (j.runs.length + " disk image(s) analyzed, phase 6 recorded"), fail ? "warn" : "ok");
        } else {
          toast(j.error || "Analysis failed", "err");
        }
        refresh();
        statusLbl.textContent = "";
        btn.disabled = false;
      }).catch(function () {
        toast("Analysis request failed", "err");
        statusLbl.textContent = "";
        btn.disabled = false;
      });
    });
    refresh();
  })();
});
