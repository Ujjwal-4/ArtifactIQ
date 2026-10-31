/* ArtifactIQ v2 front-end helpers (vanilla, offline). */
(function () {
  "use strict";

  var csrf = document.querySelector('meta[name="csrf-token"]')?.content ||
    (document.querySelector('input[name="csrf_token"]') || {}).value || "";
  window.CSRF = csrf;

  function toast(msg, kind) {
    var box = document.getElementById("toasts");
    if (!box) { console.log(kind || "info", msg); return; }
    var t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.textContent = msg;
    box.appendChild(t);
    setTimeout(function () { t.remove(); }, 5200);
  }
  window.toast = toast;

  function api(path, opts) {
    opts = opts || {};
    var headers = { "X-CSRF-Token": window.CSRF };
    var body;
    if (opts.data && !(opts.data instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(opts.data);
    } else if (opts.data) {
      body = opts.data;
    }
    return fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: body,
      credentials: "same-origin",
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error((j && j.error) || ("HTTP " + r.status));
        return j;
      });
    });
  }
  window.api = api;

  // ---- demo load buttons
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-demo-load]");
    if (!b) return;
    e.preventDefault();
    b.disabled = true;
    api("/api/demo/load", { method: "POST", data: { mode: b.dataset.demoLoad } })
      .then(function (j) {
        toast("Demo case created. Opening…");
        window.location.href = "/cases/" + j.case_id;
      })
      .catch(function (er) { toast(er.message, "err"); b.disabled = false; });
  });

  // ---- generic confirm actions
  document.addEventListener("click", function (e) {
    var b = e.target.closest("[data-action]");
    if (!b) return;
    e.preventDefault();
    var action = b.dataset.action,
        url = b.dataset.url,
        method = b.dataset.method || "POST",
        kind = b.dataset.toast || "",
        data;
    if (b.dataset.confirm) {
      if (!window.confirm(b.dataset.confirm)) return;
    }
    if (b.dataset.body) {
      try { data = JSON.parse(b.dataset.body); } catch (er) { data = null; }
    }
    b.disabled = true;
    api(url, { method: method, data: data })
      .then(function (j) {
        if (kind) toast(kind + " ✔");
        if (b.dataset.redirect) {
          // action removes the page underneath (e.g. case deleted): go elsewhere
          setTimeout(function () { window.location.href = b.dataset.redirect; }, 700);
        } else if (b.dataset.refresh !== "none") {
          setTimeout(function () { window.location.reload(); }, 700);
        }
      })
      .catch(function (er) { toast(er.message, "err"); b.disabled = false; });
  });

  // ---- drawer for event/evidence details
  function showDrawer(title, contentHTML) {
    var ov = document.getElementById("overlay");
    var dw = document.getElementById("drawer");
    if (!dw) return;
    dw.querySelector(".drawer-title").textContent = title || "Details";
    dw.querySelector(".drawer-body").innerHTML = contentHTML;
    ov.classList.add("show");
    dw.classList.add("show");
  }
  window.showDrawer = showDrawer;
  window.closeDrawer = function () {
    var ov = document.getElementById("overlay");
    if (ov) ov.classList.remove("show");
    if (dw) dw.classList.remove("show");
  };
  document.addEventListener("DOMContentLoaded", function () {
    var dw = document.createElement("aside");
    dw.className = "drawer"; dw.id = "drawer";
    dw.innerHTML = '<h2 class="drawer-title">Details</h2><div class="drawer-body"></div>' +
      '<div class="btn-row" style="margin-top:14px"><button class="btn" onclick="closeDrawer()">Close</button></div>';
    var ov = document.createElement("div");
    ov.className = "overlay"; ov.id = "overlay";
    ov.onclick = closeDrawer;
    document.body.appendChild(ov);
    document.body.appendChild(dw);
  });

  function kvTRows(obj) {
    return '<dl class="kv">' +
      Object.entries(obj).filter(function (x) { return x[1] !== null && x[1] !== ""; })
        .map(function (x) {
          return "<dt>" + esc(x[0]) + "</dt><dd>" + esc(String(x[1])) + "</dd>";
        }).join("") + "</dl>";
  }
  window.kvTRows = kvTRows;

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  window.esc = esc;

  // Stored activity timestamps are UTC ("...", "...Z"). Convert to the
  // viewer's local time for display; fall back to the raw string.
  function fmtLocal(s) {
    if (s === null || s === undefined || s === "") return "";
    var iso = String(s).replace(" ", "T");
    if (!/(Z|[+-]\d\d:?\d\d)$/.test(iso)) iso += "Z";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(s);
    var pad = function (n) { return (n < 10 ? "0" : "") + n; };
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
      " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  window.fmtLocal = fmtLocal;

  // Server-rendered timestamps: elements with class "ts-local" hold UTC text
  // and are rewritten in place to local time once the DOM is ready.
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".ts-local").forEach(function (el) {
      var v = fmtLocal(el.textContent.trim());
      if (v) el.textContent = v;
    });
  });

  // ---- event detail openers
  document.addEventListener("click", function (e) {
    var a = e.target.closest("[data-event-id]");
    if (a) {
      e.preventDefault();
      showDrawer("Normalized event", '<div class="skeleton" style="height:200px"></div>');
      api("/api/events/" + a.dataset.eventId).then(function (j) {
        var ev = j.event;
        var html = kvTRows({
          "UTC time": ev.ts_utc || "(absent in artifact)",
          "Original ts": ev.ts_original || "",
          "Precision": ev.ts_precision,
          "Timestamp source": ev.ts_source,
          "Type": ev.event_type,
          "Code": ev.event_code,
          "Record id": ev.record_id,
          "Channel": ev.channel, "Provider": ev.provider,
          "Host": ev.hostname, "User": ev.username, "SID": ev.user_sid,
          "Process": ev.process_name, "PID": ev.process_id, "PPID": ev.parent_process_id,
          "Cmd": ev.command_line, "Src IP": ev.source_ip, "Dst IP": ev.destination_ip,
          "Source path": ev.source_path, "Dest path": ev.destination_path,
          "Raw ref": ev.raw_ref, "Parser": ev.parser + " " + (ev.parser_version || ""),
          "Status": ev.parse_status,
        });
        if (ev.evidence) {
          html += '<h3 style="margin-top:16px">Source evidence</h3>' + kvTRows({
            "Original name": ev.evidence.original_name,
            "SHA-256": ev.evidence.sha256,
            "Status": ev.evidence.verify_status,
            "Method": ev.evidence.acquisition_method,
          });
        }
        if (j.event.parser_run) {
          html += '<div class="attach-note">Parser run ' + esc(j.event.parser_run.id) +
            " status: " + esc(j.event.parser_run.status) + "</div>";
        }
        dw.querySelector(".drawer-body").innerHTML = html;
      }).catch(function (er) { showDrawer("Error", esc(er.message)); });
    }
  });
})();
