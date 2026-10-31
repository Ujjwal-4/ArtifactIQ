/* Tab script 'timeline' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-timeline").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    var state = { page: 1, per_page: 50 };
    var el = function (id) { return document.getElementById(id); };

    function qs() {
      var p = new URLSearchParams();
      p.set("page", state.page); p.set("per_page", state.per_page);
      if (el("tl-q").value) p.set("q", el("tl-q").value);
      if (el("tl-type").value) p.set("event_type", el("tl-type").value);
      if (el("tl-user").value) p.set("user", el("tl-user").value);
      if (el("tl-host").value) p.set("host", el("tl-host").value);
      if (el("tl-from").value) p.set("from", el("tl-from").value);
      if (el("tl-to").value) p.set("to", el("tl-to").value);
      return p.toString();
    }

    function load() {
      el("tl-body").innerHTML = '<tr><td colspan="4"><div class="skeleton" style="height:120px"></div></td></tr>';
      api(CFG.timeline + "?" + qs()).then(function (j) {
        el("tl-total").textContent = j.total + " events · " + j.unknown_ts_count +
          " w/o UTC" + (j.no_ts_in_source_count ? " (" + j.no_ts_in_source_count + " not in source)" : "");
        el("tl-page").textContent = "page " + j.page + " / " + Math.max(1, Math.ceil(j.total / j.per_page));
        // facets
        j.facets.event_types.forEach(function (f) {
          var o = document.createElement("option");
          o.value = f.event_type; o.textContent = f.event_type + " (" + f.n + ")";
          el("tl-type").appendChild(o);
        });
        el("tl-users").innerHTML = j.facets.users.map(function (u) {
          return '<span class="chip">' + esc(u.username) + ' ×' + u.n + '</span>';
        }).join("") || '<span class="faint tiny">none recorded</span>';
        if (!j.items.length) {
          el("tl-body").innerHTML = '<tr><td colspan="4"><div class="empty" style="border:none">No events match. ' +
            (j.total === 0 ? 'Parse evidence to build the timeline.' : 'Adjust filters.') + '</div></td></tr>';
        } else {
          el("tl-body").innerHTML = j.items.map(renderRow).join("");
        }
        window.renderDonut(el("tl-donut"),
          j.facets.categories.slice(0, 6).map(function (f) { return { label: f.category, value: f.n }; }),
          { centerLabel: "events", centerValue: j.total });
      }).catch(function (er) {
        el("tl-body").innerHTML = '<tr><td colspan="4"><div class="empty">' + esc(er.message) + '</div></td></tr>';
      });
    }

    function renderRow(e) {
      var main = e.command_line || e.process_name || e.source_path || e.destination_path ||
        e.username || e.provider || "";
      var tsCell;
      if (e.ts_utc) {
        tsCell = e.ts_utc.replace("T", " ").slice(0, 19);
      } else if (e.ts_source === "no_timestamp") {
        tsCell = '<span class="faint" title="The source artifact format does not carry timestamps; ' +
          'none was invented">(no timestamp in source)</span>';
      } else {
        tsCell = '<span class="faint" title="A timestamp existed in the source but could not be parsed">' +
          '(unparsed timestamp)</span>';
      }
      return '<tr>' +
        '<td class="mono tiny num">' + tsCell + '</td>' +
        '<td><span class="chip" style="padding:2px 8px">' + esc(e.event_type) + '</span>' +
          (e.event_code ? '<div class="tiny faint">id ' + esc(e.event_code) + '</div>' : '') + '</td>' +
        '<td class="wrap tiny"><a href="#" data-event-id="' + e.id + '">' + esc(String(main).slice(0, 130)) + '</a>' +
          '<div class="faint">' + [e.hostname, e.username, e.channel].filter(Boolean).map(esc).join(" · ") + '</div></td>' +
        '<td class="tiny faint">' + esc(e.parser) + '<br><span class="badge ' + e.parse_status + '" style="font-size:.62rem">' + esc(e.parse_status) + '</span></td>' +
        '</tr>';
    }

    el("tl-apply").addEventListener("click", function () { state.page = 1; load(); });
    ["tl-q"].forEach(function (id) {
      el(id).addEventListener("keydown", function (e) { if (e.key === "Enter") { state.page = 1; load(); } });
    });
    el("tl-prev").addEventListener("click", function () { if (state.page > 1) { state.page--; load(); } });
    el("tl-next").addEventListener("click", function () { state.page++; load(); });
    var exp = el("tl-export");
    exp.addEventListener("click", function (ev) {
      var base = exp.href.split("?")[0];
      exp.href = base + "?" + qs();
    });
    api(CFG.timeline_clusters).then(function (j) {
      el("tl-clusters").innerHTML = (j.clusters || []).slice(0, 8).map(function (c) {
        return '<div style="margin-bottom:6px"><b class="mono tiny">' + c.start.slice(0, 16).replace("T", " ") +
          '</b> <span class="chip">' + c.count + '</span><div class="faint tiny">' + esc(c.types.join(", ").slice(0, 90)) + '</div></div>';
      }).join("") || '<span class="tiny faint">no timestamped events to cluster</span>';
    });
    load();
  })();
});
