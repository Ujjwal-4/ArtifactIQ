/* Tab script 'graph' — externalized for CSP (script-src 'self').
   URLs come from the non-executable JSON config below. */
var CFG = JSON.parse(document.getElementById("cfg-graph").textContent);
document.addEventListener("DOMContentLoaded", function () {

  (function () {
    var container = document.getElementById("g-graph");
    var latest = null;
    function ensureTooltip() {
      var t = document.querySelector(".tooltip-box");
      if (!t) { t = document.createElement("div"); t.className = "tooltip-box"; document.body.appendChild(t); }
      return t;
    }
    function draw(graph) {
      latest = graph;
      document.getElementById("g-empty").style.display = graph.nodes.length ? "none" : "";
      var t = ensureTooltip();
      window.renderGraph(container, graph, { width: 980, height: 520 });
      document.getElementById("g-stats").textContent =
        graph.nodes.length + " nodes · " + graph.relationships.length + " relationships" +
        (graph.note ? " · " + graph.note : "");
      // re-attach core tooltip handlers in charts.js already; focus behavior:
    }
    function loadGraph() {
      var p = new URLSearchParams();
      if (document.getElementById("g-focus").value) {
        p.set("focus", document.getElementById("g-focus").value);
        p.set("hops", document.getElementById("g-hops").value);
      }
      api(CFG.graph_view + "?" + p.toString()).then(function (j) {
        draw(j.graph);
      }).catch(function (er) { toast(er.message, "err"); });
    }
    document.getElementById("g-load").addEventListener("click", function () {
      api(CFG.analyze, { method: "POST", data: {} })
        .then(function (j) {
          toast("Graph rebuilt: " + j.graph.nodes.length + " nodes, " + j.attack.mappings.length + " mappings");
          loadGraph();
        })
        .catch(function (er) { toast(er.message, "err"); });
    });
    document.getElementById("g-redraw").addEventListener("click", loadGraph);
    document.addEventListener("DOMContentLoaded", loadGraph);
  })();
});
