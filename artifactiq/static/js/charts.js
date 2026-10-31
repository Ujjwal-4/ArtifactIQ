/* SVG helpers: bar chart, donut, and interactive event graph (no CDN). */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  window.svgEl = function (tag, attrs) {
    const e = document.createElementNS(NS, tag);
    for (const k in (attrs || {})) e.setAttribute(k, attrs[k]);
    return e;
  };

  // Vertical bar chart. data: [{label, value, color}]
  window.renderBars = function (container, data, opts) {
    opts = opts || {};
    const W = opts.width || 560, H = opts.height || 190, P = { l: 34, b: 40, t: 14, r: 8 };
    const max = Math.max(1, ...data.map(d => d.value));
    const innerW = W - P.l - P.r, innerH = H - P.t - P.b;
    const bw = innerW / Math.max(1, data.length);
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img" });
    for (let i = 0; i <= 4; i++) {
      const yv = max * i / 4, y = P.t + innerH - yv / max * innerH;
      svg.appendChild(svgEl("line", { x1: P.l, y1: y, x2: W - P.r, y2: y, stroke: "#1c2836" }));
      svg.appendChild(svgEl("text", { x: P.l - 6, y: y + 3, "text-anchor": "end", "font-size": 9 })).textContent = 
        (yv >= 1000 ? (yv / 1000).toFixed(1) + "k" : Math.round(yv));
    }
    data.forEach((d, i) => {
      const h = d.value / max * innerH;
      const x = P.l + i * bw + bw * 0.18, y = P.t + innerH - h;
      const rect = svgEl("rect", {
        x, y, width: bw * 0.64, height: Math.max(1, h), rx: 3,
        fill: d.color || "#34b39a", opacity: 0.92,
      });
      if (opts.onBarClick && d.id) rect.classList.add("svg-link");
      svg.appendChild(rect);
      if (d.onclick) rect.style.cursor = "pointer";
      if (d.onclick) rect.addEventListener("click", d.onclick);
      // label
      const lbl = d.label.length > 12 ? d.label.slice(0, 11) + "…" : d.label;
      svg.appendChild(svgEl("text", {
        x: x + bw * 0.32, y: H - P.b + 14, "text-anchor": "middle",
        "font-size": 9,
      })).textContent = lbl;
      if (d.value > 0 && bw > 20) {
        svg.appendChild(svgEl("text", {
          x: x + bw * 0.32, y: y - 4, "text-anchor": "middle", "font-size": 9,
        })).textContent = d.value;
      }
    });
    container.innerHTML = "";
    container.appendChild(svg);
  };

  window.renderDonut = function (container, data, opts) {
    opts = opts || {};
    const size = opts.size || 170, r = size / 2 - 12, cx = size / 2, cy = size / 2;
    const total = data.reduce((s, d) => s + d.value, 0) || 1;
    const svg = svgEl("svg", { viewBox: `0 0 ${size} ${size}`, width: size });
    let a0 = -Math.PI / 2;
    const colors = ["#34b39a", "#5b9bd8", "#8f8ad9", "#d9a13c", "#e2606a", "#7edc9a", "#76d0f5"];
    if (total === 0) {
      svg.appendChild(svgEl("circle", { cx, cy, r, fill: "none", stroke: "#1c2836", "stroke-width": 16 }));
    }
    data.forEach((d, i) => {
      const frac = d.value / total;
      const a1 = a0 + frac * Math.PI * 2;
      const large = frac > 0.5 ? 1 : 0;
      const x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      if (frac > 0.001) {
        svg.appendChild(svgEl("path", {
          d: `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`,
          stroke: d.color || colors[i % colors.length], "stroke-width": 16,
          fill: "none", opacity: 0.94,
        }));
      }
      a0 = a1;
    });
    svg.appendChild(svgEl("text", {
      x: cx, y: cy - 2, "text-anchor": "middle", "font-size": 22, fill: "#dbe4ee",
    })).textContent = String(opts.centerValue != null ? opts.centerValue : total);
    svg.appendChild(svgEl("text", {
      x: cx, y: cy + 16, "text-anchor": "middle", "font-size": 9,
    })).textContent = opts.centerLabel || "events";
    container.innerHTML = "";
    container.appendChild(svg);
    return total;
  };

  // ---- interactive graph: radial layout, drag, click-detail
  window.renderGraph = function (container, graph, opts) {
    opts = opts || {};
    const W = opts.width || container.clientWidth || 900;
    const H = opts.height || 520;
    const nodes = graph.nodes, rels = graph.relationships;
    const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", height: H });
    const colorMap = {
      user: "#5b9bd8", host: "#34b39a", process: "#8f8ad9", file: "#7edc9a",
      network: "#76d0f5", usb: "#d9a13c", service: "#e2606a", task: "#e0a1c0",
    };
    const pos = {};
    // radial grouping by type around center
    const types = [...new Set(nodes.map(n => n.type))];
    const N = nodes.length;
    const cx = W / 2, cy = H / 2;
    nodes.forEach((n, i) => {
      const ring = types.length > 1 ? 0 : 0;
      const tIdx = types.indexOf(n.type);
      const a = (i / Math.max(1, N)) * Math.PI * 2 + tIdx * 0.55;
      const rad = Math.min(W, H) * 0.32 * (1 + 0.22 * (tIdx % 2)) + (i % 5) * 18;
      pos[n.id] = { x: cx + rad * Math.cos(a), y: cy + rad * Math.sin(a), n };
    });
    const tooltip = document.createElement("div");
    tooltip.className = "tooltip-box";
    document.body.appendChild(tooltip);

    // edges
    rels.forEach(r => {
      const s = pos[r.source], t = pos[r.target];
      if (!s || !t) return;
      const line = svgEl("line", {
        x1: s.x, y1: s.y, x2: t.x, y2: t.y,
        stroke: r.count > 2 ? "#2d5c85" : "#243244",
        "stroke-width": Math.min(3.2, 0.7 + Math.log2(r.count + 1) * 0.55),
        opacity: 0.75,
      });
      line.dataset.kind = r.kind;
      line.addEventListener("mouseenter", (e) => {
        tooltip.style.display = "block";
        tooltip.innerHTML = `<b>${esc(r.kind)}</b> ×${r.count}<br>` +
          `<span class="faint">evidence: ${esc(r.evidence_ids.join(", ").slice(0, 120))}</span>`;
        tooltip.style.left = e.clientX + 12 + "px";
        tooltip.style.top = e.clientY + 12 + "px";
      });
      line.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
      svg.appendChild(line);
    });
    // nodes
    nodes.forEach(en => {
      const p = pos[en.id];
      if (!p) return;
      const g = svgEl("g", { class: "svg-link" });
      const color = colorMap[en.type] || "#8fa2b8";
      const rad = en.type === "host" ? 17 : 12;
      g.appendChild(svgEl("circle", { cx: p.x, cy: p.y, r: rad, fill: "#10161e", stroke: color, "stroke-width": 2 }));
      const label = svgEl("text", {
        x: p.x, y: p.y + rad + 12, "text-anchor": "middle", "font-size": 9.5,
      });
      const name = en.name.length > 22 ? en.name.slice(0, 21) + "…" : en.name;
      label.textContent = name;
      g.appendChild(label);
      g.appendChild(svgEl("circle", { cx: p.x, cy: p.y, r: 4.5, fill: color }));
      g.addEventListener("click", () => {
        if (opts.onNodePick) opts.onNodePick(en);
        else if (opts.focusBaseHref) window.location.href = opts.focusBaseHref + encodeURIComponent(en.type + "::" + en.name);
      });
      // drag
      let dragging = false, moved = false;
      g.addEventListener("mousedown", () => { dragging = true; moved = false; });
      svg.addEventListener("mousemove", (e) => {
        if (!dragging) return;
        moved = true;
        const pt = svgEl("svg", {}).createSVGPoint ? null : null;
        const rect = svg.getBoundingClientRect();
        p.x = (e.clientX - rect.left) / rect.width * W;
        p.y = (e.clientY - rect.top) / rect.height * H;
        window.requestAnimationFrame(() => {
          g.querySelectorAll("circle")[0].setAttribute("cx", p.x);
          g.querySelectorAll("circle")[0].setAttribute("cy", p.y);
          label.setAttribute("x", p.x);
          label.setAttribute("y", p.y + rad + 12);
        });
      });
      window.addEventListener("mouseup", () => { dragging = false; });
      g.addEventListener("mouseenter", (e) => {
        tooltip.style.display = "block";
        tooltip.innerHTML = `<b>${esc(en.type)}</b> ${esc(en.name)}<br>` +
          `<span class="faint">^{attrs}</span>`.replace("^{" + "^attrs", "");
        tooltip.style.left = e.clientX + 12 + "px";
        tooltip.style.top = e.clientY + 12 + "px";
      });
      g.addEventListener("mouseleave", () => { tooltip.style.display = "none"; });
      svg.appendChild(g);
    });
    container.innerHTML = "";
    container.appendChild(svg);
    return { tooltip };
  };

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  window.esc2 = esc;
})();
