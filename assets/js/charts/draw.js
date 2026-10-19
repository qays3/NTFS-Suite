const NS = "http://www.w3.org/2000/svg";

export function palette() {
  const s = getComputedStyle(document.documentElement);
  const v = (name) => s.getPropertyValue(name).trim();
  return {
    accent: v("--amber"),
    bad: v("--bad"),
    warn: v("--warn"),
    ok: v("--ok"),
    grid: v("--border"),
    axis: v("--mut-2"),
    text: v("--mut"),
    strong: v("--text-strong"),
    panel: v("--bg2"),
  };
}

function el(tag, attrs) {
  const node = document.createElementNS(NS, tag);
  for (const key in attrs) {
    node.setAttribute(key, attrs[key]);
  }
  return node;
}

function svg(width, height) {
  const node = el("svg", {
    viewBox: "0 0 " + width + " " + height,
    class: "chart-svg",
    preserveAspectRatio: "xMidYMid meet",
  });
  return node;
}

function linear(d0, d1, r0, r1) {
  const span = d1 - d0 || 1;
  return (value) => r0 + ((value - d0) / span) * (r1 - r0);
}

function text(node, x, y, value, color, anchor, size) {
  const t = el("text", { x, y, fill: color, "text-anchor": anchor || "start", "font-size": size || 10 });
  t.textContent = value;
  node.appendChild(t);
}

export function barChart(container, items, options) {
  const opts = options || {};
  const p = palette();
  const w = 520;
  const h = 240;
  const padL = 44;
  const padR = 12;
  const padT = 12;
  const padB = 56;
  const node = svg(w, h);
  const max = Math.max(1, ...items.map((d) => d.value));
  const y = linear(0, max, h - padB, padT);
  const bandW = (w - padL - padR) / Math.max(1, items.length);
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const gy = padT + ((h - padB - padT) / gridLines) * i;
    node.appendChild(el("line", { x1: padL, y1: gy, x2: w - padR, y2: gy, stroke: p.grid, "stroke-width": 1 }));
    text(node, padL - 6, gy + 3, Math.round(max - (max / gridLines) * i).toLocaleString(), p.axis, "end", 9);
  }
  items.forEach((d, i) => {
    const bx = padL + bandW * i + bandW * 0.15;
    const bw = bandW * 0.7;
    const by = y(d.value);
    const color = d.color || p.accent;
    const rect = el("rect", { x: bx, y: by, width: bw, height: h - padB - by, fill: color, rx: 2 });
    const title = el("title", {});
    title.textContent = d.label + ": " + d.value.toLocaleString();
    rect.appendChild(title);
    if (opts.onClick) {
      rect.style.cursor = "pointer";
      rect.addEventListener("click", () => opts.onClick(d));
    }
    node.appendChild(rect);
    const label = el("text", {
      x: bx + bw / 2,
      y: h - padB + 12,
      fill: p.axis,
      "text-anchor": "end",
      "font-size": 9,
      transform: "rotate(-40 " + (bx + bw / 2) + " " + (h - padB + 12) + ")",
    });
    label.textContent = d.label;
    node.appendChild(label);
  });
  container.innerHTML = "";
  container.appendChild(node);
}

export function scatter(container, points, options) {
  const opts = options || {};
  const p = palette();
  const w = 520;
  const h = 300;
  const padL = 54;
  const padR = 14;
  const padT = 14;
  const padB = 40;
  const node = svg(w, h);
  const xs = points.map((d) => d.x);
  const ys = points.map((d) => d.y);
  const xMin = Math.min(...xs);
  const xMax = Math.max(...xs);
  const yMin = Math.min(...ys);
  const yMax = Math.max(...ys);
  const x = linear(xMin, xMax, padL, w - padR);
  const y = linear(yMin, yMax, h - padB, padT);
  node.appendChild(el("line", { x1: padL, y1: h - padB, x2: w - padR, y2: h - padB, stroke: p.grid }));
  node.appendChild(el("line", { x1: padL, y1: padT, x2: padL, y2: h - padB, stroke: p.grid }));
  if (opts.diagonal) {
    node.appendChild(el("line", { x1: x(xMin), y1: y(xMin), x2: x(xMax), y2: y(xMax), stroke: p.axis, "stroke-dasharray": "4 4" }));
  }
  for (const d of points) {
    const dot = el("circle", { cx: x(d.x), cy: y(d.y), r: d.flag ? 2.6 : 1.6, fill: d.flag ? p.bad : p.accent, "fill-opacity": d.flag ? 0.9 : 0.4 });
    node.appendChild(dot);
  }
  text(node, padL, h - padB + 14, opts.xLabel || "", p.axis, "start", 9);
  const yl = el("text", { x: 14, y: padT + 4, fill: p.axis, "font-size": 9, transform: "rotate(-90 14 " + (padT + 4) + ")" });
  yl.textContent = opts.yLabel || "";
  node.appendChild(yl);
  container.innerHTML = "";
  container.appendChild(node);
}

export function lineChart(container, points, options) {
  const opts = options || {};
  const p = palette();
  const w = 760;
  const h = 220;
  const padL = 46;
  const padR = 14;
  const padT = 14;
  const padB = 34;
  const node = svg(w, h);
  if (points.length === 0) {
    container.innerHTML = "";
    container.appendChild(node);
    return;
  }
  const xs = points.map((d) => d.x);
  const xMin = Math.min(...xs);
  const xMax = Math.max(...xs);
  const yMax = Math.max(1, ...points.map((d) => d.y));
  const x = linear(xMin, xMax, padL, w - padR);
  const y = linear(0, yMax, h - padB, padT);
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const gy = padT + ((h - padB - padT) / gridLines) * i;
    node.appendChild(el("line", { x1: padL, y1: gy, x2: w - padR, y2: gy, stroke: p.grid }));
    text(node, padL - 6, gy + 3, Math.round(yMax - (yMax / gridLines) * i).toLocaleString(), p.axis, "end", 9);
  }
  let path = "";
  points.forEach((d, i) => {
    path += (i === 0 ? "M" : "L") + x(d.x) + " " + y(d.y);
  });
  node.appendChild(el("path", { d: path, fill: "none", stroke: p.accent, "stroke-width": 1.6 }));
  if (opts.onBrush) {
    const overlay = el("rect", { x: padL, y: padT, width: w - padR - padL, height: h - padB - padT, fill: "transparent", style: "cursor:crosshair" });
    const sel = el("rect", { x: 0, y: padT, width: 0, height: h - padB - padT, fill: p.accent, "fill-opacity": 0.14, stroke: p.accent, "stroke-width": 1, visibility: "hidden" });
    node.appendChild(sel);
    node.appendChild(overlay);
    let start = null;
    const toValue = (clientX, rect) => {
      const ratio = (clientX - rect.left) / rect.width;
      const px = padL + ratio * (w - padR - padL);
      const clamped = Math.min(Math.max(px, padL), w - padR);
      return { px: clamped, value: xMin + ((clamped - padL) / (w - padR - padL)) * (xMax - xMin) };
    };
    overlay.addEventListener("mousedown", (e) => {
      const rect = node.getBoundingClientRect();
      const svgRect = { left: rect.left + (padL / w) * 0, width: rect.width };
      start = toValue(e.clientX, rect);
      sel.setAttribute("visibility", "visible");
      void svgRect;
    });
    node.addEventListener("mousemove", (e) => {
      if (!start) {
        return;
      }
      const rect = node.getBoundingClientRect();
      const now = toValue(e.clientX, rect);
      const left = Math.min(start.px, now.px);
      const width = Math.abs(now.px - start.px);
      const ratioLeft = ((left - rect.left) / rect.width);
      void ratioLeft;
      sel.setAttribute("x", left);
      sel.setAttribute("width", width);
    });
    const finish = (e) => {
      if (!start) {
        return;
      }
      const rect = node.getBoundingClientRect();
      const now = toValue(e.clientX, rect);
      const lo = Math.min(start.value, now.value);
      const hi = Math.max(start.value, now.value);
      start = null;
      sel.setAttribute("visibility", "hidden");
      if (hi - lo > 1000) {
        opts.onBrush(lo, hi);
      }
    };
    node.addEventListener("mouseup", finish);
  }
  container.innerHTML = "";
  container.appendChild(node);
}

export function heatmap(container, cells, options) {
  const opts = options || {};
  const p = palette();
  const rows = 7;
  const cols = 24;
  const cell = 20;
  const padL = 34;
  const padT = 16;
  const w = padL + cols * cell + 12;
  const h = padT + rows * cell + 20;
  const node = svg(w, h);
  const grid = {};
  let max = 1;
  for (const c of cells) {
    grid[c.dow + "-" + c.hour] = c.count;
    if (c.count > max) {
      max = c.count;
    }
  }
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  for (let r = 0; r < rows; r++) {
    text(node, padL - 6, padT + r * cell + cell * 0.65, days[r], p.axis, "end", 9);
    for (let c = 0; c < cols; c++) {
      const count = grid[r + "-" + c] || 0;
      const ratio = count === 0 ? 0 : 0.15 + 0.85 * (count / max);
      const rect = el("rect", {
        x: padL + c * cell,
        y: padT + r * cell,
        width: cell - 2,
        height: cell - 2,
        rx: 2,
        fill: count === 0 ? p.panel : p.accent,
        "fill-opacity": count === 0 ? 1 : ratio,
      });
      const title = el("title", {});
      title.textContent = days[r] + " " + c + ":00 - " + count.toLocaleString();
      rect.appendChild(title);
      node.appendChild(rect);
    }
  }
  for (let c = 0; c < cols; c += 3) {
    text(node, padL + c * cell + 2, h - 6, String(c), p.axis, "start", 8);
  }
  void opts;
  container.innerHTML = "";
  container.appendChild(node);
}
