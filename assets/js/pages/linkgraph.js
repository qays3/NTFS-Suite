import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { mountOwnership } from "/js/pages/ownership.js";

const NS = "http://www.w3.org/2000/svg";
const CARD_W = 200;
const CARD_H = 74;

const view = { k: 1, tx: 0, ty: 0 };
let model = { cards: [], links: [], evidenceId: null };
let graphGen = 0;

const TABS = [
  ["map", "NTFS map"],
  ["owner", "Ownership"],
];

export async function render(root) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const content = caseShell(root, "graph");
  const parsed = state.evidence.find((e) => e.status === "parsed");
  if (!parsed) {
    content.innerHTML = `<section class="panel"><h3>Graph</h3><p class="muted">No parsed evidence yet.</p><div class="row-end"><button type="button" class="btn" id="an-add">${icon("plus")} Add evidence</button></div></section>`;
    content.querySelector("#an-add").addEventListener("click", () => go("/logs"));
    return;
  }
  const evidenceId = parsed.id;
  let active = "map";
  try {
    active = sessionStorage.getItem("graph_tab") || "map";
  } catch (e) {
    void e;
  }
  if (!TABS.some(([k]) => k === active)) {
    active = "map";
  }
  content.innerHTML = `
<div class="seg graph-tabs" id="graph-tabs">${TABS.map(([k, label]) => `<button type="button" class="seg-btn${k === active ? " on" : ""}" data-gtab="${k}">${esc(label)}</button>`).join("")}</div>
<div id="graph-pane"></div>`;
  const pane = content.querySelector("#graph-pane");
  const tabs = content.querySelector("#graph-tabs");
  const mount = (key) => {
    const my = ++graphGen;
    const alive = () => my === graphGen && pane.isConnected;
    for (const b of tabs.querySelectorAll(".seg-btn")) {
      b.classList.toggle("on", b.getAttribute("data-gtab") === key);
    }
    try {
      sessionStorage.setItem("graph_tab", key);
    } catch (e) {
      void e;
    }
    pane.innerHTML = `<div class="skeleton" style="height:220px"></div>`;
    if (key === "owner") {
      mountOwnership(pane, evidenceId, alive);
    } else {
      mountMap(pane, evidenceId, alive);
    }
  };
  tabs.addEventListener("click", (e) => {
    const b = e.target.closest(".seg-btn");
    if (b) {
      mount(b.getAttribute("data-gtab"));
    }
  });
  mount(active);
}

async function mountMap(pane, evidenceId, alive) {
  if (!pane || (alive && !alive())) {
    return;
  }
  model = { cards: [], links: [], evidenceId };
  view.k = 1;
  view.tx = 0;
  view.ty = 0;
  pane.innerHTML = `
<div class="anatomy">
<div class="an-canvas">
<svg id="an-svg" viewBox="0 0 1320 840" preserveAspectRatio="xMidYMid meet"><g id="an-view"></g></svg>
<div class="an-controls">
<button type="button" class="icon-btn" id="an-in" title="Zoom in">+</button>
<button type="button" class="icon-btn" id="an-out" title="Zoom out">-</button>
<button type="button" class="icon-btn" id="an-reset" title="Reset view">${icon("grid")}</button>
</div>
<div class="an-legend">
<span class="an-leg"><span class="an-dot present"></span>present</span>
<span class="an-leg"><span class="an-dot deleted"></span>deleted</span>
<span class="an-leg"><span class="an-dot missing"></span>not in this image</span>
</div>
</div>
<div class="an-detail" id="an-detail"><p class="muted">The NTFS metadata files of this volume. Click a file to read its role and what was parsed.</p></div>
</div>`;

  wireControls(pane);
  try {
    const data = await api.graphAnatomy(evidenceId);
    if (alive && !alive()) {
      return;
    }
    buildModel(data);
    draw(pane);
  } catch (e) {
    if (alive && !alive()) {
      return;
    }
    const detail = pane.querySelector("#an-detail");
    if (detail) {
      detail.innerHTML = '<p class="hint">Could not load. Restart the server if it was just updated.</p>';
    }
  }
}

const PLUGIN_FOR_NODE = { "$MFT": "mft", "$UsnJrnl": "usnjrnl", "$Secure": "secure" };

function loadedPlugins() {
  const set = new Set();
  try {
    for (const e of state.evidence || []) {
      set.add(e.plugin);
    }
  } catch (e) {
    void e;
  }
  return set;
}

const ATTR_NODES = [
  ["$STANDARD_INFORMATION", "the four $SI MACB timestamps, flags, owner and security id"],
  ["$ATTRIBUTE_LIST", "only when a record's attributes overflow into other records"],
  ["$FILE_NAME", "the name, parent reference and the four $FN timestamps"],
  ["$DATA", "the file contents, resident in the record or in cluster runs on disk"],
  ["Directory index", "a folder's entries, held in $INDEX_ROOT, $INDEX_ALLOCATION and $BITMAP"],
];

function buildModel(data) {
  const cards = [];
  const byId = new Map();
  const loaded = loadedPlugins();
  const links = [];
  const add = (card) => {
    cards.push(card);
    byId.set(card.id, card);
    return card;
  };
  const concept = (id, name, x, y, role, sub, primary) =>
    add({ id, name, x, y, role, sub: sub || "structure", present: true, concept: true, entry: -1, primary: !!primary, loaded: false });
  const live = (m, x, y, primary) => {
    const plugin = PLUGIN_FOR_NODE[m.name];
    return add({ ...m, id: m.name, x, y, primary: !!primary, loaded: plugin ? loaded.has(plugin) : false });
  };

  const total = data.metafiles.find((m) => m.entry === 0);

  // Root and its three children: boot sector, the MFT, and the data clusters.
  concept("NTFS", "NTFS volume", 600, 10, "The NTFS volume. Everything below belongs to it: the boot sector, the Master File Table that catalogues every file, and the data clusters that hold the contents.", "volume", true);
  concept("Boot sector", "Boot sector", 120, 120, "The first sectors of the volume, $Boot (record 7). Holds the BIOS parameter block, cluster size and the location of the $MFT.", "$Boot, record 7");
  const mftMeta = data.metafiles.find((m) => m.entry === 0);
  if (mftMeta) {
    live(mftMeta, 600, 120, true);
  } else {
    concept("$MFT", "$MFT", 600, 120, "The Master File Table.", "record 0", true);
  }
  concept("Data clusters", "Data clusters", 1120, 120, "The clusters on disk that hold the actual file contents. A non-resident $DATA attribute points here with cluster runs.", "on disk");
  links.push({ from: "NTFS", to: "Boot sector" });
  links.push({ from: "NTFS", to: "$MFT" });
  links.push({ from: "NTFS", to: "Data clusters" });

  // Two groups under the MFT.
  concept("System files", "System metadata files", 250, 235, "The volume's own metadata files, records 0 to 11. They describe the file system itself.", "records 0 to 11");
  concept("User files", "User files and folders", 980, 235, "Ordinary files and folders, records 24 and up. Each is one $MFT record made of attributes.", "records 24+");
  links.push({ from: "$MFT", to: "System files" });
  links.push({ from: "$MFT", to: "User files" });

  // The live system metafiles (records 1 to 11), in a grid under System files.
  const sysCols = [30, 250, 470];
  const systemList = data.metafiles
    .filter((m) => m.entry !== 0)
    .sort((a, b) => a.entry - b.entry);
  systemList.forEach((m, i) => {
    const x = sysCols[i % 3];
    const y = 345 + Math.floor(i / 3) * 95;
    live(m, x, y);
    links.push({ from: "System files", to: m.name });
  });
  // $Extend's children hang below the grid.
  const extendRow = 345 + Math.ceil(systemList.length / 3) * 95;
  const extCols = [30, 250, 470, 690];
  data.extend.forEach((m, i) => {
    live(m, extCols[i % 4], extendRow + Math.floor(i / 4) * 95);
    links.push({ from: "$Extend", to: m.name, soft: true });
  });

  // A generic user record and its attributes, under User files.
  concept("MFT Record", "An MFT record", 980, 345, "One file or folder. A 1024-byte record that is a header followed by a set of attributes.", "1024 bytes");
  links.push({ from: "User files", to: "MFT Record" });
  ATTR_NODES.forEach(([name, role], i) => {
    concept(name, name, 900 + (i % 2) * 220, 455 + Math.floor(i / 2) * 95, role, "attribute");
    links.push({ from: "MFT Record", to: name, soft: true });
  });
  concept("Resident", "Resident $DATA", 900, 740, "A small file whose contents sit inside the record itself.", "in the record");
  concept("Non-resident", "Non-resident $DATA", 1120, 740, "A larger file whose contents live in cluster runs out on disk.", "cluster runs");
  links.push({ from: "$DATA", to: "Resident", soft: true });
  links.push({ from: "$DATA", to: "Non-resident", soft: true });
  links.push({ from: "Non-resident", to: "Data clusters", soft: true });

  model.cards = cards;
  model.byId = byId;
  model.links = links;
  void total;
}

function center(card) {
  return { x: card.x + CARD_W / 2, y: card.y + CARD_H / 2 };
}

function colors() {
  const s = getComputedStyle(document.documentElement);
  const v = (n) => s.getPropertyValue(n).trim();
  return {
    accent: v("--amber"),
    bad: v("--bad"),
    mut: v("--mut-2"),
    line: v("--border-strong"),
    text: v("--text-strong"),
    sub: v("--mut"),
    panel: v("--bg2"),
    border: v("--border"),
    ok: v("--ok"),
  };
}

function statusColor(card, c) {
  if (card.concept) {
    return c.sub;
  }
  if (!card.present) {
    return c.mut;
  }
  if (card.deleted) {
    return c.bad;
  }
  return c.accent;
}

function el(tag, attrs) {
  const node = document.createElementNS(NS, tag);
  for (const k in attrs) {
    node.setAttribute(k, attrs[k]);
  }
  return node;
}

function draw(content) {
  const g = content.querySelector("#an-view");
  const svg = content.querySelector("#an-svg");
  g.setAttribute("transform", "translate(" + view.tx + " " + view.ty + ") scale(" + view.k + ")");
  const c = colors();
  g.innerHTML = "";
  for (const link of model.links) {
    const a = model.byId.get(link.from);
    const b = model.byId.get(link.to);
    if (!a || !b) {
      continue;
    }
    const from = center(a);
    const to = center(b);
    const my = (from.y + to.y) / 2;
    g.appendChild(el("path", {
      d: "M" + from.x + " " + from.y + " C" + from.x + " " + my + " " + to.x + " " + my + " " + to.x + " " + to.y,
      fill: "none",
      stroke: c.line,
      "stroke-width": 1,
      "stroke-dasharray": link.soft ? "4 3" : "none",
    }));
  }
  for (const card of model.cards) {
    const node = el("g", { class: "an-card", transform: "translate(" + card.x + " " + card.y + ")", style: "cursor:grab" });
    const accent = statusColor(card, c);
    node.appendChild(el("rect", {
      x: 0,
      y: 0,
      width: CARD_W,
      height: CARD_H,
      rx: 5,
      fill: c.panel,
      stroke: card.name === model.selected ? accent : c.border,
      "stroke-width": card.primary || card.name === model.selected ? 2 : 1,
    }));
    node.appendChild(el("rect", { x: 0, y: 0, width: 4, height: CARD_H, rx: 2, fill: card.loaded ? c.ok : accent }));
    const name = el("text", { x: 16, y: 24, fill: c.text, "font-size": 13, "font-family": "monospace" });
    name.textContent = card.name;
    node.appendChild(name);
    if (card.loaded) {
      node.appendChild(el("circle", { cx: CARD_W - 14, cy: 14, r: 4, fill: c.ok }));
      const tag = el("text", { x: CARD_W - 24, y: 17, fill: c.ok, "font-size": 8, "font-family": "monospace", "text-anchor": "end" });
      tag.textContent = "loaded";
      node.appendChild(tag);
    }
    const badge = el("text", { x: 16, y: 40, fill: c.sub, "font-size": 9, "font-family": "monospace" });
    if (card.concept) {
      badge.textContent = card.sub || "structure";
    } else {
      const num = card.entry >= 0 ? "record " + card.entry.toLocaleString() : "optional";
      badge.textContent = card.present ? num + " · " + countLabel(card) : num;
    }
    node.appendChild(badge);
    const role = el("text", { x: 16, y: 58, fill: c.sub, "font-size": 9 });
    role.textContent = clip(card.role, 30);
    node.appendChild(role);
    attachCardDrag(content, node, card, svg);
    g.appendChild(node);
  }
}

function attachCardDrag(content, node, card, svg) {
  node.addEventListener("mousedown", (ev) => {
    ev.stopPropagation();
    ev.preventDefault();
    const start = svgPoint(svg, ev.clientX, ev.clientY);
    const origin = { x: card.x, y: card.y };
    let moved = false;
    const move = (e) => {
      const now = svgPoint(svg, e.clientX, e.clientY);
      const dx = (now.x - start.x) / view.k;
      const dy = (now.y - start.y) / view.k;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
        moved = true;
      }
      card.x = origin.x + dx;
      card.y = origin.y + dy;
      draw(content);
    };
    const up = () => {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      if (!moved) {
        select(content, card);
      }
    };
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  });
}

function wireControls(content) {
  const svg = content.querySelector("#an-svg");
  content.querySelector("#an-in").addEventListener("click", () => zoom(content, 1.2));
  content.querySelector("#an-out").addEventListener("click", () => zoom(content, 1 / 1.2));
  content.querySelector("#an-reset").addEventListener("click", () => {
    view.k = 1;
    view.tx = 0;
    view.ty = 0;
    draw(content);
  });
  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.1 : 1 / 1.1;
    const pt = svgPoint(svg, e.clientX, e.clientY);
    const nk = clampK(view.k * factor);
    const real = nk / view.k;
    view.tx = pt.x - real * (pt.x - view.tx);
    view.ty = pt.y - real * (pt.y - view.ty);
    view.k = nk;
    draw(content);
  }, { passive: false });
  let panning = null;
  svg.addEventListener("mousedown", (e) => {
    if (e.target.closest(".an-card")) {
      return;
    }
    panning = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty };
    svg.style.cursor = "grabbing";
  });
  window.addEventListener("mouseup", () => {
    svg.style.cursor = "";
  });
  window.addEventListener("mousemove", (e) => {
    if (!panning) {
      return;
    }
    const rect = svg.getBoundingClientRect();
    const scale = 1320 / rect.width;
    view.tx = panning.tx + (e.clientX - panning.x) * scale;
    view.ty = panning.ty + (e.clientY - panning.y) * scale;
    draw(content);
  });
  window.addEventListener("mouseup", () => {
    panning = null;
  });
}

function zoom(content, factor) {
  const nk = clampK(view.k * factor);
  const cx = 660;
  const cy = 420;
  const real = nk / view.k;
  view.tx = cx - real * (cx - view.tx);
  view.ty = cy - real * (cy - view.ty);
  view.k = nk;
  draw(content);
}

function clampK(k) {
  return Math.max(0.4, Math.min(3, k));
}

function svgPoint(svg, clientX, clientY) {
  const rect = svg.getBoundingClientRect();
  return {
    x: ((clientX - rect.left) / rect.width) * 1320,
    y: ((clientY - rect.top) / rect.height) * 840,
  };
}

function select(content, card) {
  model.selected = card.name;
  const pane = content.querySelector("#an-detail");
  const status = card.concept ? "present" : !card.present ? "missing" : card.deleted ? "deleted" : "present";
  const statusText = card.concept ? "Structure" : !card.present ? "Not in this image" : card.deleted ? "Deleted" : "Present";
  const chips = [];
  if (card.concept) {
    chips.push(card.sub || "structure");
  } else {
    chips.push(card.entry >= 0 ? "MFT record " + card.entry.toLocaleString() : "optional feature");
    if (card.present) {
      chips.push(card.is_directory ? "directory" : "file");
      chips.push(countLabel(card));
    }
    if (card.present && card.si_created) {
      chips.push("created " + card.si_created);
    }
  }
  if (card.loaded) {
    chips.push("data loaded");
  }
  let html = `
<div class="an-d">
<div class="an-d-top"><span class="an-d-name">${esc(card.name)}</span><span class="an-status ${status}">${esc(statusText)}</span></div>
<div class="an-d-chips">${chips.map((x) => `<span class="an-chip">${esc(x)}</span>`).join("")}</div>
<div class="an-d-head">Purpose</div>
<p class="an-d-text">${esc(card.role)}</p>`;
  if (card.present && !card.concept) {
    html += `<div class="detail-controls"><button type="button" class="btn ghost small" id="an-explore">${icon("grid")} Show in Explore</button></div>`;
  }
  html += "</div>";
  pane.innerHTML = html;
  const btn = pane.querySelector("#an-explore");
  if (btn) {
    btn.addEventListener("click", () => {
      try {
        sessionStorage.setItem("focus_explore_search", card.name);
      } catch (e) {
        void e;
      }
      go("/explore");
    });
  }
  draw(content);
}

function countLabel(card) {
  if (card.entry === 0) {
    return card.records.toLocaleString() + " records in table";
  }
  if (card.is_directory) {
    return card.records.toLocaleString() + " entries inside";
  }
  return "1 record";
}

function clip(value, max) {
  const text = value === null || value === undefined ? "" : String(value);
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}
