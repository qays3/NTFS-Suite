import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import * as tz from "/js/timezone.js";
import { caseShell } from "/js/pages/case-shell.js";
import { openModal } from "/js/ui/modal.js";

const TYPES = [
  ["B", "Born"],
  ["M", "Modified"],
  ["C", "MFT changed"],
  ["A", "Accessed"],
  ["FN", "File Name born"],
];

let model = {
  evidenceId: null,
  entries: new Set(),
  roots: [],
  events: [],
  laneInfo: [],
  filters: { B: true, M: true, C: true, A: true, FN: true },
  suspiciousOnly: false,
  order: "asc",
  mode: "flagged",
  query: "",
  bodyPath: "",
  bodyLanes: [],
  bodyEvents: [],
  bodyReturned: 0,
  bodyLines: 0,
  bodyTruncated: false,
  bodyLoading: false,
  bodyError: "",
  after: "",
  before: "",
};

export async function render(root) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const parsed = state.evidence.find((e) => e.status === "parsed");
  if (!parsed) {
    const empty = caseShell(root, "time");
    empty.innerHTML = `<section class="panel"><h3>Time analyze</h3><p class="muted">No parsed evidence yet.</p><div class="row-end"><button type="button" class="btn" id="ta-add">${icon("plus")} Add evidence</button></div></section>`;
    empty.querySelector("#ta-add").addEventListener("click", () => go("/logs"));
    return;
  }
  model = {
    evidenceId: parsed.id,
    entries: new Set(),
    roots: [],
    events: [],
    laneInfo: [],
    filters: { B: true, M: true, C: true, A: true, FN: true },
    suspiciousOnly: false,
    order: "asc",
    mode: "flagged",
    query: "",
    bodyPath: "",
    bodyLanes: [],
    bodyEvents: [],
    bodyReturned: 0,
    bodyLines: 0,
    bodyTruncated: false,
    bodyLoading: false,
    bodyError: "",
    after: "",
    before: "",
  };
  model.bodyPath = loadBodyPath();
  const content = caseShell(root, "time");
  content.innerHTML = `
<div class="timean">
<div class="ta-toolbar">
<div class="ta-types" id="ta-types"></div>
<button type="button" class="type-chip" id="ta-susp"><span class="tl-swatch susp"></span>Suspicious</button>
<div class="time-filter" title="Keep events whose time is in this range, in the display time zone">${icon("clock")}<input type="text" id="ta-after" class="tf-date" placeholder="after  YYYY-MM-DD" inputmode="numeric" maxlength="10"><input type="text" id="ta-before" class="tf-date" placeholder="before  YYYY-MM-DD" inputmode="numeric" maxlength="10"><button type="button" class="tf-clear" id="ta-tclear" hidden>clear</button></div>
<button type="button" class="btn ghost small" id="ta-order">Oldest first</button>
<span class="toolbar-spacer"></span>
<span class="count" id="ta-count"></span>
</div>
<div class="ta-grid">
<div class="ta-files">
<div class="ta-files-head">
<div class="seg" id="ta-mode">
<button type="button" class="seg-btn on" data-mode="flagged">Flagged</button>
<button type="button" class="seg-btn" data-mode="all">All files</button>
<button type="button" class="seg-btn" data-mode="bodyfile">Bodyfile</button>
</div>
<span class="find-wrap">${icon("search")}<input id="ta-search" class="find" type="text" placeholder="search name or path"></span>
</div>
<ul class="lg-list" id="ta-list"></ul>
</div>
<div class="ta-feedwrap"><div class="ta-selected" id="ta-selected" hidden></div><div class="skeleton" id="ta-skel" style="height:260px"></div><div class="ta-feed" id="ta-feed" hidden></div></div>
</div>
</div>`;

  renderTypes(content);
  const susp = content.querySelector("#ta-susp");
  susp.addEventListener("click", () => {
    model.suspiciousOnly = !model.suspiciousOnly;
    susp.classList.toggle("on", model.suspiciousOnly);
    renderFeed(content);
  });
  content.querySelector("#ta-order").addEventListener("click", (e) => {
    model.order = model.order === "asc" ? "desc" : "asc";
    e.target.textContent = model.order === "asc" ? "Oldest first" : "Newest first";
    renderFeed(content);
  });
  const taAfter = content.querySelector("#ta-after");
  const taBefore = content.querySelector("#ta-before");
  const taClear = content.querySelector("#ta-tclear");
  let taTimer = null;
  const taRe = /^\d{4}-\d{2}-\d{2}$/;
  const applyRange = () => {
    const a = taAfter.value.trim();
    const b = taBefore.value.trim();
    const okA = a === "" || taRe.test(a);
    const okB = b === "" || taRe.test(b);
    taAfter.classList.toggle("bad", !okA);
    taBefore.classList.toggle("bad", !okB);
    taClear.hidden = !(a || b);
    if (!okA || !okB) {
      return;
    }
    model.after = a;
    model.before = b;
    renderFeed(content);
  };
  const runRange = () => {
    clearTimeout(taTimer);
    taTimer = setTimeout(applyRange, 300);
  };
  taAfter.addEventListener("input", runRange);
  taBefore.addEventListener("input", runRange);
  taClear.addEventListener("click", () => {
    taAfter.value = "";
    taBefore.value = "";
    taAfter.classList.remove("bad");
    taBefore.classList.remove("bad");
    model.after = "";
    model.before = "";
    taClear.hidden = true;
    renderFeed(content);
  });

  const seg = content.querySelector("#ta-mode");
  for (const b of seg.querySelectorAll(".seg-btn")) {
    b.addEventListener("click", () => {
      model.mode = b.getAttribute("data-mode");
      for (const o of seg.querySelectorAll(".seg-btn")) {
        o.classList.toggle("on", o === b);
      }
      const search = content.querySelector("#ta-search");
      if (model.mode === "bodyfile") {
        search.placeholder = "search path in the bodyfile";
        content.querySelector("#ta-selected").hidden = true;
        model.events = model.bodyEvents;
        updateList(content);
        renderFeed(content);
        if (model.bodyPath && model.bodyLanes.length === 0 && !model.bodyLoading) {
          analyzeBody(content);
        }
      } else {
        search.placeholder = "search name or path";
        updateList(content);
        refreshEvents(content);
      }
    });
  }
  let timer = null;
  content.querySelector("#ta-search").addEventListener("input", (e) => {
    model.query = e.target.value.trim();
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (model.mode === "bodyfile") {
        analyzeBody(content);
      } else {
        updateList(content);
      }
    }, 250);
  });

  try {
    model.roots = await api.graphRoots(model.evidenceId);
  } catch (e) {
    model.roots = [];
  }
  for (const entry of takePending()) {
    model.entries.add(entry);
  }
  await updateList(content);
  await refreshEvents(content);
}

function takePending() {
  try {
    const raw = sessionStorage.getItem("focus_time_entries");
    sessionStorage.removeItem("focus_time_entries");
    return raw ? JSON.parse(raw) : [];
  } catch (e) {
    return [];
  }
}

function renderTypes(content) {
  const wrap = content.querySelector("#ta-types");
  wrap.innerHTML = "";
  for (const [key, label] of TYPES) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "type-chip tl-" + key + (model.filters[key] ? " on" : "");
    b.innerHTML = '<span class="tl-swatch tl-' + key + '"></span>' + label;
    b.addEventListener("click", () => {
      model.filters[key] = !model.filters[key];
      b.classList.toggle("on", model.filters[key]);
      renderFeed(content);
    });
    wrap.appendChild(b);
  }
}

async function updateList(content) {
  if (model.mode === "bodyfile") {
    renderBodyImport(content);
    return;
  }
  const list = content.querySelector("#ta-list");
  const q = model.query.toLowerCase();
  let items = [];
  if (model.mode === "flagged") {
    items = (model.roots || [])
      .filter((r) => !q || r.label.toLowerCase().includes(q) || r.sub.toLowerCase().includes(q))
      .map((r) => ({ entry: Number(r.id.split(":")[1]), name: r.label, sub: r.sub }));
    if (items.length === 0) {
      list.innerHTML = q
        ? '<li class="muted">No flagged file matches.</li>'
        : '<li class="muted">No findings yet. Run detection first.</li>';
      return;
    }
  } else {
    if (!model.query) {
      list.innerHTML = '<li class="muted">Type a name or path to search every record in the MFT.</li>';
      return;
    }
    list.innerHTML = '<li class="muted">Searching…</li>';
    let rows = [];
    try {
      const data = await api.records({ evidence_id: model.evidenceId, offset: 0, limit: 60, search: model.query });
      rows = data.rows || [];
    } catch (e) {
      list.innerHTML = '<li class="muted">Search failed.</li>';
      return;
    }
    if (rows.length === 0) {
      list.innerHTML = '<li class="muted">No record matches.</li>';
      return;
    }
    items = rows.map((r) => ({ entry: r.entry, name: r.name || r.path, sub: r.path }));
  }
  renderItems(content, items);
}

function renderItems(content, items) {
  const list = content.querySelector("#ta-list");
  list.innerHTML = "";
  for (const it of items) {
    const li = document.createElement("li");
    const on = model.entries.has(it.entry);
    li.className = "lg-root" + (on ? " on" : "");
    li.innerHTML = `<span class="lg-root-name">${on ? "✓ " : ""}${esc(it.name)}</span><span class="lg-root-sub">${esc(it.sub)}</span>`;
    li.addEventListener("click", async () => {
      if (model.entries.has(it.entry)) {
        model.entries.delete(it.entry);
      } else {
        model.entries.add(it.entry);
      }
      li.classList.toggle("on");
      li.querySelector(".lg-root-name").textContent = (model.entries.has(it.entry) ? "✓ " : "") + it.name;
      await refreshEvents(content);
    });
    list.appendChild(li);
  }
}

async function refreshEvents(content) {
  content.querySelector("#ta-skel").hidden = false;
  content.querySelector("#ta-feed").hidden = true;
  const entries = [...model.entries];
  let lanes = [];
  if (entries.length > 0) {
    try {
      lanes = await api.timelineEvents(model.evidenceId, entries);
    } catch (e) {
      lanes = [];
    }
  }
  model.laneInfo = lanes.map((l) => ({ entry: l.entry, name: l.name, path: l.path }));
  model.events = flatten(lanes);
  renderSelected(content);
  content.querySelector("#ta-skel").hidden = true;
  content.querySelector("#ta-feed").hidden = false;
  renderFeed(content);
}

function renderSelected(content) {
  const bar = content.querySelector("#ta-selected");
  if (!model.laneInfo || model.laneInfo.length === 0) {
    bar.hidden = true;
    bar.innerHTML = "";
    return;
  }
  bar.hidden = false;
  bar.innerHTML =
    '<span class="sel-label">Selected</span>' +
    model.laneInfo
      .map((l) => `<span class="sel-chip">${esc(l.name || l.path)}<button type="button" class="sel-x" data-e="${l.entry}" title="Remove">×</button></span>`)
      .join("") +
    '<button type="button" class="btn ghost small sel-clear" id="ta-clear">Clear all</button>';
  for (const btn of bar.querySelectorAll(".sel-x")) {
    btn.addEventListener("click", async () => {
      model.entries.delete(Number(btn.getAttribute("data-e")));
      await refreshEvents(content);
      updateList(content);
    });
  }
  bar.querySelector("#ta-clear").addEventListener("click", async () => {
    model.entries.clear();
    await refreshEvents(content);
    updateList(content);
  });
}

function flatten(lanes) {
  const out = [];
  const now = Date.now();
  const fmt = (t) => (t ? tz.format(t) : "");
  for (const lane of lanes) {
    const byLabel = {};
    for (const e of lane.events) {
      byLabel[e.label] = e.time;
    }
    const b = byLabel.B;
    const fn = byLabel.FN;
    const stomp = b && fn && b < fn;
    const siTimes = ["B", "M", "C", "A"].map((k) => byLabel[k]).filter(Boolean);
    const allEqual = siTimes.length === 4 && siTimes.every((t) => t === siTimes[0]);
    for (const ev of lane.events) {
      const flags = [];
      if (ev.label === "B") {
        if (stomp) {
          flags.push({ name: "Standard Information created before File Name", value: "SI " + fmt(b) + "  before  FN " + fmt(fn) });
        }
        if (allEqual) {
          flags.push({ name: "All four Standard Information times identical", value: fmt(b) });
        }
        for (const f of lane.findings || []) {
          flags.push({ name: f, value: "flagged by the detection engine" });
        }
      }
      if (ev.label === "M" && b && ev.time < b) {
        flags.push({ name: "Modified before created, copied in", value: "M " + fmt(ev.time) + "  before  B " + fmt(b) });
      }
      if (ev.label === "A" && b && ev.time < b) {
        flags.push({ name: "Accessed before created", value: "A " + fmt(ev.time) + "  before  B " + fmt(b) });
      }
      if (/\.0000000Z$/.test(ev.time)) {
        flags.push({ name: "Zeroed sub seconds", value: fmt(ev.time) });
      }
      if (Date.parse(ev.time) > now) {
        flags.push({ name: "Timestamp in the future", value: fmt(ev.time) });
      }
      out.push({
        entry: lane.entry,
        name: lane.name,
        path: lane.path,
        deleted: lane.deleted,
        label: ev.label,
        full: ev.full,
        time: ev.time,
        t: Date.parse(ev.time),
        flags,
      });
    }
  }
  return out;
}

function renderFeed(content) {
  const feed = content.querySelector("#ta-feed");
  let items = model.events.filter((e) => model.filters[e.label]);
  if (model.suspiciousOnly) {
    items = items.filter((e) => e.flags.length > 0 || e.deleted);
  }
  if (model.after || model.before) {
    items = items.filter((e) => {
      const day = tz.format(e.time).slice(0, 10);
      if (!day) {
        return false;
      }
      if (model.after && day < model.after) {
        return false;
      }
      if (model.before && day > model.before) {
        return false;
      }
      return true;
    });
  }
  items.sort((a, b) => (model.order === "asc" ? a.t - b.t : b.t - a.t));
  const fileCount = model.mode === "bodyfile" ? model.bodyLanes.length : model.entries.size;
  content.querySelector("#ta-count").textContent =
    items.length.toLocaleString() + " events across " + fileCount.toLocaleString() + " files";
  if (items.length === 0) {
    feed.innerHTML =
      model.mode === "bodyfile"
        ? '<p class="muted">Choose a bodyfile on the left and click Analyze.</p>'
        : '<p class="muted">No events. Add a flagged file on the left, or from a record in Explore.</p>';
    return;
  }
  let html = "";
  let lastDay = "";
  items.forEach((e, i) => {
    const shown = tz.format(e.time);
    const day = shown.slice(0, 10);
    if (day !== lastDay) {
      html += `<div class="tl-day">${esc(day)}</div>`;
      lastDay = day;
    }
    const suspicious = e.flags.length > 0 || e.deleted;
    html += `
<div class="tl-item${suspicious ? " flagged" : ""}" data-i="${i}">
<div class="tl-spine"><span class="tl-dot tl-${esc(e.label)}"></span></div>
<div class="tl-card">
<div class="tl-time">${esc(shown)}</div>
<div class="tl-main"><span class="tl-type tl-${esc(e.label)}">${esc(labelName(e.label))}</span><span class="tl-file">${esc(e.name || e.path)}</span>${e.deleted ? '<span class="tl-badge del">deleted</span>' : ""}${e.flags.map((f) => `<span class="tl-badge warn">${esc(f.name)}</span>`).join("")}</div>
<div class="tl-path">${esc(e.path)}</div>
</div>
</div>`;
  });
  feed.innerHTML = html;
  for (const node of feed.querySelectorAll(".tl-item")) {
    node.addEventListener("click", () => openEvent(items[Number(node.getAttribute("data-i"))]));
  }
}

function labelName(label) {
  const map = { B: "Born", M: "Modified", C: "MFT changed", A: "Accessed", FN: "File Name born" };
  return map[label] || label;
}

function openEvent(e) {
  const m = openModal({ title: "Timeline event", width: "560px" });
  m.body.innerHTML = `
<div class="an-d">
<div class="an-d-top"><span class="an-d-name">${esc(e.name || e.path)}</span>${e.deleted ? '<span class="an-status deleted">Deleted</span>' : ""}</div>
<div class="an-d-chips"><span class="an-chip">entry ${e.entry}</span><span class="an-chip">${esc(labelName(e.label))}</span></div>
<div class="an-d-head">When</div>
<p class="an-d-text mono">${esc(tz.format(e.time))}</p>
<p class="an-d-text mono">${esc(e.time)}</p>
<div class="an-d-head">What</div>
<p class="an-d-text">${esc(e.full)}</p>
${e.flags.length ? `<div class="an-d-head">Detections</div>
<table class="det-table"><thead><tr><th>Detection</th><th>Value that helped detect it</th></tr></thead>
<tbody>${e.flags.map((f) => `<tr><td>${esc(f.name)}</td><td class="mono">${esc(f.value)}</td></tr>`).join("")}</tbody></table>` : ""}
<div class="an-d-head">Path</div>
<p class="an-d-text mono wrap">${esc(e.path)}</p>
<div class="detail-controls"><button type="button" class="btn ghost small" id="ta-explore">${icon("grid")} Show in Explore</button></div>
</div>`;
  m.body.querySelector("#ta-explore").addEventListener("click", () => {
    try {
      sessionStorage.setItem("focus_explore_search", e.name || e.path);
    } catch (err) {
      void err;
    }
    m.close();
    go("/explore");
  });
}

function renderBodyImport(content) {
  const list = content.querySelector("#ta-list");
  const chosen = model.bodyPath
    ? `<div class="ta-import-file mono">${esc(model.bodyPath)}</div>`
    : '<div class="muted">No bodyfile chosen.</div>';
  let status = "";
  if (model.bodyError) {
    status = `<div class="ta-import-status err">${esc(model.bodyError)}</div>`;
  } else if (model.bodyLoading) {
    status = '<div class="ta-import-status">Reading the bodyfile…</div>';
  } else if (model.bodyLanes.length) {
    const more = model.bodyTruncated ? ", showing the first " + model.bodyReturned.toLocaleString() : "";
    status = `<div class="ta-import-status">${model.bodyReturned.toLocaleString()} files from ${model.bodyLines.toLocaleString()} records${more}</div>`;
  }
  list.innerHTML = `<li class="ta-import">
<p class="muted">Read a Sleuth Kit bodyfile from fls, mactime input or another examiner and view it as a timeline here. Times are read as seconds.</p>
${chosen}
<div class="ta-import-row">
<button type="button" class="btn small" id="ta-body-pick">${icon("folder")} Choose bodyfile</button>
<button type="button" class="btn ghost small" id="ta-body-run"${model.bodyPath ? "" : " disabled"}>${icon("search")} Analyze</button>
</div>
${status}
</li>`;
  list.querySelector("#ta-body-pick").addEventListener("click", async () => {
    try {
      const res = await api.pick("file");
      if (res && res.path) {
        model.bodyPath = res.path;
        model.bodyError = "";
        renderBodyImport(content);
        analyzeBody(content);
      } else if (res && res.supported === false) {
        model.bodyError = "The file picker is not available here. Run the tool on your own machine to browse.";
        renderBodyImport(content);
      }
    } catch (err) {
      void err;
    }
  });
  const run = list.querySelector("#ta-body-run");
  if (run) {
    run.addEventListener("click", () => analyzeBody(content));
  }
}

async function analyzeBody(content) {
  if (!model.bodyPath) {
    return;
  }
  model.bodyLoading = true;
  model.bodyError = "";
  content.querySelector("#ta-skel").hidden = false;
  content.querySelector("#ta-feed").hidden = true;
  renderBodyImport(content);
  try {
    const res = await api.timelineBodyfile(model.bodyPath, model.query);
    model.bodyLanes = res.lanes || [];
    model.bodyReturned = res.returned || 0;
    model.bodyLines = res.lines || 0;
    model.bodyTruncated = !!res.truncated;
    model.bodyEvents = flattenBody(model.bodyLanes);
    model.events = model.bodyEvents;
    saveBodyPath(model.bodyPath);
  } catch (err) {
    model.bodyError = err && err.message ? err.message : "Could not read the bodyfile.";
    model.bodyLanes = [];
    model.bodyEvents = [];
    model.events = [];
    if (/not a file/i.test(model.bodyError)) {
      clearBodyPath();
    }
  }
  model.bodyLoading = false;
  content.querySelector("#ta-skel").hidden = true;
  content.querySelector("#ta-feed").hidden = false;
  renderBodyImport(content);
  renderFeed(content);
}

function flattenBody(lanes) {
  const out = [];
  const now = Date.now();
  const fmt = (t) => (t ? tz.format(t) : "");
  for (const lane of lanes) {
    const byLabel = {};
    for (const e of lane.events) {
      byLabel[e.label] = e.time;
    }
    const b = byLabel.B;
    const fn = byLabel.FN;
    const stomp = b && fn && b < fn;
    const siTimes = ["B", "M", "C", "A"].map((k) => byLabel[k]).filter(Boolean);
    const allEqual = siTimes.length === 4 && siTimes.every((t) => t === siTimes[0]);
    for (const ev of lane.events) {
      const flags = [];
      if (ev.label === "B") {
        if (stomp) {
          flags.push({ name: "Standard Information created before File Name", value: "SI " + fmt(b) + "  before  FN " + fmt(fn) });
        }
        if (allEqual) {
          flags.push({ name: "All four Standard Information times identical", value: fmt(b) });
        }
      }
      if (ev.label === "M" && b && ev.time < b) {
        flags.push({ name: "Modified before created, copied in", value: "M " + fmt(ev.time) + "  before  B " + fmt(b) });
      }
      if (ev.label === "A" && b && ev.time < b) {
        flags.push({ name: "Accessed before created", value: "A " + fmt(ev.time) + "  before  B " + fmt(b) });
      }
      if (Date.parse(ev.time) > now) {
        flags.push({ name: "Timestamp in the future", value: fmt(ev.time) });
      }
      out.push({
        entry: lane.entry,
        name: lane.name,
        path: lane.path,
        deleted: lane.deleted,
        label: ev.label,
        full: ev.full,
        time: ev.time,
        t: Date.parse(ev.time),
        flags,
      });
    }
  }
  return out;
}

function bodyKey() {
  const file = state.caseInfo && state.caseInfo.file ? state.caseInfo.file : "";
  return "ntfs_body:" + file + ":" + model.evidenceId;
}

function loadBodyPath() {
  try {
    return localStorage.getItem(bodyKey()) || "";
  } catch (e) {
    void e;
    return "";
  }
}

function saveBodyPath(path) {
  try {
    if (path) {
      localStorage.setItem(bodyKey(), path);
    }
  } catch (e) {
    void e;
  }
}

function clearBodyPath() {
  try {
    localStorage.removeItem(bodyKey());
  } catch (e) {
    void e;
  }
}
