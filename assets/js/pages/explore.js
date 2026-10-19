import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import * as tz from "/js/timezone.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { rowsToCSV, rowsToJSON, copyText } from "/js/ui/clip.js";
import { toast } from "/js/ui/toast.js";
import { openMenu, closeMenu } from "/js/ui/menu.js";
import { renderSecureSection } from "/js/ui/secure-section.js";

const page = {
  evidenceId: null,
  offset: 0,
  limit: 200,
  total: 0,
  rows: [],
  chips: { deleted_only: false, ads_only: false, dir_only: false, orphan_only: false, si_lt_fn_only: false, fn_lt_si_only: false },
  search: "",
  after: "",
  before: "",
  cols: {},
};

const CHIPS = [
  ["deleted_only", "Deleted"],
  ["ads_only", "ADS"],
  ["dir_only", "Directories"],
  ["orphan_only", "Orphans"],
  ["si_lt_fn_only", "SI<FN"],
  ["fn_lt_si_only", "FN<SI"],
];

const COLUMNS = [
  { key: "entry", label: "Entry", get: (r) => r.entry },
  { key: "name", label: "Name", get: (r) => r.name },
  { key: "path", label: "Path", get: (r) => r.path },
  { key: "state", label: "State", get: (r) => rowState(r) },
  { key: "ads", label: "ADS", get: (r) => (r.has_ads ? "yes" : "") },
  { key: "si_created", label: "SI created", get: (r) => tz.format(r.si_created) },
  { key: "fn_created", label: "FN created", get: (r) => tz.format(r.fn_created) },
  { key: "flags", label: "Flags", get: (r) => flagText(r) },
  { key: "sources", label: "Seen in", get: (r) => (r.sources || []).join(" ") },
];

function sourceBadges(r) {
  const list = r.sources || [];
  const html = list.map((s) => `<span class="src-badge src-${s.replace(/\\$/g, "").toLowerCase()}">${s}</span>`).join("");
  return r.correlated ? `<span class="src-cor" title="Mentioned in more than one NTFS artifact">correlated</span>${html}` : html;
}

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const parsed = state.evidence.find((e) => e.status === "parsed");
  if (!parsed) {
    const empty = caseShell(view, "explore");
    empty.innerHTML = `<section class="panel"><h3>Explore</h3><p class="muted">No parsed evidence yet.</p><div class="row-end"><button type="button" class="btn" id="ex-add">${icon("plus")} Add evidence</button></div></section>`;
    empty.querySelector("#ex-add").addEventListener("click", () => go("/logs"));
    return;
  }
  page.evidenceId = parsed.id;
  page.offset = 0;
  page.rows = [];
  page.chips = { deleted_only: false, ads_only: false, dir_only: false, orphan_only: false, si_lt_fn_only: false, fn_lt_si_only: false };
  page.after = "";
  page.before = "";
  page.cols = loadCols();
  let focus = "";
  try {
    focus = sessionStorage.getItem("focus_explore_search") || "";
    sessionStorage.removeItem("focus_explore_search");
  } catch (e) {
    void e;
  }
  page.search = focus;
  view.classList.add("full");
  const content = caseShell(view, "explore");

  content.innerHTML = `
<div class="explore">
<div class="toolbar">
<span class="find-wrap">${icon("search")}<input id="ex-search" class="find" type="text" placeholder="find name or path"></span>
<div class="chips" id="ex-chips"></div>
<div class="time-filter" title="Match records with any timestamp in this range, in the stored UTC time">${icon("clock")}<input type="text" id="ex-after" class="tf-date" placeholder="after  YYYY-MM-DD" inputmode="numeric" maxlength="10"><input type="text" id="ex-before" class="tf-date" placeholder="before  YYYY-MM-DD" inputmode="numeric" maxlength="10"><button type="button" class="tf-clear" id="ex-tclear" hidden>clear</button></div>
<button type="button" class="btn ghost small" id="ex-clear-all">${icon("cancel")} Clear all</button>
<span class="toolbar-spacer"></span>
<span class="count" id="ex-count"></span>
<button type="button" class="btn ghost small" id="ex-views">${icon("list")} Views</button>
<button type="button" class="btn ghost small" id="ex-cols">${icon("grid")} Columns</button>
<button type="button" class="btn ghost small" id="ex-copy-csv">Copy CSV</button>
<button type="button" class="btn ghost small" id="ex-copy-json">Copy JSON</button>
<button type="button" class="btn ghost small" id="ex-csv">${icon("download")} CSV</button>
<button type="button" class="btn ghost small" id="ex-json">${icon("download")} JSON</button>
</div>
<div class="explore-body">
<div class="table-pane">
<div class="skeleton" id="ex-skel" style="height:100%"></div>
<table class="data-table dense" id="ex-table" hidden>
<thead id="ex-head"></thead>
<tbody id="ex-body"></tbody>
</table>
</div>
<aside class="detail-pane" id="ex-detail"><p class="muted">Select a record to see its full detail</p></aside>
</div>
<div class="pager" id="ex-pager" hidden>
<span id="ex-pageinfo"></span>
<div class="page-nav" id="ex-pages"></div>
</div>
</div>`;

  renderChips(view);
  if (page.search) {
    view.querySelector("#ex-search").value = page.search;
  }

  let timer = null;
  view.querySelector("#ex-search").addEventListener("input", (e) => {
    page.search = e.target.value.trim();
    clearTimeout(timer);
    timer = setTimeout(() => {
      page.offset = 0;
      load(view);
    }, 250);
  });
  view.querySelector("#ex-csv").addEventListener("click", () => download("csv"));
  view.querySelector("#ex-json").addEventListener("click", () => download("json"));
  view.querySelector("#ex-copy-csv").addEventListener("click", () => {
    copyText(rowsToCSV(page.rows, visibleColumns()), page.rows.length + " rows copied as CSV");
  });
  view.querySelector("#ex-copy-json").addEventListener("click", () => {
    copyText(rowsToJSON(page.rows, visibleColumns()), page.rows.length + " rows copied as JSON");
  });
  view.querySelector("#ex-cols").addEventListener("click", (e) => openColumnsMenu(view, e.currentTarget));
  view.querySelector("#ex-views").addEventListener("click", (e) => openViewsMenu(view, e.currentTarget));
  view.querySelector("#ex-clear-all").addEventListener("click", () => clearAll(view));
  wireTimeFilter(view);

  await load(view);
}

function clearAll(view) {
  page.search = "";
  page.chips = { deleted_only: false, ads_only: false, dir_only: false, orphan_only: false, si_lt_fn_only: false, fn_lt_si_only: false };
  page.after = "";
  page.before = "";
  page.offset = 0;
  const s = view.querySelector("#ex-search");
  if (s) {
    s.value = "";
  }
  const a = view.querySelector("#ex-after");
  if (a) {
    a.value = "";
  }
  const b = view.querySelector("#ex-before");
  if (b) {
    b.value = "";
  }
  const tclear = view.querySelector("#ex-tclear");
  if (tclear) {
    tclear.hidden = true;
  }
  renderChips(view);
  load(view);
}

function visibleColumns() {
  return COLUMNS.filter((c) => page.cols[c.key] !== false);
}

function renderChips(view) {
  const wrap = view.querySelector("#ex-chips");
  wrap.innerHTML = "";
  for (const [key, label] of CHIPS) {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip" + (page.chips[key] ? " on" : "");
    chip.textContent = label;
    chip.dataset.chip = key;
    chip.addEventListener("click", () => {
      page.chips[key] = !page.chips[key];
      chip.classList.toggle("on", page.chips[key]);
      page.offset = 0;
      load(view);
    });
    wrap.appendChild(chip);
  }
}

function syncChipButtons(view) {
  for (const chip of view.querySelectorAll("#ex-chips .chip")) {
    const key = chip.dataset.chip;
    chip.classList.toggle("on", !!page.chips[key]);
  }
}

function wireTimeFilter(view) {
  const after = view.querySelector("#ex-after");
  const before = view.querySelector("#ex-before");
  const clear = view.querySelector("#ex-tclear");
  let timer = null;
  const re = /^\d{4}-\d{2}-\d{2}$/;
  const apply = () => {
    const a = after.value.trim();
    const b = before.value.trim();
    const okA = a === "" || re.test(a);
    const okB = b === "" || re.test(b);
    after.classList.toggle("bad", !okA);
    before.classList.toggle("bad", !okB);
    clear.hidden = !(a || b);
    if (!okA || !okB) {
      return;
    }
    page.after = a;
    page.before = b;
    page.offset = 0;
    load(view);
  };
  const run = () => {
    clearTimeout(timer);
    timer = setTimeout(apply, 300);
  };
  after.addEventListener("input", run);
  before.addEventListener("input", run);
  clear.addEventListener("click", () => {
    after.value = "";
    before.value = "";
    after.classList.remove("bad");
    before.classList.remove("bad");
    page.after = "";
    page.before = "";
    clear.hidden = true;
    page.offset = 0;
    load(view);
  });
}

function filterParams() {
  return {
    evidence_id: page.evidenceId,
    search: page.search,
    after: page.after,
    before: page.before,
    ...page.chips,
  };
}

function download(format) {
  const q = new URLSearchParams();
  q.set("evidence_id", String(page.evidenceId));
  q.set("format", format);
  if (page.search) {
    q.set("search", page.search);
  }
  if (page.after) {
    q.set("after", page.after);
  }
  if (page.before) {
    q.set("before", page.before);
  }
  for (const [key, value] of Object.entries(page.chips)) {
    if (value) {
      q.set(key, "true");
    }
  }
  const a = document.createElement("a");
  a.href = "/api/records/export?" + q.toString();
  a.download = "records." + format;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

async function load(view) {
  view.querySelector("#ex-skel").hidden = false;
  view.querySelector("#ex-table").hidden = true;
  const data = await api.records({ offset: page.offset, limit: page.limit, ...filterParams() });
  page.total = data.total;
  page.rows = data.rows || [];
  renderTable(view);
  view.querySelector("#ex-skel").hidden = true;
  view.querySelector("#ex-table").hidden = false;
  view.querySelector("#ex-pager").hidden = false;
  const from = page.total === 0 ? 0 : page.offset + 1;
  const to = Math.min(page.offset + page.limit, page.total);
  view.querySelector("#ex-pageinfo").textContent = from + " to " + to + " of " + page.total.toLocaleString();
  view.querySelector("#ex-count").textContent = page.total.toLocaleString() + " records";
  renderPager(view);
}

function renderTable(view) {
  const cols = visibleColumns();
  view.querySelector("#ex-head").innerHTML = "<tr>" + cols.map((c) => `<th>${c.label}</th>`).join("") + "</tr>";
  const body = view.querySelector("#ex-body");
  body.innerHTML = "";
  for (const r of page.rows) {
    body.appendChild(rowEl(view, r, cols));
  }
}

function rowEl(view, r, cols) {
  const tr = document.createElement("tr");
  const stomp = tz.siBeforeFn(r.si_created, r.fn_created);
  const fnStomp = tz.siBeforeFn(r.fn_created, r.si_created);
  const zeroSub = tz.hasZeroSubseconds(r.si_created);
  if (stomp) {
    tr.classList.add("flag-row");
  } else if (fnStomp) {
    tr.classList.add("flag-row-soft");
  }
  for (const c of cols) {
    if (c.key === "name") {
      truncCell(tr, r.name, "ex-name");
    } else if (c.key === "path") {
      truncCell(tr, r.path, "ex-path");
    } else if (c.key === "flags") {
      const td = document.createElement("td");
      td.className = "flags-cell";
      td.textContent = flagText(r);
      tr.appendChild(td);
    } else if (c.key === "sources") {
      const td = document.createElement("td");
      td.className = "src-cell";
      td.innerHTML = sourceBadges(r);
      tr.appendChild(td);
    } else {
      cell(tr, c.get(r));
    }
  }
  tr.addEventListener("click", () => {
    for (const el of view.querySelectorAll("#ex-body tr.selected")) {
      el.classList.remove("selected");
    }
    tr.classList.add("selected");
    showDetail(view, r, stomp, zeroSub);
  });
  return tr;
}

function flagText(r) {
  const flags = [];
  if (tz.siBeforeFn(r.si_created, r.fn_created)) {
    flags.push("SI<FN");
  }
  if (tz.siBeforeFn(r.fn_created, r.si_created)) {
    flags.push("FN<SI");
  }
  if (tz.hasZeroSubseconds(r.si_created)) {
    flags.push("0sub");
  }
  return flags.join(" ");
}

function openColumnsMenu(view, anchor) {
  const wrap = document.createElement("div");
  wrap.className = "menu-pop-body";
  wrap.innerHTML = '<div class="menu-head">Columns</div>';
  for (const c of COLUMNS) {
    const row = document.createElement("label");
    row.className = "menu-check";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = page.cols[c.key] !== false;
    cb.addEventListener("change", () => {
      const visible = visibleColumns();
      if (!cb.checked && visible.length === 1 && visible[0].key === c.key) {
        cb.checked = true;
        return;
      }
      page.cols[c.key] = cb.checked;
      saveCols();
      renderTable(view);
    });
    row.appendChild(cb);
    const span = document.createElement("span");
    span.textContent = c.label;
    row.appendChild(span);
    wrap.appendChild(row);
  }
  openMenu(anchor, wrap);
}

function openViewsMenu(view, anchor) {
  const wrap = document.createElement("div");
  wrap.className = "menu-pop-body";
  const views = loadViews();
  let html = '<div class="menu-head">Saved views</div>';
  if (views.length === 0) {
    html += '<div class="menu-empty">None saved</div>';
  }
  wrap.innerHTML = html;
  views.forEach((v, i) => {
    const row = document.createElement("div");
    row.className = "menu-view";
    const name = document.createElement("button");
    name.type = "button";
    name.className = "menu-view-name";
    name.textContent = v.name;
    name.addEventListener("click", () => {
      applyView(view, v);
      closeMenu();
    });
    const del = document.createElement("button");
    del.type = "button";
    del.className = "menu-view-del";
    del.textContent = "×";
    del.title = "Delete";
    del.addEventListener("click", () => {
      const all = loadViews();
      all.splice(i, 1);
      saveViews(all);
      closeMenu();
      openViewsMenu(view, anchor);
    });
    row.appendChild(name);
    row.appendChild(del);
    wrap.appendChild(row);
  });
  const saveRow = document.createElement("div");
  saveRow.className = "menu-saverow";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "menu-input";
  input.placeholder = "name this view";
  const save = document.createElement("button");
  save.type = "button";
  save.className = "btn small";
  save.textContent = "Save current";
  save.addEventListener("click", () => {
    const nm = input.value.trim();
    if (!nm) {
      return;
    }
    const all = loadViews();
    const v = {
      name: nm,
      search: page.search,
      chips: { ...page.chips },
      after: page.after,
      before: page.before,
    };
    const at = all.findIndex((x) => x.name === nm);
    if (at >= 0) {
      all[at] = v;
    } else {
      all.push(v);
    }
    saveViews(all);
    toast("View saved");
    closeMenu();
  });
  saveRow.appendChild(input);
  saveRow.appendChild(save);
  wrap.appendChild(saveRow);
  openMenu(anchor, wrap);
}

function applyView(view, v) {
  page.search = v.search || "";
  page.chips = {
    deleted_only: false,
    ads_only: false,
    dir_only: false,
    orphan_only: false,
    si_lt_fn_only: false,
    fn_lt_si_only: false,
    ...(v.chips || {}),
  };
  page.after = v.after || "";
  page.before = v.before || "";
  page.offset = 0;
  const search = view.querySelector("#ex-search");
  if (search) {
    search.value = page.search;
  }
  const a = view.querySelector("#ex-after");
  const b = view.querySelector("#ex-before");
  if (a) {
    a.value = page.after;
  }
  if (b) {
    b.value = page.before;
  }
  const clear = view.querySelector("#ex-tclear");
  if (clear) {
    clear.hidden = !(page.after || page.before);
  }
  syncChipButtons(view);
  load(view);
}

function caseKey(prefix) {
  const file = state.caseInfo && state.caseInfo.file ? state.caseInfo.file : "";
  return prefix + ":" + file + ":" + page.evidenceId;
}

function loadCols() {
  try {
    const raw = localStorage.getItem(caseKey("ntfs_cols"));
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    void e;
    return {};
  }
}

function saveCols() {
  try {
    localStorage.setItem(caseKey("ntfs_cols"), JSON.stringify(page.cols));
  } catch (e) {
    void e;
  }
}

function loadViews() {
  try {
    const raw = localStorage.getItem(caseKey("ntfs_views"));
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    void e;
    return [];
  }
}

function saveViews(all) {
  try {
    localStorage.setItem(caseKey("ntfs_views"), JSON.stringify(all));
  } catch (e) {
    void e;
  }
}

function goPage(view, n) {
  const pages = Math.max(1, Math.ceil(page.total / page.limit));
  const clamped = Math.min(Math.max(1, n), pages);
  page.offset = (clamped - 1) * page.limit;
  load(view);
}

function pageButton(view, label, target, opts) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "page-btn" + (opts && opts.current ? " current" : "");
  b.textContent = label;
  if (opts && opts.disabled) {
    b.disabled = true;
  } else {
    b.addEventListener("click", () => goPage(view, target));
  }
  return b;
}

function pageGap() {
  const s = document.createElement("span");
  s.className = "page-gap";
  s.textContent = "...";
  return s;
}

function renderPager(view) {
  const nav = view.querySelector("#ex-pages");
  nav.innerHTML = "";
  const pages = Math.max(1, Math.ceil(page.total / page.limit));
  const current = Math.floor(page.offset / page.limit) + 1;
  nav.appendChild(pageButton(view, "First", 1, { disabled: current === 1 }));
  nav.appendChild(pageButton(view, "Prev", current - 1, { disabled: current === 1 }));
  const nums = pageRange(current, pages);
  let prev = 0;
  for (const n of nums) {
    if (n - prev > 1) {
      nav.appendChild(pageGap());
    }
    nav.appendChild(pageButton(view, String(n), n, { current: n === current }));
    prev = n;
  }
  nav.appendChild(pageButton(view, "Next", current + 1, { disabled: current === pages }));
  nav.appendChild(pageButton(view, "Last", pages, { disabled: current === pages }));
}

function pageRange(current, pages) {
  const out = new Set([1, pages, current]);
  for (let d = 1; d <= 2; d++) {
    if (current - d >= 1) {
      out.add(current - d);
    }
    if (current + d <= pages) {
      out.add(current + d);
    }
  }
  return Array.from(out).sort((a, b) => a - b);
}

function showDetail(view, r, stomp, zeroSub) {
  const pane = view.querySelector("#ex-detail");
  const rows = [
    ["Entry", r.entry],
    ["Sequence", r.sequence],
    ["Name", r.name],
    ["Path", r.path],
    ["State", rowState(r)],
    ["Parent entry", r.parent_entry],
    ["Has ADS", r.has_ads ? "yes" : "no"],
    ["Orphan", r.orphan ? "yes" : "no"],
    ["SI created", tz.format(r.si_created)],
    ["SI modified", tz.format(r.si_modified)],
    ["SI MFT modified", tz.format(r.si_mft_modified)],
    ["SI accessed", tz.format(r.si_accessed)],
    ["FN created", tz.format(r.fn_created)],
  ];
  let html = `<div class="detail-head">${escape(r.name)}</div>`;
  if (stomp || zeroSub) {
    const tags = [];
    if (stomp) {
      tags.push("SI&lt;FN");
    }
    if (zeroSub) {
      tags.push("zero subseconds");
    }
    html += `<div class="detail-flags">${tags.join(" · ")}</div>`;
  }
  html += '<dl class="detail-list">';
  for (const [k, v] of rows) {
    html += `<div class="detail-row"><dt>${k}</dt><dd>${escape(String(v))}</dd></div>`;
  }
  html += "</dl>";
  html += `<div class="detail-sub">Seen in</div><div class="detail-sources">${sourceBadges(r)}</div>`;
  html += `<div id="ex-secure"></div>`;
  html += `<div class="detail-controls"><button type="button" class="btn ghost small" id="ex-findings">${icon("search")} Show in Findings</button><button type="button" class="btn ghost small" id="ex-journal">${icon("clock")} Show in Journal</button><button type="button" class="btn ghost small" id="ex-time">${icon("clock")} Add to Time analyze</button></div>`;
  pane.innerHTML = html;
  const jbtn = pane.querySelector("#ex-journal");
  if (jbtn) {
    jbtn.addEventListener("click", () => {
      try {
        sessionStorage.setItem("focus_journal_search", r.name);
      } catch (e) {
        void e;
      }
      go("/journal");
    });
  }
  const btn = pane.querySelector("#ex-findings");
  if (btn) {
    btn.addEventListener("click", () => {
      try {
        sessionStorage.setItem("focus_findings_search", r.path);
      } catch (e) {
        void e;
      }
      go("/findings");
    });
  }
  renderSecureSection(pane.querySelector("#ex-secure"), { security_id: r.security_id });
  const timeBtn = pane.querySelector("#ex-time");
  if (timeBtn) {
    timeBtn.addEventListener("click", () => {
      try {
        sessionStorage.setItem("focus_time_entries", JSON.stringify([r.entry]));
      } catch (e) {
        void e;
      }
      go("/time");
    });
  }
}

function rowState(r) {
  if (!r.in_use) {
    return r.orphan ? "deleted orphan" : "deleted";
  }
  return r.is_directory ? "dir" : "file";
}

function cell(tr, value) {
  const td = document.createElement("td");
  td.textContent = value === null || value === undefined ? "" : String(value);
  tr.appendChild(td);
}

function truncCell(tr, value, cls) {
  const td = document.createElement("td");
  const text = value === null || value === undefined ? "" : String(value);
  td.className = "trunc " + cls;
  td.textContent = text;
  td.title = text;
  tr.appendChild(td);
}

function escape(value) {
  return String(value || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
