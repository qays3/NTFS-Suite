import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { openModal } from "/js/ui/modal.js";
import { rowsToCSV, rowsToJSON, copyText } from "/js/ui/clip.js";
import { toast } from "/js/ui/toast.js";
import { openMenu, closeMenu } from "/js/ui/menu.js";
import { renderSecureSection } from "/js/ui/secure-section.js";
import { renderRules } from "/js/pages/rules.js";

const COLUMNS = [
  { key: "severity", label: "Severity", get: (f) => f.severity, cell: "sev" },
  { key: "rule_id", label: "Rule", get: (f) => f.rule_id },
  { key: "name", label: "File", get: (f) => f.name },
  { key: "path", label: "Path", get: (f) => f.path, cell: "path" },
  { key: "mitre", label: "MITRE", get: (f) => f.mitre },
  { key: "status", label: "Status", get: (f) => f.status, cell: "status" },
  { key: "sources", label: "Seen in", get: (f) => (f.sources || []).join(" "), cell: "sources" },
  { key: "reason", label: "Reason", get: (f) => f.reason, def: false },
];

const page = {
  evidenceId: null,
  offset: 0,
  limit: 100,
  total: 0,
  severity: "",
  status: "",
  search: "",
  rows: [],
  cols: {},
};

const NOT_RUN = [
  "Record number order versus creation time",
  "Executable content inside an alternate data stream (MZ header)",
  "Zone.Identifier download source and Mark of the Web",
  "Allocated versus real size anomalies",
  "Broken fixup and BAAD records",
];

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const parsed = state.evidence.find((e) => e.status === "parsed");
  if (!parsed) {
    const empty = caseShell(view, "findings");
    empty.innerHTML = `<section class="panel"><h3>Findings</h3><p class="muted">No parsed evidence yet.</p><div class="row-end"><button type="button" class="btn" id="fd-add">${icon("plus")} Add evidence</button></div></section>`;
    empty.querySelector("#fd-add").addEventListener("click", () => go("/logs"));
    return;
  }
  page.evidenceId = parsed.id;
  page.offset = 0;
  page.cols = loadCols();
  let focus = "";
  try {
    focus = sessionStorage.getItem("focus_findings_search") || "";
    sessionStorage.removeItem("focus_findings_search");
  } catch (e) {
    void e;
  }
  page.search = focus;
  const content = caseShell(view, "findings");
  content.innerHTML = `
<div class="findings">
<div class="seg fd-tabs" id="fd-tabs"><button type="button" class="seg-btn on" data-pane="findings">Findings</button><button type="button" class="seg-btn" data-pane="rules">Rules</button></div>
<div id="fd-findings-pane">
<div class="toolbar">
<div class="stat-chips" id="fd-stats"></div>
<span class="toolbar-spacer"></span>
<button type="button" class="btn ghost small" id="fd-rerun">${icon("search")} Re-run detection</button>
</div>
<div class="toolbar">
<span class="find-wrap">${icon("search")}<input id="fd-search" class="find" type="text" placeholder="find file or path"></span>
<select id="fd-sev" class="mini-select"><option value="">All severity</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
<select id="fd-status" class="mini-select"><option value="">All status</option><option value="new">New</option><option value="confirmed">Confirmed</option><option value="false_positive">False positive</option></select>
<button type="button" class="btn ghost small" id="fd-clear-all">${icon("cancel")} Clear all</button>
<span class="toolbar-spacer"></span>
<span class="count" id="fd-count"></span>
<button type="button" class="btn ghost small" id="fd-views">${icon("list")} Views</button>
<button type="button" class="btn ghost small" id="fd-cols">${icon("grid")} Columns</button>
<button type="button" class="btn ghost small" id="fd-copy-csv">Copy CSV</button>
<button type="button" class="btn ghost small" id="fd-copy-json">Copy JSON</button>
</div>
<div class="findings-body">
<div class="table-pane">
<div class="skeleton" id="fd-skel" style="height:100%"></div>
<table class="data-table dense" id="fd-table" hidden>
<thead id="fd-head"></thead>
<tbody id="fd-rows"></tbody>
</table>
</div>
<aside class="detail-pane" id="fd-ranked"></aside>
</div>
<div class="pager" id="fd-pager" hidden>
<span id="fd-pageinfo"></span>
<div class="page-nav" id="fd-pages"></div>
</div>
<section class="panel subtle">
<h3>Checks not run from the $MFT alone</h3>
<ul class="plain-list">${NOT_RUN.map((c) => `<li>${esc(c)}</li>`).join("")}</ul>
<p class="muted">These need other artifacts such as $UsnJrnl, $LogFile, Prefetch or the Registry, added as plugins in later versions.</p>
</section>
</div>
<div id="fd-rules-pane" hidden></div>
</div>`;

  if (page.search) {
    content.querySelector("#fd-search").value = page.search;
  }
  let timer = null;
  content.querySelector("#fd-search").addEventListener("input", (e) => {
    page.search = e.target.value.trim();
    clearTimeout(timer);
    timer = setTimeout(() => {
      page.offset = 0;
      load(content);
    }, 250);
  });
  content.querySelector("#fd-sev").addEventListener("change", (e) => {
    page.severity = e.target.value;
    page.offset = 0;
    load(content);
  });
  content.querySelector("#fd-status").addEventListener("change", (e) => {
    page.status = e.target.value;
    page.offset = 0;
    load(content);
  });
  content.querySelector("#fd-copy-csv").addEventListener("click", () => {
    copyText(rowsToCSV(page.rows, visibleColumns()), page.rows.length + " findings copied as CSV");
  });
  content.querySelector("#fd-copy-json").addEventListener("click", () => {
    copyText(rowsToJSON(page.rows, visibleColumns()), page.rows.length + " findings copied as JSON");
  });
  content.querySelector("#fd-cols").addEventListener("click", (e) => openColumnsMenu(content, e.currentTarget));
  content.querySelector("#fd-views").addEventListener("click", (e) => openViewsMenu(content, e.currentTarget));
  content.querySelector("#fd-clear-all").addEventListener("click", () => {
    page.search = "";
    page.severity = "";
    page.status = "";
    page.offset = 0;
    const s = content.querySelector("#fd-search");
    if (s) {
      s.value = "";
    }
    const sev = content.querySelector("#fd-sev");
    if (sev) {
      sev.value = "";
    }
    const st = content.querySelector("#fd-status");
    if (st) {
      st.value = "";
    }
    load(content);
  });
  let rulesLoaded = false;
  const tabs = content.querySelector("#fd-tabs");
  for (const b of tabs.querySelectorAll(".seg-btn")) {
    b.addEventListener("click", () => {
      for (const o of tabs.querySelectorAll(".seg-btn")) {
        o.classList.toggle("on", o === b);
      }
      const pane = b.getAttribute("data-pane");
      content.querySelector("#fd-findings-pane").hidden = pane !== "findings";
      content.querySelector("#fd-rules-pane").hidden = pane !== "rules";
      if (pane === "rules" && !rulesLoaded) {
        rulesLoaded = true;
        renderRules(content.querySelector("#fd-rules-pane"), page.evidenceId);
      }
    });
  }
  content.querySelector("#fd-rerun").addEventListener("click", async () => {
    const btn = content.querySelector("#fd-rerun");
    btn.disabled = true;
    btn.textContent = "Running";
    try {
      await api.detect(page.evidenceId);
      page.offset = 0;
      await load(content);
    } catch (e) {
      void e;
    }
    btn.disabled = false;
    btn.innerHTML = icon("search") + " Re-run detection";
  });

  await load(content);
}

async function load(content) {
  content.querySelector("#fd-skel").hidden = false;
  content.querySelector("#fd-table").hidden = true;
  const query = {
    evidence_id: page.evidenceId,
    offset: page.offset,
    limit: page.limit,
    severity: page.severity,
    status: page.status,
    search: page.search,
  };
  const body = content.querySelector("#fd-rows");
  body.innerHTML = "";

  const data = await api.findings(query);
  page.total = data.total;
  renderStats(content, data.stats, "Files");
  renderRanked(content, data.ranked);
  page.rows = data.rows;
  renderTable(content);
  content.querySelector("#fd-count").textContent = page.total.toLocaleString() + " findings";

  content.querySelector("#fd-skel").hidden = true;
  content.querySelector("#fd-table").hidden = false;
  content.querySelector("#fd-pager").hidden = false;
  const from = page.total === 0 ? 0 : page.offset + 1;
  const to = Math.min(page.offset + page.limit, page.total);
  content.querySelector("#fd-pageinfo").textContent = from + " to " + to + " of " + page.total.toLocaleString();
  renderPager(content);
}

function renderStats(content, stats, lastLabel) {
  const last = lastLabel === "Folders" ? stats.folders : stats.flagged_files;
  content.querySelector("#fd-stats").innerHTML = `
<span class="chip-stat sev-high">High ${stats.high}</span>
<span class="chip-stat sev-medium">Medium ${stats.medium}</span>
<span class="chip-stat sev-low">Low ${stats.low}</span>
<span class="chip-stat">${lastLabel} ${last}</span>`;
}

function renderRanked(content, ranked) {
  const pane = content.querySelector("#fd-ranked");
  if (!ranked || ranked.length === 0) {
    pane.innerHTML = '<p class="muted">No ranked files</p>';
    return;
  }
  pane.innerHTML = '<div class="rank-head">Top ranked files</div><ol class="rank-list" id="fd-rank-list"></ol>';
  const list = pane.querySelector("#fd-rank-list");
  for (const r of ranked) {
    const li = document.createElement("li");
    li.className = "rank-item clickable";
    li.innerHTML = `<span class="sev-dot sev-${esc(r.top_severity)}"></span><span class="rank-name" title="${esc(r.path)}">${esc(r.name) || esc(r.path)}</span><span class="rank-score">${r.total_score}</span>`;
    li.addEventListener("click", () => {
      const term = r.path || r.name || "";
      page.search = term;
      page.offset = 0;
      const box = content.querySelector("#fd-search");
      if (box) {
        box.value = term;
      }
      load(content);
    });
    list.appendChild(li);
  }
}

function visibleColumns() {
  return COLUMNS.filter((c) => (page.cols[c.key] === undefined ? c.def !== false : page.cols[c.key]));
}

function renderTable(content) {
  const cols = visibleColumns();
  content.querySelector("#fd-head").innerHTML = "<tr>" + cols.map((c) => `<th>${c.label}</th>`).join("") + "</tr>";
  const body = content.querySelector("#fd-rows");
  body.innerHTML = "";
  page.rows.forEach((f, idx) => body.appendChild(row(content, f, idx, cols)));
}

function row(content, f, idx, cols) {
  const tr = document.createElement("tr");
  for (const c of cols) {
    if (c.cell === "sev") {
      tr.appendChild(sevCell(f.severity));
    } else if (c.cell === "status") {
      tr.appendChild(statusCell(content, f));
    } else if (c.cell === "path") {
      const td = document.createElement("td");
      td.className = "path-cell";
      td.textContent = f.path;
      td.title = f.path;
      tr.appendChild(td);
    } else if (c.cell === "sources") {
      const td = document.createElement("td");
      td.className = "src-cell";
      const list = f.sources || [];
      const badges = list.map((s) => `<span class="src-badge src-${s.replace(/\\$/g, "").toLowerCase()}">${s}</span>`).join("");
      td.innerHTML = f.correlated ? `<span class="src-cor" title="Mentioned in more than one NTFS artifact">correlated</span>${badges}` : badges;
      tr.appendChild(td);
    } else {
      cell(tr, c.get(f));
    }
  }
  tr.classList.add("clickable");
  tr.addEventListener("click", () => openFinding(content, idx));
  return tr;
}

function openColumnsMenu(content, anchor) {
  const wrap = document.createElement("div");
  wrap.className = "menu-pop-body";
  wrap.innerHTML = '<div class="menu-head">Columns</div>';
  for (const c of COLUMNS) {
    const row = document.createElement("label");
    row.className = "menu-check";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = page.cols[c.key] === undefined ? c.def !== false : page.cols[c.key];
    cb.addEventListener("change", () => {
      const visible = visibleColumns();
      if (!cb.checked && visible.length === 1 && visible[0].key === c.key) {
        cb.checked = true;
        return;
      }
      page.cols[c.key] = cb.checked;
      saveCols();
      renderTable(content);
    });
    row.appendChild(cb);
    const span = document.createElement("span");
    span.textContent = c.label;
    row.appendChild(span);
    wrap.appendChild(row);
  }
  openMenu(anchor, wrap);
}

function openViewsMenu(content, anchor) {
  const wrap = document.createElement("div");
  wrap.className = "menu-pop-body";
  const views = loadViews();
  let html = '<div class="menu-head">Saved views</div>';
  if (views.length === 0) {
    html += '<div class="menu-empty">None saved</div>';
  }
  wrap.innerHTML = html;
  views.forEach((v, i) => {
    const r = document.createElement("div");
    r.className = "menu-view";
    const name = document.createElement("button");
    name.type = "button";
    name.className = "menu-view-name";
    name.textContent = v.name;
    name.addEventListener("click", () => {
      applyView(content, v);
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
      openViewsMenu(content, anchor);
    });
    r.appendChild(name);
    r.appendChild(del);
    wrap.appendChild(r);
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
    const v = { name: nm, search: page.search, severity: page.severity, status: page.status };
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

function applyView(content, v) {
  page.search = v.search || "";
  page.severity = v.severity || "";
  page.status = v.status || "";
  page.offset = 0;
  const search = content.querySelector("#fd-search");
  if (search) {
    search.value = page.search;
  }
  const sev = content.querySelector("#fd-sev");
  if (sev) {
    sev.value = page.severity;
  }
  const st = content.querySelector("#fd-status");
  if (st) {
    st.value = page.status;
  }
  load(content);
}

function caseKey(prefix) {
  const file = state.caseInfo && state.caseInfo.file ? state.caseInfo.file : "";
  return prefix + ":" + file + ":" + page.evidenceId;
}

function loadCols() {
  try {
    const raw = localStorage.getItem(caseKey("ntfs_fcols"));
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    void e;
    return {};
  }
}

function saveCols() {
  try {
    localStorage.setItem(caseKey("ntfs_fcols"), JSON.stringify(page.cols));
  } catch (e) {
    void e;
  }
}

function loadViews() {
  try {
    const raw = localStorage.getItem(caseKey("ntfs_fviews"));
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    void e;
    return [];
  }
}

function saveViews(all) {
  try {
    localStorage.setItem(caseKey("ntfs_fviews"), JSON.stringify(all));
  } catch (e) {
    void e;
  }
}

function statusWord(value) {
  return { new: "New", confirmed: "Confirmed", false_positive: "False positive" }[value] || value;
}

function openFinding(content, startIndex) {
  let dirty = false;
  const m = openModal({
    title: "Finding detail",
    width: "640px",
    onClose: () => {
      if (dirty) {
        load(content);
      }
    },
  });
  let i = startIndex;

  function paint() {
    const f = page.rows[i];
    m.body.innerHTML = `
<div class="finding-detail">
<h3 class="finding-title">${esc(f.title)}</h3>
<div class="detail-flags"><span class="sev-badge sev-${esc(f.severity)}">${esc(f.severity)}</span><span class="tag">${esc(f.rule_id)}</span><span class="tag">${esc(f.mitre)}</span></div>
<dl class="detail-list">
<div class="detail-row"><dt>File</dt><dd>${esc(f.name) || "-"}</dd></div>
<div class="detail-row"><dt>Path</dt><dd class="mono wrap">${esc(f.path)}</dd></div>
<div class="detail-row"><dt>Entry</dt><dd>${esc(String(f.entry))}</dd></div>
<div class="detail-row"><dt>Score</dt><dd>${esc(String(f.score))}</dd></div>
<div class="detail-row"><dt>Found</dt><dd>${esc(f.created_utc)}</dd></div>
</dl>
<div class="detail-reason-head">Reason</div>
<p class="detail-reason">${esc(f.reason)}</p>
<div class="detail-sub">Seen in</div>
<div class="detail-sources">${(f.sources || []).map((s) => `<span class="src-badge src-${s.replace(/\$/g, "").toLowerCase()}">${esc(s)}</span>`).join("")}${f.correlated ? '<span class="src-cor">correlated</span>' : ""}</div>
<div id="md-secure"></div>
<div class="detail-controls">
<label class="inline-label">Status<select id="md-status" class="mini-select"></select></label>
<button type="button" class="btn ghost small" id="md-group">Apply to all with this reason</button>
<button type="button" class="btn ghost small" id="md-explore">${icon("grid")} Show in Explore</button>
<button type="button" class="btn ghost small" id="md-journal">${icon("clock")} Show in Journal</button>
</div>
<p class="group-note" id="md-group-note"></p>
<div class="modal-nav">
<button type="button" class="btn ghost small" id="md-prev"${i === 0 ? " disabled" : ""}>Prev</button>
<span class="nav-count">${i + 1} of ${page.rows.length}</span>
<button type="button" class="btn ghost small" id="md-next"${i >= page.rows.length - 1 ? " disabled" : ""}>Next</button>
</div>
</div>`;

    const sel = m.body.querySelector("#md-status");
    for (const [value, label] of [["new", "New"], ["confirmed", "Confirmed"], ["false_positive", "False positive"]]) {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = label;
      if (value === f.status) {
        opt.selected = true;
      }
      sel.appendChild(opt);
    }
    sel.addEventListener("change", async () => {
      try {
        await api.findingStatus({ id: f.id, status: sel.value, notes: f.notes || "" });
        f.status = sel.value;
        dirty = true;
        const rowSel = document.querySelector('select[data-fid="' + f.id + '"]');
        if (rowSel) {
          rowSel.value = sel.value;
        }
      } catch (e) {
        void e;
      }
    });

    m.body.querySelector("#md-group").addEventListener("click", async () => {
      const note = m.body.querySelector("#md-group-note");
      const chosen = sel.value;
      note.textContent = "Applying to every " + f.rule_id + " finding";
      try {
        const res = await api.findingStatusGroup({ evidence_id: page.evidenceId, rule_id: f.rule_id, status: chosen });
        dirty = true;
        for (const r of page.rows) {
          if (r.rule_id === f.rule_id) {
            r.status = chosen;
            const rowSel = document.querySelector('select[data-fid="' + r.id + '"]');
            if (rowSel) {
              rowSel.value = chosen;
            }
          }
        }
        note.textContent = res.updated + " findings with this reason set to " + statusWord(chosen);
      } catch (e) {
        note.textContent = "Could not apply to the group";
      }
    });

    m.body.querySelector("#md-explore").addEventListener("click", () => {
      try {
        sessionStorage.setItem("focus_explore_search", f.path);
      } catch (e) {
        void e;
      }
      m.close();
      go("/explore");
    });

    const jbtn = m.body.querySelector("#md-journal");
    if (jbtn) {
      jbtn.addEventListener("click", () => {
        try {
          sessionStorage.setItem("focus_journal_search", f.name);
        } catch (e) {
          void e;
        }
        m.close();
        go("/journal");
      });
    }

    renderSecureSection(m.body.querySelector("#md-secure"), { entry: f.entry });

    const prev = m.body.querySelector("#md-prev");
    const next = m.body.querySelector("#md-next");
    if (prev) {
      prev.addEventListener("click", () => {
        if (i > 0) {
          i -= 1;
          paint();
        }
      });
    }
    if (next) {
      next.addEventListener("click", () => {
        if (i < page.rows.length - 1) {
          i += 1;
          paint();
        }
      });
    }
  }

  paint();
}

function sevCell(severity) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = "sev-badge sev-" + severity;
  span.textContent = severity;
  td.appendChild(span);
  return td;
}

function statusCell(content, f) {
  const td = document.createElement("td");
  const sel = document.createElement("select");
  sel.className = "mini-select";
  sel.dataset.fid = f.id;
  sel.addEventListener("click", (e) => e.stopPropagation());
  for (const [value, label] of [["new", "New"], ["confirmed", "Confirmed"], ["false_positive", "False positive"]]) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    if (value === f.status) {
      opt.selected = true;
    }
    sel.appendChild(opt);
  }
  sel.addEventListener("change", async () => {
    try {
      await api.findingStatus({ id: f.id, status: sel.value, notes: f.notes || "" });
      f.status = sel.value;
      load(content);
    } catch (e) {
      void e;
    }
  });
  td.appendChild(sel);
  return td;
}

function cell(tr, value) {
  const td = document.createElement("td");
  td.textContent = value === null || value === undefined ? "" : String(value);
  tr.appendChild(td);
}

function goPage(content, n) {
  const pages = Math.max(1, Math.ceil(page.total / page.limit));
  const clamped = Math.min(Math.max(1, n), pages);
  page.offset = (clamped - 1) * page.limit;
  load(content);
}

function pageButton(content, label, target, opts) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "page-btn" + (opts && opts.current ? " current" : "");
  b.textContent = label;
  if (opts && opts.disabled) {
    b.disabled = true;
  } else {
    b.addEventListener("click", () => goPage(content, target));
  }
  return b;
}

function pageGap() {
  const s = document.createElement("span");
  s.className = "page-gap";
  s.textContent = "...";
  return s;
}

function renderPager(content) {
  const nav = content.querySelector("#fd-pages");
  nav.innerHTML = "";
  const pages = Math.max(1, Math.ceil(page.total / page.limit));
  const current = Math.floor(page.offset / page.limit) + 1;
  nav.appendChild(pageButton(content, "First", 1, { disabled: current === 1 }));
  nav.appendChild(pageButton(content, "Prev", current - 1, { disabled: current === 1 }));
  const nums = pageRange(current, pages);
  let prev = 0;
  for (const n of nums) {
    if (n - prev > 1) {
      nav.appendChild(pageGap());
    }
    nav.appendChild(pageButton(content, String(n), n, { current: n === current }));
    prev = n;
  }
  nav.appendChild(pageButton(content, "Next", current + 1, { disabled: current === pages }));
  nav.appendChild(pageButton(content, "Last", pages, { disabled: current === pages }));
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
