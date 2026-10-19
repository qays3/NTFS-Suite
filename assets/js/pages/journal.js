import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import * as tz from "/js/timezone.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { openModal } from "/js/ui/modal.js";
import { renderSecureSection, fileAttrText } from "/js/ui/secure-section.js";

function sourceInfoText(flags) {
  const f = Number(flags) || 0;
  const names = [];
  if (f & 0x1) names.push("data management");
  if (f & 0x2) names.push("auxiliary data");
  if (f & 0x4) names.push("replication");
  return names.length ? names.join(", ") : "normal user change";
}

function sourceBadges(r) {
  const list = r.sources || [];
  const html = list.map((s) => `<span class="src-badge src-${s.replace(/\$/g, "").toLowerCase()}">${esc(s)}</span>`).join("");
  return r.correlated ? `<span class="src-cor" title="Mentioned in more than one NTFS artifact">correlated</span>${html}` : html;
}

const page = {
  evidenceId: null,
  offset: 0,
  limit: 200,
  total: 0,
  search: "",
  summary: "",
  after: "",
  before: "",
};

const SUMMARY_ORDER = ["create", "delete", "rename", "data", "security", "reparse", "basic info", "close", "other"];

function pivot(term, key, path) {
  try {
    sessionStorage.setItem(key, term);
  } catch (e) {
    void e;
  }
  go(path);
}

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const content = caseShell(view, "journal");
  const usn = state.evidence.find((e) => e.plugin === "usnjrnl");
  if (!usn) {
    content.innerHTML = `<section class="panel"><h3>Change journal</h3><p class="muted">No $UsnJrnl $J added to this case. The journal records every create, delete, rename and change, with its own timestamps. Add a $UsnJrnl $J from the Add evidence page to see it here.</p><div class="row-end"><button type="button" class="btn" id="jr-add">${icon("plus")} Add evidence</button></div></section>`;
    content.querySelector("#jr-add").addEventListener("click", () => go("/logs"));
    return;
  }
  page.evidenceId = usn.id;
  page.offset = 0;
  page.search = "";
  page.summary = "";
  page.after = "";
  page.before = "";
  try {
    const focus = sessionStorage.getItem("focus_journal_search");
    if (focus) {
      page.search = focus;
    }
    sessionStorage.removeItem("focus_journal_search");
  } catch (e) {
    void e;
  }

  content.innerHTML = `
<div class="journal">
<div class="toolbar">
<span class="find-wrap">${icon("search")}<input id="jr-search" class="find" type="text" placeholder="find a file name"></span>
<select id="jr-summary" class="mini-select"><option value="">All changes</option>${SUMMARY_ORDER.map((s) => `<option value="${s}">${s}</option>`).join("")}</select>
<div class="time-filter" title="Keep journal entries whose time is in this range, in UTC">${icon("clock")}<input type="text" id="jr-after" class="tf-date" placeholder="after  YYYY-MM-DD" inputmode="numeric" maxlength="10"><input type="text" id="jr-before" class="tf-date" placeholder="before  YYYY-MM-DD" inputmode="numeric" maxlength="10"></div>
<button type="button" class="btn ghost small" id="jr-clear">${icon("cancel")} Clear all</button>
<span class="toolbar-spacer"></span>
<span class="count" id="jr-count"></span>
</div>
<div class="tiles" id="jr-tiles"></div>
<div class="table-pane">
<div class="skeleton" id="jr-skel" style="height:360px"></div>
<table class="data-table dense" id="jr-table" hidden>
<thead><tr><th>Time (UTC)</th><th>USN</th><th>Record</th><th>Name</th><th>Change</th><th>Details</th><th>Seen in</th></tr></thead>
<tbody id="jr-body"></tbody>
</table>
</div>
<div class="pager" id="jr-pager" hidden>
<span id="jr-pageinfo"></span>
<div class="page-nav" id="jr-pages"></div>
</div>
</div>`;

  let timer = null;
  content.querySelector("#jr-search").addEventListener("input", (e) => {
    page.search = e.target.value.trim();
    clearTimeout(timer);
    timer = setTimeout(() => {
      page.offset = 0;
      load(content);
    }, 250);
  });
  content.querySelector("#jr-summary").addEventListener("change", (e) => {
    page.summary = e.target.value;
    page.offset = 0;
    load(content);
  });
  wireDate(content, "#jr-after", (v) => {
    page.after = v;
    page.offset = 0;
    load(content);
  });
  wireDate(content, "#jr-before", (v) => {
    page.before = v;
    page.offset = 0;
    load(content);
  });
  if (page.search) {
    content.querySelector("#jr-search").value = page.search;
  }
  content.querySelector("#jr-clear").addEventListener("click", () => {
    page.search = "";
    page.summary = "";
    page.after = "";
    page.before = "";
    page.offset = 0;
    content.querySelector("#jr-search").value = "";
    content.querySelector("#jr-summary").value = "";
    content.querySelector("#jr-after").value = "";
    content.querySelector("#jr-before").value = "";
    load(content);
  });

  await load(content);
}

function wireDate(content, sel, onChange) {
  const input = content.querySelector(sel);
  input.addEventListener("change", () => {
    const v = input.value.trim();
    if (v === "" || /^\d{4}-\d{2}-\d{2}$/.test(v)) {
      onChange(v);
    }
  });
}

async function load(content) {
  content.querySelector("#jr-skel").hidden = false;
  content.querySelector("#jr-table").hidden = true;
  let data;
  try {
    data = await api.usnList({
      evidence_id: page.evidenceId,
      offset: page.offset,
      limit: page.limit,
      search: page.search,
      summary: page.summary,
      after: page.after,
      before: page.before,
    });
  } catch (err) {
    content.querySelector("#jr-skel").hidden = true;
    content.querySelector("#jr-body").innerHTML = `<tr><td colspan="7" class="hint">Could not load the journal: ${esc(err.message)}. If the server was just updated, restart it.</td></tr>`;
    content.querySelector("#jr-table").hidden = false;
    return;
  }
  page.total = data.total;
  const noFilters = !page.search && !page.summary && !page.after && !page.before;
  renderTiles(content, data.summary_counts);
  renderRows(content, data.rows, noFilters && page.total === 0);
  content.querySelector("#jr-count").textContent = page.total.toLocaleString() + " entries";
  content.querySelector("#jr-skel").hidden = true;
  content.querySelector("#jr-table").hidden = false;
  content.querySelector("#jr-pager").hidden = false;
  const from = page.total === 0 ? 0 : page.offset + 1;
  const to = Math.min(page.offset + page.limit, page.total);
  content.querySelector("#jr-pageinfo").textContent = from + " to " + to + " of " + page.total.toLocaleString();
  renderPager(content);
}

function renderTiles(content, counts) {
  const host = content.querySelector("#jr-tiles");
  if (!counts || !counts.length) {
    host.innerHTML = "";
    return;
  }
  host.innerHTML = counts
    .map((c) => `<div class="tile"><span class="tile-value">${Number(c.count).toLocaleString()}</span><span class="tile-label">${esc(c.summary)}</span></div>`)
    .join("");
}

function renderRows(content, rows, emptyEvidence) {
  const body = content.querySelector("#jr-body");
  if (!rows.length) {
    if (emptyEvidence) {
      body.innerHTML = '<tr><td colspan="7" class="muted">The $UsnJrnl was added but no USN records were found in it. Make sure you exported the $J data stream itself (the $J named stream of \\$Extend\\$UsnJrnl), not the small $Max stream or an empty file. Tools like KAPE and FTK Imager export it as a file named "$J".</td></tr>';
    } else {
      body.innerHTML = '<tr><td colspan="7" class="muted">No journal entries match.</td></tr>';
    }
    return;
  }
  body.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.className = "clickable";
    if (r.flag) {
      tr.classList.add("jr-flagged");
    }
    const flagBadge = r.flag ? `<span class="jr-flag" title="${esc(r.flag)}">flag</span>` : "";
    tr.innerHTML = `
<td class="mono">${esc(tz.format(r.timestamp))}</td>
<td class="mono">${esc(String(r.usn))}</td>
<td class="mono">${esc(String(r.entry))}</td>
<td class="jr-name" title="${esc(r.name)}">${esc(r.name)}${flagBadge}</td>
<td><span class="jr-kind jr-${esc(r.summary)}">${esc(r.summary)}</span></td>
<td class="jr-reason">${esc(r.flag || r.reason_text)}</td>
<td class="src-cell">${sourceBadges(r)}</td>`;
    tr.classList.add("clickable");
    tr.addEventListener("click", () => openEventModal(r));
    body.appendChild(tr);
  }
}

function openEventModal(r) {
  const m = openModal({ title: "Journal entry", width: "560px" });
  const rows = [
    ["Time (UTC)", tz.format(r.timestamp)],
    ["USN", r.usn],
    ["Record (entry)", r.entry],
    ["Parent record", r.parent_entry],
    ["Change", r.summary],
    ["Reasons", r.reason_text],
    ["File attributes", fileAttrText(r.file_attributes)],
    ["Source", sourceInfoText(r.source_info)],
    ["Security id", r.security_id],
  ];
  let html = `<div class="detail-head">${esc(r.name)}</div>`;
  if (r.flag) {
    html += `<div class="detail-flags"><span class="jr-flag">${esc(r.flag)}</span></div>`;
  }
  html += '<dl class="detail-list">';
  for (const [k, v] of rows) {
    html += `<div class="detail-row"><dt>${esc(k)}</dt><dd>${esc(String(v))}</dd></div>`;
  }
  html += "</dl>";
  html += `<div class="detail-sub">Seen in</div><div class="detail-sources">${sourceBadges(r)}</div>`;
  html += `<div id="jm-secure"></div>`;
  html += `<div class="detail-controls"><button type="button" class="btn ghost small" id="jm-explore">${icon("grid")} Show in Explore</button><button type="button" class="btn ghost small" id="jm-findings">${icon("search")} Show in Findings</button></div>`;
  m.body.innerHTML = html;
  renderSecureSection(m.body.querySelector("#jm-secure"), { security_id: r.security_id, entry: r.entry });
  m.body.querySelector("#jm-explore").addEventListener("click", () => {
    pivot(r.name, "focus_explore_search", "/explore");
    m.close();
  });
  m.body.querySelector("#jm-findings").addEventListener("click", () => {
    pivot(r.name, "focus_findings_search", "/findings");
    m.close();
  });
}

function renderPager(content) {
  const nav = content.querySelector("#jr-pages");
  const pages = Math.ceil(page.total / page.limit);
  const current = Math.floor(page.offset / page.limit);
  if (pages <= 1) {
    nav.innerHTML = "";
    return;
  }
  nav.innerHTML = "";
  const mk = (label, target, disabled) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn ghost small";
    b.textContent = label;
    b.disabled = disabled;
    b.addEventListener("click", () => {
      page.offset = target * page.limit;
      load(content);
    });
    nav.appendChild(b);
  };
  mk("Prev", current - 1, current === 0);
  mk("Next", current + 1, current >= pages - 1);
}

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
