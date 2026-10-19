import { api } from "/js/api.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { openModal } from "/js/ui/modal.js";
import { toast } from "/js/ui/toast.js";

const FIELDS = [
  "name", "ext", "path", "parent_path",
  "si_created", "si_modified", "si_mft_modified", "si_accessed", "fn_created",
  "is_directory", "deleted", "has_ads", "orphan",
  "entry", "sequence", "parent_entry",
];

const OPS = [
  ["contains", "contains"],
  ["eq", "equals"],
  ["ne", "not equals"],
  ["starts_with", "starts with"],
  ["ends_with", "ends with"],
  ["regex", "matches regex"],
  ["in", "is in list"],
  ["gt", "greater than"],
  ["lt", "less than"],
  ["gte", "greater or equal"],
  ["lte", "less or equal"],
  ["before", "time before"],
  ["after", "time after"],
  ["lt_field", "earlier than field"],
  ["gt_field", "later than field"],
  ["is_true", "is true"],
  ["is_false", "is false"],
];

export async function renderRules(container, evidenceId) {
  container.innerHTML = `
<div class="rules-head">
<p class="muted">Every detection rule in this case. Turn a rule off to drop it from the ranking, read how it works, or write your own. Re-run detection on the Findings tab to apply changes.</p>
<button type="button" class="btn small" id="rl-new">${icon("plus")} New rule</button>
</div>
<details class="rl-ioc">
<summary>IOC list <span class="muted" id="rl-ioc-count"></span></summary>
<p class="muted">An $MFT records a file's name, path and size, not its contents, so a file cannot be hashed from an $MFT alone. Matching is by name, path and size. Rule MFT-IOC-01 flags records whose name, path or size is on the list. A hash column is accepted and kept with the list for when a content source is added later, but it is not matched yet. CSV needs a header row with name, path, size or hash. JSON is an array of those objects.</p>
<div class="rl-ioc-row">
<select id="rl-ioc-format" class="mini-select"><option value="csv">CSV</option><option value="json">JSON</option></select>
<span class="toolbar-spacer"></span>
<button type="button" class="btn ghost small" id="rl-ioc-clear">Clear</button>
<button type="button" class="btn small" id="rl-ioc-import">Import</button>
</div>
<textarea id="rl-ioc-text" class="rb-json" placeholder="name,path,size,hash"></textarea>
<p class="rb-note" id="rl-ioc-note"></p>
</details>
<div class="skeleton" id="rl-skel" style="height:240px"></div>
<div id="rl-list" hidden></div>`;
  container.querySelector("#rl-new").addEventListener("click", () => openBuilder(container, evidenceId, null));
  wireIoc(container);
  await load(container, evidenceId);
}

function wireIoc(container) {
  const countEl = container.querySelector("#rl-ioc-count");
  const note = container.querySelector("#rl-ioc-note");
  const refresh = async () => {
    try {
      const data = await api.iocList();
      countEl.textContent = data.count ? "(" + data.count.toLocaleString() + " entries)" : "(empty)";
    } catch (e) {
      void e;
    }
  };
  container.querySelector("#rl-ioc-import").addEventListener("click", async () => {
    const text = container.querySelector("#rl-ioc-text").value;
    const format = container.querySelector("#rl-ioc-format").value;
    if (!text.trim()) {
      note.textContent = "Paste the list first.";
      return;
    }
    try {
      const res = await api.iocImport(text, format);
      note.textContent = res.count.toLocaleString() + " entries imported. Re-run detection to match them.";
      refresh();
    } catch (e) {
      note.textContent = e.message || "Import failed.";
    }
  });
  container.querySelector("#rl-ioc-clear").addEventListener("click", async () => {
    try {
      await api.iocClear();
      note.textContent = "IOC list cleared.";
      refresh();
    } catch (e) {
      void e;
    }
  });
  refresh();
}

async function load(container, evidenceId) {
  const skel = container.querySelector("#rl-skel");
  const list = container.querySelector("#rl-list");
  skel.hidden = false;
  list.hidden = true;
  let data;
  try {
    data = await api.rulesList();
  } catch (e) {
    list.innerHTML = '<p class="muted">Could not load rules.</p>';
    skel.hidden = true;
    list.hidden = false;
    return;
  }
  list.innerHTML = data.rules.map(ruleRow).join("");
  for (const row of list.querySelectorAll(".rl-row")) {
    const id = row.getAttribute("data-id");
    const rule = data.rules.find((r) => r.id === id);
    row.querySelector(".rl-main").addEventListener("click", (e) => {
      if (e.target.closest(".rl-toggle")) {
        return;
      }
      row.classList.toggle("open");
    });
    const toggle = row.querySelector(".rl-toggle input");
    toggle.addEventListener("change", async () => {
      try {
        await api.rulesEnable(id, toggle.checked);
        row.classList.toggle("off", !toggle.checked);
      } catch (err) {
        void err;
        toggle.checked = !toggle.checked;
      }
    });
    if (rule.custom) {
      const edit = row.querySelector(".rl-edit");
      const del = row.querySelector(".rl-del");
      if (edit) {
        edit.addEventListener("click", () => openBuilder(container, evidenceId, rule));
      }
      if (del) {
        del.addEventListener("click", async () => {
          try {
            await api.rulesDelete(id);
            load(container, evidenceId);
          } catch (err) {
            void err;
          }
        });
      }
    }
  }
  skel.hidden = true;
  list.hidden = false;
}

function ruleRow(r) {
  const body = r.custom
    ? `<pre class="rl-cond">${esc(r.condition)}</pre><div class="rl-actions"><button type="button" class="btn ghost small rl-edit">Edit</button><button type="button" class="btn ghost small danger rl-del">Delete</button></div>`
    : `<p class="rl-cond-text">${esc(r.condition)}</p>`;
  return `
<div class="rl-row${r.enabled ? "" : " off"}" data-id="${esc(r.id)}">
<div class="rl-main">
<label class="rl-toggle" title="Enable or disable"><input type="checkbox"${r.enabled ? " checked" : ""}></label>
<span class="sev-badge sev-${esc(r.severity)}">${esc(r.severity)}</span>
<span class="rl-id">${esc(r.id)}</span>
<span class="rl-title">${esc(r.title)}</span>
<span class="rl-tags"><span class="tag">${esc(r.mitre || "-")}</span><span class="tag">${esc(r.kind)}</span></span>
<span class="rl-count">${r.count.toLocaleString()} found</span>
</div>
<div class="rl-detail">
<div class="rl-meta"><span>Source: ${esc(r.source)}</span><span>Needs: ${esc(r.needs)}</span><span>Ships in: ${esc(r.ships_in)}</span></div>
${body}
</div>
</div>`;
}

function openBuilder(container, evidenceId, existing) {
  const m = openModal({ title: existing ? "Edit rule" : "New rule", width: "720px" });
  const start = existing && existing.custom ? safeParse(existing.condition) : null;
  const combine = start && start.any ? "any" : "all";
  const preds = start ? (start.all || start.any || []) : [{ field: "path", op: "contains", value: "" }];
  m.body.innerHTML = `
<div class="rb">
<div class="rb-grid">
<label>Title<input type="text" id="rb-title" value="${existing ? esc(existing.title) : ""}"></label>
<label>Severity<select id="rb-sev" class="mini-select"><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
<label>MITRE technique<input type="text" id="rb-mitre" placeholder="T1036" value="${existing ? esc(existing.mitre) : ""}"></label>
</div>
<label>Reason shown on a finding<input type="text" id="rb-reason" value="${existing ? esc(existing.reason || "") : ""}"></label>
<div class="rb-cond-head">Match when <select id="rb-combine" class="mini-select"><option value="all">all</option><option value="any">any</option></select> of these are true</div>
<div id="rb-rows"></div>
<button type="button" class="btn ghost small" id="rb-add">${icon("plus")} Add condition</button>
<details class="rb-raw"><summary>Advanced: edit as JSON</summary><textarea id="rb-json" class="rb-json" spellcheck="false"></textarea><button type="button" class="btn ghost small" id="rb-apply-json">Use this JSON</button></details>
<div class="rb-foot">
<button type="button" class="btn ghost small" id="rb-preview">Preview matches</button>
<span class="rb-note" id="rb-note"></span>
<span class="toolbar-spacer"></span>
<button type="button" class="btn small" id="rb-save">${existing ? "Save changes" : "Create rule"}</button>
</div>
<div id="rb-sample"></div>
</div>`;
  const sevSel = m.body.querySelector("#rb-sev");
  sevSel.value = existing ? existing.severity : "medium";
  m.body.querySelector("#rb-combine").value = combine;
  const rowsWrap = m.body.querySelector("#rb-rows");
  const addRow = (p) => {
    const row = document.createElement("div");
    row.className = "rb-row";
    row.innerHTML = `
<select class="mini-select rb-field">${FIELDS.map((f) => `<option value="${f}">${f}</option>`).join("")}</select>
<select class="mini-select rb-op">${OPS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select>
<input type="text" class="rb-val" placeholder="value">
<button type="button" class="rb-rm" title="Remove">${icon("cancel")}</button>`;
    row.querySelector(".rb-field").value = p.field || "path";
    row.querySelector(".rb-op").value = p.op || "contains";
    row.querySelector(".rb-val").value = valueToText(p.value);
    const syncVal = () => {
      const op = row.querySelector(".rb-op").value;
      row.querySelector(".rb-val").style.visibility = op === "is_true" || op === "is_false" ? "hidden" : "visible";
    };
    row.querySelector(".rb-op").addEventListener("change", syncVal);
    row.querySelector(".rb-rm").addEventListener("click", () => row.remove());
    syncVal();
    rowsWrap.appendChild(row);
  };
  for (const p of preds) {
    addRow(p);
  }
  m.body.querySelector("#rb-add").addEventListener("click", () => addRow({ field: "path", op: "contains", value: "" }));

  const collect = () => {
    const raw = m.body.querySelector("#rb-json").value.trim();
    let condition;
    if (raw) {
      condition = safeParse(raw);
      if (!condition) {
        return null;
      }
    } else {
      const comb = m.body.querySelector("#rb-combine").value;
      const list = [];
      for (const row of rowsWrap.querySelectorAll(".rb-row")) {
        const field = row.querySelector(".rb-field").value;
        const op = row.querySelector(".rb-op").value;
        const value = textToValue(op, row.querySelector(".rb-val").value);
        list.push({ field, op, value });
      }
      condition = comb === "any" ? { any: list } : { all: list };
    }
    return {
      id: existing ? existing.id : "",
      title: m.body.querySelector("#rb-title").value,
      severity: sevSel.value,
      mitre: m.body.querySelector("#rb-mitre").value,
      reason: m.body.querySelector("#rb-reason").value,
      condition,
    };
  };

  m.body.querySelector("#rb-apply-json").addEventListener("click", () => {
    const note = m.body.querySelector("#rb-note");
    const parsed = safeParse(m.body.querySelector("#rb-json").value);
    note.textContent = parsed ? "JSON is valid and will be used on save." : "That JSON is not valid.";
  });

  m.body.querySelector("#rb-preview").addEventListener("click", async () => {
    const note = m.body.querySelector("#rb-note");
    const rule = collect();
    if (!rule) {
      note.textContent = "Fix the rule before preview.";
      return;
    }
    note.textContent = "Scanning...";
    try {
      const res = await api.rulesPreview(evidenceId, rule);
      note.textContent = res.count.toLocaleString() + " matches in " + res.scanned.toLocaleString() + " records" + (res.truncated ? " (first part scanned)" : "");
      const sample = m.body.querySelector("#rb-sample");
      sample.innerHTML = res.sample.length
        ? '<div class="rb-sample-head">Sample</div>' + res.sample.map((s) => `<div class="rb-sample-row"><span class="mono">${esc(s.name || s.path)}</span><span class="rb-sample-path">${esc(s.path)}</span></div>`).join("")
        : "";
    } catch (e) {
      note.textContent = "Preview failed.";
    }
  });

  m.body.querySelector("#rb-save").addEventListener("click", async () => {
    const note = m.body.querySelector("#rb-note");
    const rule = collect();
    if (!rule) {
      note.textContent = "Fix the rule JSON before saving.";
      return;
    }
    if (!rule.title.trim()) {
      note.textContent = "Give the rule a title.";
      return;
    }
    try {
      await api.rulesSave(rule);
      toast("Rule saved");
      m.close();
      load(container, evidenceId);
    } catch (e) {
      note.textContent = e.message || "Could not save the rule.";
    }
  });
}

function valueToText(value) {
  if (value === undefined || value === null) {
    return "";
  }
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function textToValue(op, text) {
  const t = text.trim();
  if (op === "is_true" || op === "is_false") {
    return true;
  }
  if (op === "in") {
    return t ? t.split(",").map((s) => s.trim()).filter(Boolean) : [];
  }
  if (op === "gt" || op === "lt" || op === "gte" || op === "lte") {
    const n = Number(t);
    return Number.isNaN(n) ? t : n;
  }
  return t;
}

function safeParse(text) {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? v : null;
  } catch (e) {
    return null;
  }
}
