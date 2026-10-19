import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { palette, barChart, scatter, lineChart, heatmap } from "/js/charts/draw.js";

const page = { evidenceId: null, from: "", to: "" };

const PANELS = [
  ["density", "Activity over time", "Drag to select a date range and filter every chart"],
  ["sifn", "Standard Information vs File Name creation", "Timestomped files fall off the diagonal"],
  ["record", "Record number vs creation time", "Backdated files sit far below the rising line"],
  ["subsecond", "Sub second first digit", "A spike at zero marks tool set times"],
  ["heatmap", "Activity by day and hour", "Off hours activity in the display zone"],
  ["extensions", "Top file extensions", ""],
  ["severity", "Findings by severity", ""],
  ["rules", "Findings by rule", ""],
];

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const parsed = state.evidence.find((e) => e.status === "parsed");
  if (!parsed) {
    const empty = caseShell(view, "graphs");
    empty.innerHTML = `<section class="panel"><h3>Graphs</h3><p class="muted">No parsed evidence yet.</p><div class="row-end"><button type="button" class="btn" id="g-add">${icon("plus")} Add evidence</button></div></section>`;
    empty.querySelector("#g-add").addEventListener("click", () => go("/logs"));
    return;
  }
  page.evidenceId = parsed.id;
  page.from = "";
  page.to = "";
  const content = caseShell(view, "graphs");
  content.innerHTML = `
<div class="graphs">
<div class="tiles" id="g-tiles"></div>
<div class="range-bar" id="g-range"></div>
<div class="chart-grid">
${PANELS.map(([key, title, hint]) => `
<section class="panel chart-panel${key === "density" ? " wide" : ""}">
<div class="chart-head"><h3>${esc(title)}</h3>${hint ? `<span class="chart-hint">${esc(hint)}</span>` : ""}</div>
<div class="skeleton chart-skel" id="skel-${key}"></div>
<div class="chart-holder" id="chart-${key}" hidden></div>
</section>`).join("")}
</div>
</div>`;
  await load(content);
}

function reset(content) {
  page.from = "";
  page.to = "";
  load(content);
}

async function load(content) {
  for (const [key] of PANELS) {
    content.querySelector("#skel-" + key).hidden = false;
    content.querySelector("#chart-" + key).hidden = true;
  }
  let data;
  try {
    data = await api.chartsDashboard({ evidence_id: page.evidenceId, from: page.from, to: page.to });
  } catch (err) {
    for (const [key] of PANELS) {
      content.querySelector("#skel-" + key).hidden = true;
      const holder = content.querySelector("#chart-" + key);
      holder.hidden = false;
      holder.innerHTML = '<p class="hint">Could not load charts: ' + esc(err.message) + ". If the server was just updated, restart it and try again.</p>";
    }
    return;
  }
  renderTiles(content, data.totals);
  renderRange(content);

  const show = (key) => {
    content.querySelector("#skel-" + key).hidden = true;
    const holder = content.querySelector("#chart-" + key);
    holder.hidden = false;
    return holder;
  };
  const p = palette();

  lineChart(show("density"), data.density.map((d) => ({ x: Date.parse(d.day), y: d.count })), {
    onBrush: (lo, hi) => {
      page.from = toDay(lo);
      page.to = toDay(hi);
      load(content);
    },
  });

  scatter(show("sifn"), data.si_fn.map((d) => ({ x: Date.parse(d.si), y: Date.parse(d.fnc), flag: d.stomp })), {
    diagonal: true,
    xLabel: "SI creation",
    yLabel: "FN creation",
  });

  scatter(show("record"), data.record_scatter.map((d) => ({ x: d.entry, y: Date.parse(d.si), flag: false })), {
    xLabel: "Record number",
    yLabel: "SI creation",
  });

  barChart(show("subsecond"), data.subsecond.map((count, i) => ({
    label: "." + i,
    value: count,
    color: i === 0 ? p.bad : p.accent,
  })));

  heatmap(show("heatmap"), data.heatmap);

  barChart(show("extensions"), data.extensions.map((d) => ({ label: d.name, value: d.count })));

  barChart(show("severity"), [
    { label: "High", value: data.totals.high, color: p.bad },
    { label: "Medium", value: data.totals.medium, color: p.warn },
    { label: "Low", value: data.totals.low, color: p.accent },
  ]);

  barChart(show("rules"), data.rules.map((d) => ({ label: d.name, value: d.count })));
}

function renderTiles(content, t) {
  const tiles = [
    ["Records", t.records],
    ["Deleted", t.deleted],
    ["Alternate streams", t.ads],
    ["Orphans", t.orphans],
    ["High findings", t.high],
    ["Medium findings", t.medium],
  ];
  content.querySelector("#g-tiles").innerHTML = tiles
    .map(([label, value]) => `<div class="tile"><span class="tile-value">${Number(value).toLocaleString()}</span><span class="tile-label">${esc(label)}</span></div>`)
    .join("");
}

function renderRange(content) {
  const bar = content.querySelector("#g-range");
  if (page.from || page.to) {
    bar.innerHTML = `<span class="range-note">Range ${esc(page.from)} to ${esc(page.to)}</span><button type="button" class="btn ghost small" id="g-reset">Reset range</button>`;
    bar.querySelector("#g-reset").addEventListener("click", () => reset(content));
  } else {
    bar.innerHTML = `<span class="range-note">Showing all time</span>`;
  }
}

function toDay(ms) {
  try {
    return new Date(ms).toISOString().slice(0, 10);
  } catch (e) {
    return "";
  }
}
