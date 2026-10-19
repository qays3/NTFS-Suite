import { renderCasesPanel } from "/js/pages/cases.js";
import { renderSettingsPanel } from "/js/pages/settings.js";
import { renderGuidePanel } from "/js/pages/guide.js";
import { renderCollectPanel } from "/js/pages/collect.js";

let current = null;

const TITLES = { guide: "Guide", settings: "Settings", cases: "Cases", collect: "Collect" };

export function panelKind() {
  return current ? current.kind : null;
}

export function closePanel() {
  if (!current) {
    return;
  }
  document.removeEventListener("keydown", current.onKey);
  current.panel.remove();
  document.body.classList.remove("panel-open");
  syncTabs(null);
  current = null;
}

export function openPanel(kind, onChange) {
  if (current && current.kind === kind) {
    closePanel();
    return;
  }
  closePanel();
  const panel = document.createElement("aside");
  panel.className = "side-panel";
  panel.innerHTML = `
<div class="sp-head"><span class="sp-title">${TITLES[kind] || ""}</span><button type="button" class="btn ghost small sp-close">Close</button></div>
<div class="sp-body" id="sp-body"><div class="skeleton" style="height:220px"></div></div>`;
  document.body.appendChild(panel);
  document.body.classList.add("panel-open");
  const onKey = (e) => {
    if (e.key === "Escape") {
      closePanel();
    }
  };
  document.addEventListener("keydown", onKey);
  panel.querySelector(".sp-close").addEventListener("click", () => closePanel());
  current = { panel, kind, onKey };
  syncTabs(kind);
  const body = panel.querySelector("#sp-body");
  if (kind === "guide") {
    renderGuidePanel(body);
  } else if (kind === "settings") {
    renderSettingsPanel(body, onChange, closePanel);
  } else if (kind === "cases") {
    renderCasesPanel(body, onChange, closePanel);
  } else if (kind === "collect") {
    renderCollectPanel(body, onChange, closePanel);
  }
}

function syncTabs(kind) {
  const map = { cases: "btn-cases", collect: "btn-collect", settings: "btn-settings", guide: "btn-guide" };
  for (const [k, id] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el) {
      el.classList.toggle("active", k === kind);
    }
  }
}
