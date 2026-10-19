import { state, loadBoot, refreshCase, el } from "/js/state.js";
import { addRoute, addCasePage, setNotFound, startRouter, replace, currentPath, go, caseSlug } from "/js/router.js";
import { api } from "/js/api.js";
import { icon } from "/js/icons.js";
import { openPalette, paletteOpen } from "/js/ui/palette.js";
import * as tz from "/js/timezone.js";
import { render as renderSetup } from "/js/pages/setup.js";
import { render as renderCase } from "/js/pages/caseview.js";
import { render as renderHome } from "/js/pages/home.js";
import { render as renderExplore } from "/js/pages/explore.js";
import { render as renderFindings } from "/js/pages/findings.js";
import { render as renderGraph } from "/js/pages/linkgraph.js";
import { render as renderTime } from "/js/pages/timeanalyze.js";
import { render as renderJournal } from "/js/pages/journal.js";
import { render as renderGuide } from "/js/pages/guide.js";
import { render as renderSamples } from "/js/pages/samples.js";
import { render as renderLogs } from "/js/pages/logs.js";
import { openPanel } from "/js/ui/side-panel.js";

function applyTheme(theme) {
  state.theme = theme;
  document.documentElement.setAttribute("data-theme", theme);
  updateThemeButton();
}

function updateThemeButton() {
  const btn = el("btn-theme");
  if (!btn) {
    return;
  }
  const toLight = state.theme === "dark";
  btn.innerHTML = icon(toLight ? "sun" : "moon");
  btn.title = toLight ? "Switch to light theme" : "Switch to dark theme";
}

async function toggleTheme() {
  const next = state.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  const s = state.boot.settings;
  s.theme = next;
  try {
    await api.setup({
      storage_mode: s.storage_mode,
      cases_dir: s.cases_dir,
      analyst: s.analyst,
      organization: s.organization,
      default_timezone: s.default_timezone,
      downgrade_cloud_sync: s.downgrade_cloud_sync,
      encrypt_new_vaults: s.encrypt_new_vaults,
      auto_shutdown_seconds: s.auto_shutdown_seconds,
      theme: next,
    });
  } catch (e) {
    void e;
  }
}

function buildActions() {
  const nav = (path) => () => go(path);
  return [
    { label: "Home", keywords: "start about landing", hint: "page", run: nav("/home") },
    { label: "Overview", keywords: "case home", hint: "page", run: nav("/case") },
    { label: "Add evidence", keywords: "upload parse mft bodyfile", hint: "page", run: nav("/logs") },
    { label: "Explore records", keywords: "table search records", hint: "page", run: nav("/explore") },
    { label: "Findings", keywords: "detections timestomp", hint: "page", run: nav("/findings") },
    { label: "Graph", keywords: "anatomy ntfs", hint: "page", run: nav("/graphs") },
    { label: "Time analyze", keywords: "timeline macb bodyfile", hint: "page", run: nav("/time") },
    { label: "Journal", keywords: "usn usnjrnl change journal", hint: "page", run: nav("/journal") },
    { label: "Guide", keywords: "help docs how", hint: "panel", run: () => openPanel("guide") },
    { label: "Samples", keywords: "download sample cases", hint: "page", run: nav("/samples") },
    { label: "Open cases", keywords: "switch create case", hint: "panel", run: () => openPanel("cases", () => updateTopbar()) },
    { label: "Collect", keywords: "acquire live volume mft usnjrnl secure raw", hint: "panel", run: () => openPanel("collect", () => updateTopbar()) },
    { label: "Settings", keywords: "preferences analyst timezone", hint: "panel", run: () => openPanel("settings", () => applyTheme(state.theme)) },
    { label: "Toggle theme", keywords: "dark light appearance", hint: "action", run: () => toggleTheme() },
  ];
}

function updateTopbar() {
  const chip = el("case-chip");
  if (state.caseOpen && state.caseInfo) {
    chip.hidden = false;
    chip.textContent = state.caseInfo.name;
  } else {
    chip.hidden = true;
  }
}

async function homeHandler(view) {
  await refreshCase();
  updateTopbar();
  if (!state.boot.setup_complete) {
    replace("/setup");
    return;
  }
  if (state.caseOpen) {
    replace("/case/" + caseSlug() + "/overview");
    return;
  }
  await renderHome(view);
}

function guard(handler, needsCase) {
  return async (view) => {
    await refreshCase();
    updateTopbar();
    if (!state.boot.setup_complete && currentPath() !== "/setup") {
      replace("/setup");
      return;
    }
    if (needsCase && !state.caseOpen) {
      replace("/");
      return;
    }
    await handler(view);
  };
}

async function boot() {
  await loadBoot();
  applyTheme(state.theme);
  tz.setZone(state.boot.settings.default_timezone || "UTC");

  el("btn-home").addEventListener("click", () => go("/home"));
  el("btn-guide").addEventListener("click", () => openPanel("guide"));
  el("btn-samples").addEventListener("click", () => go("/samples"));
  el("btn-theme").addEventListener("click", () => toggleTheme());
  el("btn-palette").innerHTML = icon("search");
  el("btn-palette").addEventListener("click", () => openPalette(buildActions()));
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      if (!paletteOpen()) {
        openPalette(buildActions());
      }
    }
  });
  updateThemeButton();
  el("btn-cases").addEventListener("click", () => openPanel("cases", () => { updateTopbar(); }));
  el("btn-collect").addEventListener("click", () => openPanel("collect", () => { updateTopbar(); }));
  el("btn-settings").addEventListener("click", () => openPanel("settings", () => {
    applyTheme(state.theme);
    if (currentPath().endsWith("/explore")) {
      renderExplore(el("view"));
    }
  }));
  el("case-chip").addEventListener("click", () => go("/case"));
  window.addEventListener("case-changed", () => { updateTopbar(); });

  addRoute("/setup", renderSetup);
  addRoute("/", homeHandler);
  addRoute("/home", guard(renderHome, false));
  addRoute("/guide", renderGuide);
  addRoute("/samples", renderSamples);
  addCasePage("overview", guard(renderCase, true));
  addCasePage("evidence", guard(renderLogs, true));
  addCasePage("explore", guard(renderExplore, true));
  addCasePage("findings", guard(renderFindings, true));
  addCasePage("graph", guard(renderGraph, true));
  addCasePage("time-analyze", guard(renderTime, true));
  addCasePage("journal", guard(renderJournal, true));
  setNotFound(homeHandler);

  updateTopbar();
  startRouter();
}

boot().catch((e) => {
  document.body.textContent = "Startup failed: " + e.message;
});
