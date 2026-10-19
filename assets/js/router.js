import { api } from "/js/api.js";
import { state, refreshCase } from "/js/state.js";

const routes = [];
const casePages = {};
let notFound = null;

const SHORT_TO_KEY = {
  "/case": "overview",
  "/explore": "explore",
  "/graphs": "graph",
  "/time": "time-analyze",
  "/journal": "journal",
  "/findings": "findings",
  "/logs": "evidence",
  "/add": "evidence",
};

export function addRoute(path, handler) {
  routes.push({ path, handler });
}

export function addCasePage(key, handler) {
  casePages[key] = handler;
}

export function setNotFound(handler) {
  notFound = handler;
}

function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function slugFor(name, number) {
  let base = slugify(name) || "case";
  const n = slugify(number);
  if (n) {
    base += "-" + n;
  }
  return base;
}

export function caseSlug() {
  const info = state.caseInfo;
  return info ? slugFor(info.name, info.number) : "case";
}

function normalize(path) {
  const key = SHORT_TO_KEY[path];
  if (key && state.caseOpen && state.caseInfo) {
    return "/case/" + caseSlug() + "/" + key;
  }
  return path;
}

export function go(path) {
  const target = normalize(path);
  if (target === currentPath()) {
    render();
    return;
  }
  history.pushState({}, "", target + window.location.search);
  render();
}

export function replace(path) {
  const target = normalize(path);
  history.replaceState({}, "", target + window.location.search);
  render();
}

export function currentPath() {
  const p = window.location.pathname;
  return p === "" ? "/" : p;
}

export function startRouter() {
  window.addEventListener("popstate", render);
  document.addEventListener("click", (e) => {
    const link = e.target.closest("[data-link]");
    if (link) {
      e.preventDefault();
      go(link.getAttribute("href"));
    }
  });
  render();
}

async function ensureCase(slug) {
  if (state.caseOpen && state.caseInfo && caseSlug() === slug) {
    return;
  }
  try {
    const cases = await api.listCases();
    const match = cases.find((c) => slugFor(c.name, c.number) === slug);
    if (match) {
      await api.openCase(match.file);
      await refreshCase();
    }
  } catch (e) {
    void e;
  }
}

async function render() {
  const path = currentPath();
  const view = document.getElementById("view");
  view.className = "view";
  view.innerHTML = "";
  const parts = path.split("/").filter(Boolean);
  if (parts[0] === "case" && parts.length >= 3) {
    await ensureCase(parts[1]);
    const key = parts[2];
    const handler = casePages[key] || casePages.overview;
    if (handler) {
      await handler(view);
    }
    return;
  }
  const route = routes.find((r) => r.path === path);
  if (route) {
    await route.handler(view);
  } else if (notFound) {
    await notFound(view);
  }
}
