import { api } from "/js/api.js";

export const state = {
  boot: null,
  caseOpen: false,
  caseInfo: null,
  evidence: [],
  theme: "dark",
};

export async function loadBoot() {
  state.boot = await api.bootstrap();
  state.theme = state.boot.settings.theme || "dark";
}

export async function refreshCase() {
  try {
    state.caseInfo = await api.caseState();
    state.caseOpen = true;
    state.evidence = state.caseInfo.evidence || [];
  } catch (e) {
    void e;
    state.caseOpen = false;
    state.caseInfo = null;
    state.evidence = [];
  }
}

export function el(id) {
  return document.getElementById(id);
}

export function clear(node) {
  node.innerHTML = "";
}
