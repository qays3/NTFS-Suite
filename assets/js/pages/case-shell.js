import { api } from "/js/api.js";
import { state, refreshCase } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { confirmDialog } from "/js/ui/modal.js";

export function caseShell(view, active) {
  const info = state.caseInfo;
  view.classList.add("full");
  view.innerHTML = `
<div class="case-bar">
<div class="case-id">
<span class="case-title">${esc(info.name)}</span>
<span class="tag">${esc(info.display_timezone)}</span>
</div>
<button type="button" class="icon-btn danger case-close" id="case-x" title="Delete case">${icon("cancel")}</button>
</div>
<nav class="case-tabs">
<a href="/case" data-link class="ctab" data-k="overview">Overview</a>
<a href="/explore" data-link class="ctab" data-k="explore">Explore</a>
<a href="/graphs" data-link class="ctab" data-k="graph">Graph</a>
<a href="/time" data-link class="ctab" data-k="time">Time analyze</a>
<a href="/journal" data-link class="ctab" data-k="journal">Journal</a>
<a href="/findings" data-link class="ctab" data-k="findings">Findings</a>
<a href="/logs" data-link class="ctab" data-k="logs">Add evidence</a>
</nav>
<div class="case-content" id="case-content"></div>`;
  for (const t of view.querySelectorAll(".ctab")) {
    t.classList.toggle("active", t.getAttribute("data-k") === active);
  }
  view.querySelector("#case-x").addEventListener("click", async () => {
    const ok = await confirmDialog("Delete case " + info.name + "? This removes the vault file.", "Delete");
    if (ok) {
      try {
        await api.deleteCase(info.file);
        await refreshCase();
        window.dispatchEvent(new CustomEvent("case-changed"));
        go("/");
      } catch (err) {
        view.querySelector("#case-content").insertAdjacentHTML("afterbegin", '<p class="hint">Delete failed: ' + esc(err.message) + "</p>");
      }
    }
  });
  return view.querySelector("#case-content");
}
