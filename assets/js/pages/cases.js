import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { confirmDialog } from "/js/ui/modal.js";

export function renderCasesPanel(container, onChange, close) {
  const open = state.caseOpen && state.caseInfo;
  container.innerHTML = `
${open ? `<button type="button" class="btn small panel-cta" id="mc-goto">${icon("grid")} Go to current case</button>` : ""}
<div class="seg panel-seg" id="mc-tabs"><button type="button" class="seg-btn on" data-tab="create">Create</button><button type="button" class="seg-btn" data-tab="recent">Recent cases</button></div>
<div data-panel="create">
<label>Case name<input id="mc-name" type="text" placeholder="Investigation name"></label>
<label>Case number<input id="mc-number" type="text" placeholder="Optional"></label>
<label>Notes<textarea id="mc-notes" rows="2"></textarea></label>
<div class="row-end"><button type="button" class="btn small" id="mc-create">${icon("plus")} Create case</button></div>
<p class="hint" id="mc-error"></p>
</div>
<ul class="case-list" data-panel="recent" id="mc-list" hidden><li class="muted">Loading</li></ul>`;

  if (open) {
    container.querySelector("#mc-goto").addEventListener("click", () => {
      if (close) {
        close();
      }
      go("/case");
    });
  }

  const tabs = container.querySelector("#mc-tabs");
  for (const tab of tabs.querySelectorAll(".seg-btn")) {
    tab.addEventListener("click", () => {
      const name = tab.getAttribute("data-tab");
      for (const t of tabs.querySelectorAll(".seg-btn")) {
        t.classList.toggle("on", t === tab);
      }
      for (const p of container.querySelectorAll("[data-panel]")) {
        p.hidden = p.getAttribute("data-panel") !== name;
      }
      if (name === "recent") {
        loadList(container, onChange, close);
      }
    });
  }

  container.querySelector("#mc-create").addEventListener("click", async () => {
    const name = container.querySelector("#mc-name").value.trim();
    if (!name) {
      container.querySelector("#mc-error").textContent = "Enter a case name";
      return;
    }
    try {
      await api.createCase({
        name,
        number: container.querySelector("#mc-number").value,
        analyst: "",
        notes: container.querySelector("#mc-notes").value,
      });
      await refreshCase();
      if (onChange) {
        onChange();
      }
      if (close) {
        close();
      }
      go("/add");
    } catch (e) {
      container.querySelector("#mc-error").textContent = "Create failed: " + e.message;
    }
  });
}

async function loadList(container, onChange, close) {
  const list = container.querySelector("#mc-list");
  let cases = [];
  try {
    cases = await api.listCases();
  } catch (e) {
    list.innerHTML = '<li class="muted">Could not load cases</li>';
    return;
  }
  list.innerHTML = "";
  if (cases.length === 0) {
    list.innerHTML = '<li class="muted">No cases yet</li>';
    return;
  }
  const currentFile = state.caseInfo ? state.caseInfo.file : "";
  for (const c of cases) {
    const li = document.createElement("li");
    li.className = "case-item" + (c.file === currentFile ? " current" : "");
    li.innerHTML = `<div class="case-item-body"><span class="case-card-name">${esc(c.name)}${c.file === currentFile ? '<span class="tag">open</span>' : ""}</span><span class="case-card-file">${esc(c.file)}</span></div><button type="button" class="icon-btn danger" title="Delete case">${icon("cancel")}</button>`;
    li.querySelector(".case-item-body").addEventListener("click", async () => {
      await api.openCase(c.file);
      await refreshCase();
      if (onChange) {
        onChange();
      }
      if (close) {
        close();
      }
      go("/case");
    });
    li.querySelector(".icon-btn").addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await confirmDialog("Delete case " + c.name + "? This removes the vault file.", "Delete");
      if (ok) {
        try {
          await api.deleteCase(c.file);
          await refreshCase();
          await loadList(container, onChange, close);
          if (onChange) {
            onChange();
          }
        } catch (err) {
          list.insertAdjacentHTML("afterbegin", '<li class="hint">Delete failed: ' + esc(err.message) + "</li>");
        }
      }
    });
    list.appendChild(li);
  }
}
