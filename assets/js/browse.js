import { api } from "/js/api.js";

const el = (id) => document.getElementById(id);

export function wireBrowse(root) {
  const scope = root || document;
  for (const btn of scope.querySelectorAll("[data-browse]")) {
    if (btn.dataset.wired === "1") {
      continue;
    }
    btn.dataset.wired = "1";
    btn.addEventListener("click", async () => {
      const targetId = btn.getAttribute("data-browse");
      const kind = btn.getAttribute("data-dirs") === "1" ? "folder" : "file";
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Opening";
      try {
        const res = await api.pick(kind);
        if (res.path) {
          setValue(targetId, res.path);
        } else if (!res.supported) {
          fallback(targetId, kind);
        }
      } catch (e) {
        void e;
        fallback(targetId, kind);
      } finally {
        btn.disabled = false;
        btn.textContent = original;
      }
    });
  }
  bindModalOnce();
}

function setValue(targetId, value) {
  const input = el(targetId);
  if (input) {
    input.value = value;
    input.dispatchEvent(new Event("change"));
  }
}

let onPick = null;
let dirsOnly = false;
let currentPath = "";
let modalBound = false;

function bindModalOnce() {
  if (modalBound) {
    return;
  }
  modalBound = true;
  el("browse-close").addEventListener("click", closeModal);
  el("browse-up").addEventListener("click", () => {
    const parent = el("browse-up").dataset.parent;
    if (parent) {
      loadModal(parent);
    }
  });
  el("browse-select").addEventListener("click", () => {
    if (currentPath) {
      finishModal(currentPath);
    }
  });
}

function fallback(targetId, kind) {
  dirsOnly = kind === "folder";
  onPick = (picked) => setValue(targetId, picked);
  el("browse-title").textContent = dirsOnly ? "Select a folder" : "Select a file";
  el("browse-select").hidden = !dirsOnly;
  el("browse-modal").hidden = false;
  loadModal("");
}

function closeModal() {
  el("browse-modal").hidden = true;
  onPick = null;
}

function finishModal(value) {
  if (onPick) {
    onPick(value);
  }
  closeModal();
}

async function loadModal(path) {
  const data = await api.browse(path);
  currentPath = data.path;
  el("browse-current").textContent = data.path;
  const roots = el("browse-roots");
  roots.innerHTML = "";
  for (const r of data.roots) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "root-chip";
    b.textContent = r;
    b.addEventListener("click", () => loadModal(r));
    roots.appendChild(b);
  }
  const list = el("browse-list");
  list.innerHTML = "";
  for (const entry of data.entries) {
    const li = document.createElement("li");
    li.className = entry.is_dir ? "b-dir" : "b-file";
    li.textContent = (entry.is_dir ? "[ ] " : "    ") + entry.name;
    li.addEventListener("click", () => {
      if (entry.is_dir) {
        loadModal(entry.path);
      } else if (!dirsOnly) {
        finishModal(entry.path);
      }
    });
    list.appendChild(li);
  }
  el("browse-up").dataset.parent = data.parent || "";
}
