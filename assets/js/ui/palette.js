import { esc } from "/js/pages/setup.js";

let overlay = null;

export function paletteOpen() {
  return overlay !== null;
}

export function openPalette(actions) {
  if (overlay) {
    return;
  }
  overlay = document.createElement("div");
  overlay.className = "cmdk-backdrop";
  overlay.innerHTML = `
<div class="cmdk" role="dialog" aria-modal="true">
<input class="cmdk-input" id="cmdk-input" type="text" placeholder="Type a command or page" autocomplete="off" spellcheck="false">
<ul class="cmdk-list" id="cmdk-list"></ul>
</div>`;
  document.body.appendChild(overlay);

  const input = overlay.querySelector("#cmdk-input");
  const list = overlay.querySelector("#cmdk-list");
  let filtered = actions.slice();
  let active = 0;

  const renderList = () => {
    if (filtered.length === 0) {
      list.innerHTML = '<li class="cmdk-empty">No match</li>';
      return;
    }
    list.innerHTML = filtered
      .map(
        (a, i) =>
          `<li class="cmdk-item${i === active ? " on" : ""}" data-i="${i}"><span class="cmdk-label">${esc(a.label)}</span>${a.hint ? `<span class="cmdk-hint">${esc(a.hint)}</span>` : ""}</li>`
      )
      .join("");
  };

  const scrollActive = () => {
    const el = list.querySelector(".cmdk-item.on");
    if (el) {
      el.scrollIntoView({ block: "nearest" });
    }
  };

  const apply = () => {
    const q = input.value.trim().toLowerCase();
    filtered = q
      ? actions.filter((a) => a.label.toLowerCase().includes(q) || (a.keywords || "").toLowerCase().includes(q))
      : actions.slice();
    active = 0;
    renderList();
  };

  const run = (i) => {
    const a = filtered[i];
    if (!a) {
      return;
    }
    close();
    try {
      a.run();
    } catch (e) {
      void e;
    }
  };

  function close() {
    document.removeEventListener("keydown", onKey, true);
    if (overlay) {
      overlay.remove();
      overlay = null;
    }
  }

  function onKey(e) {
    if (e.key === "Escape") {
      e.preventDefault();
      close();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      active = Math.min(active + 1, filtered.length - 1);
      renderList();
      scrollActive();
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      active = Math.max(active - 1, 0);
      renderList();
      scrollActive();
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      run(active);
    }
  }

  input.addEventListener("input", apply);
  list.addEventListener("click", (e) => {
    const li = e.target.closest(".cmdk-item");
    if (li) {
      run(Number(li.getAttribute("data-i")));
    }
  });
  overlay.addEventListener("mousedown", (e) => {
    if (e.target === overlay) {
      close();
    }
  });
  document.addEventListener("keydown", onKey, true);

  renderList();
  input.focus();
}
