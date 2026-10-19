import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { GUIDE } from "/js/content/guide.js";

export function render(view) {
  view.classList.add("full");
  view.innerHTML = `
<div class="guide">
<aside class="guide-side">
<div class="guide-brand">Guide</div>
<nav class="guide-tabs" id="guide-tabs">
${GUIDE.map((s, i) => `<button type="button" class="guide-tab${i === 0 ? " on" : ""}" data-sec="${esc(s.id)}">${esc(s.title)}</button>`).join("")}
</nav>
</aside>
<div class="guide-panel" id="guide-panel"></div>
</div>`;

  const panel = view.querySelector("#guide-panel");
  const show = (id) => {
    const s = GUIDE.find((x) => x.id === id) || GUIDE[0];
    panel.innerHTML = `<div class="guide-sec"><h2>${esc(s.title)}</h2><p class="guide-lead">${esc(s.lead)}</p>${s.blocks.map(block).join("")}</div>`;
    panel.scrollTop = 0;
    for (const b of view.querySelectorAll(".guide-tab")) {
      b.classList.toggle("on", b.getAttribute("data-sec") === id);
    }
  };
  for (const b of view.querySelectorAll(".guide-tab")) {
    b.addEventListener("click", () => show(b.getAttribute("data-sec")));
  }
  show(GUIDE[0].id);
}

export function renderGuidePanel(container) {
  container.innerHTML = `
<div class="gp-tabs" id="gp-tabs">${GUIDE.map((s, i) => `<button type="button" class="gp-tab${i === 0 ? " on" : ""}" data-sec="${esc(s.id)}">${esc(s.title)}</button>`).join("")}</div>
<div class="guide-sec" id="gp-sec"></div>`;
  const sec = container.querySelector("#gp-sec");
  const tabs = container.querySelector("#gp-tabs");
  const show = (id) => {
    const s = GUIDE.find((x) => x.id === id) || GUIDE[0];
    sec.innerHTML = `<h2>${esc(s.title)}</h2><p class="guide-lead">${esc(s.lead)}</p>${s.blocks.map(block).join("")}`;
    sec.scrollTop = 0;
    for (const b of tabs.querySelectorAll(".gp-tab")) {
      b.classList.toggle("on", b.getAttribute("data-sec") === id);
    }
  };
  for (const b of tabs.querySelectorAll(".gp-tab")) {
    b.addEventListener("click", () => show(b.getAttribute("data-sec")));
  }
  show(GUIDE[0].id);
}

function block(b) {
  if (b.t === "h") {
    return `<h3 class="guide-h">${esc(b.v)}</h3>`;
  }
  if (b.t === "p") {
    return `<p class="guide-p">${esc(b.v)}</p>`;
  }
  if (b.t === "code") {
    return `<pre class="guide-code"><code>${esc(b.v)}</code></pre>`;
  }
  if (b.t === "steps") {
    return `<ol class="guide-steps">${b.v.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>`;
  }
  if (b.t === "list") {
    return `<ul class="guide-list">${b.v.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`;
  }
  if (b.t === "note") {
    return `<p class="guide-note">${esc(b.v)}</p>`;
  }
  return "";
}

export function openGuide() {
  go("/guide");
}
