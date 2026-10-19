import { api } from "/js/api.js";
import { state, loadBoot } from "/js/state.js";
import { allZones, setZone } from "/js/timezone.js";

export function renderSettingsPanel(container, onSaved) {
  const s = state.boot.settings;
  container.innerHTML = `
<div class="subhead">Appearance</div>
<div class="seg" id="st-seg">
<button type="button" class="seg-btn" data-theme-opt="dark">Dark</button>
<button type="button" class="seg-btn" data-theme-opt="light">Light</button>
</div>
<div class="subhead">Analyst</div>
<label>Analyst name<input id="st-analyst" type="text" value="${attr(s.analyst)}"></label>
<label>Organization<input id="st-org" type="text" value="${attr(s.organization)}"></label>
<div class="subhead">Default time zone</div>
<label>Used for new cases<select id="st-tz" class="full-select"></select></label>
<div class="subhead">Storage</div>
<div class="meta-value mono">${attr(s.cases_dir)}</div>
<div class="row-end"><button type="button" class="btn small" id="st-save">Save settings</button></div>
<p class="hint" id="st-msg"></p>`;

  const seg = container.querySelector("#st-seg");
  const setSeg = (t) => {
    for (const b of seg.querySelectorAll(".seg-btn")) {
      b.classList.toggle("on", b.getAttribute("data-theme-opt") === t);
    }
  };
  setSeg(state.theme);
  for (const b of seg.querySelectorAll(".seg-btn")) {
    b.addEventListener("click", () => {
      const t = b.getAttribute("data-theme-opt");
      document.documentElement.setAttribute("data-theme", t);
      state.theme = t;
      setSeg(t);
    });
  }

  const tzSel = container.querySelector("#st-tz");
  for (const z of allZones()) {
    const opt = document.createElement("option");
    opt.value = z;
    opt.textContent = z;
    tzSel.appendChild(opt);
  }
  tzSel.value = s.default_timezone || "UTC";

  container.querySelector("#st-save").addEventListener("click", async () => {
    const msg = container.querySelector("#st-msg");
    msg.textContent = "";
    try {
      await api.setup({
        storage_mode: s.storage_mode,
        cases_dir: s.cases_dir,
        analyst: container.querySelector("#st-analyst").value,
        organization: container.querySelector("#st-org").value,
        default_timezone: tzSel.value,
        downgrade_cloud_sync: s.downgrade_cloud_sync,
        encrypt_new_vaults: s.encrypt_new_vaults,
        auto_shutdown_seconds: s.auto_shutdown_seconds,
        theme: state.theme,
      });
      await loadBoot();
      setZone(tzSel.value);
      try {
        await api.setTimezone(tzSel.value);
      } catch (e) {
        void e;
      }
      msg.className = "hint ok-text";
      msg.textContent = "Saved.";
      if (onSaved) {
        onSaved();
      }
    } catch (e) {
      msg.className = "hint";
      msg.textContent = "Save failed: " + e.message;
    }
  });
}

function attr(v) {
  return String(v || "").replace(/"/g, "&quot;");
}
