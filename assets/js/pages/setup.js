import { api } from "/js/api.js";
import { state, loadBoot } from "/js/state.js";
import { wireBrowse } from "/js/browse.js";
import { go } from "/js/router.js";

export async function render(view) {
  const boot = state.boot;
  view.innerHTML = `
<section class="panel narrow">
<h2>First run setup</h2>
<label>Analyst name<input id="su-analyst" type="text" value="${esc(boot.settings.analyst)}"></label>
<label>Organization<input id="su-org" type="text" value="${esc(boot.settings.organization)}"></label>
<label>Cases folder<span class="input-row"><input id="su-cases" type="text" value="${esc(boot.settings.cases_dir || boot.default_cases_dir)}"><button type="button" class="btn ghost small" data-browse="su-cases" data-dirs="1">Browse</button></span></label>
<label>Default time zone<input id="su-tz" type="text" value="${esc(boot.settings.default_timezone || "UTC")}"></label>
<label class="chk"><input type="checkbox" id="su-cloud" checked>Downgrade findings in cloud sync folders</label>
<div class="row-end"><button type="button" class="btn" id="su-save">Finish setup</button></div>
<p class="hint" id="su-error"></p>
</section>`;
  wireBrowse(view);
  view.querySelector("#su-save").addEventListener("click", async () => {
    view.querySelector("#su-error").textContent = "";
    try {
      await api.setup({
        storage_mode: "portable",
        cases_dir: view.querySelector("#su-cases").value,
        analyst: view.querySelector("#su-analyst").value,
        organization: view.querySelector("#su-org").value,
        default_timezone: view.querySelector("#su-tz").value || "UTC",
        downgrade_cloud_sync: view.querySelector("#su-cloud").checked,
        encrypt_new_vaults: false,
        auto_shutdown_seconds: 900,
        theme: state.theme,
      });
      await loadBoot();
      go("/");
    } catch (e) {
      view.querySelector("#su-error").textContent = "Setup failed: " + e.message;
    }
  });
}

export function esc(value) {
  return String(value || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
