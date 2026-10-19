import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { openPanel } from "/js/ui/side-panel.js";
import { caseShell } from "/js/pages/case-shell.js";

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    view.innerHTML = `
<section class="empty-state">
<h2>No case open</h2>
<p class="muted">Open an existing case or create a new one to begin.</p>
<button type="button" class="btn" id="es-open">${icon("list")} Open Cases</button>
</section>`;
    view.querySelector("#es-open").addEventListener("click", () => openPanel("cases"));
    return;
  }
  const info = state.caseInfo;
  const content = caseShell(view, "overview");
  const parsedEvidence = state.evidence.find((e) => e.status === "parsed");
  const parsed = state.evidence.filter((e) => e.status === "parsed").length;
  content.innerHTML = `
<section class="panel">
<h3>Case overview</h3>
<div class="meta-grid">
<div><span class="meta-label">Case number</span><span class="meta-value">${esc(info.number) || "-"}</span></div>
<div><span class="meta-label">Created</span><span class="meta-value">${esc(info.created_utc || "-")}</span></div>
<div><span class="meta-label">Evidence</span><span class="meta-value">${state.evidence.length} (${parsed} parsed)</span></div>
<div><span class="meta-label">Vault file</span><span class="meta-value mono">${esc(info.file)}</span></div>
</div>
<div class="row-end">
<button type="button" class="btn" id="cv-add">${icon("plus")} Add evidence</button>
<button type="button" class="btn ghost" id="cv-explore">${icon("grid")} Explore</button>
</div>
</section>
${parsedEvidence ? `
<section class="panel">
<h3>Reports and exports</h3>
<p class="muted">The report opens in a new tab to print or save as PDF. Exports download as files. Times are UTC unless noted.</p>
<div class="export-grid">
<button type="button" class="btn" id="cv-report">${icon("download")} Findings report (HTML)</button>
<button type="button" class="btn ghost" id="cv-report-json">${icon("download")} Report (JSON)</button>
<button type="button" class="btn ghost" id="cv-bodyfile">${icon("download")} Bodyfile</button>
<button type="button" class="btn ghost" id="cv-timeline">${icon("download")} Timeline CSV</button>
<button type="button" class="btn ghost" id="cv-ioc">${icon("download")} IOC list</button>
</div>
</section>` : ""}`;
  content.querySelector("#cv-add").addEventListener("click", () => go("/logs"));
  content.querySelector("#cv-explore").addEventListener("click", () => go("/explore"));
  if (parsedEvidence) {
    const id = parsedEvidence.id;
    content.querySelector("#cv-report").addEventListener("click", () => window.open("/api/report?evidence_id=" + id + "&format=html", "_blank"));
    content.querySelector("#cv-report-json").addEventListener("click", () => download("/api/report?evidence_id=" + id + "&format=json"));
    content.querySelector("#cv-bodyfile").addEventListener("click", () => download("/api/export/bodyfile?evidence_id=" + id));
    content.querySelector("#cv-timeline").addEventListener("click", () => download("/api/export/timeline?evidence_id=" + id));
    content.querySelector("#cv-ioc").addEventListener("click", () => download("/api/export/ioc?evidence_id=" + id));
  }
}

function download(url) {
  const a = document.createElement("a");
  a.href = url;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
