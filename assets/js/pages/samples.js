import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";

export async function render(view) {
  view.classList.add("full");
  view.innerHTML = `
<div class="samples">
<div class="samples-head">
<div>
<h2>Samples</h2>
<p class="muted">Public sample cases you can download and load. The tool does not fetch them for you. Download the files from the links here, then add them to a case from the Add evidence page.</p>
</div>
<a class="btn ghost small" id="sm-repo" target="_blank" rel="noreferrer">${icon("list")} Repository</a>
</div>
<div class="skeleton" id="sm-skel" style="height:220px"></div>
<div id="sm-body" hidden></div>
</div>`;

  const body = view.querySelector("#sm-body");
  const skel = view.querySelector("#sm-skel");
  let idx = null;
  try {
    const res = await fetch("/samples-index.json", { cache: "no-store" });
    if (!res.ok) {
      throw new Error(String(res.status));
    }
    idx = await res.json();
  } catch (e) {
    skel.hidden = true;
    body.hidden = false;
    body.innerHTML = `<p class="muted">Could not read the samples index. ${esc(e.message || "")}</p>`;
    return;
  }

  const repo = idx.repo || "https://github.com/qays3/NTFS-Suite";
  view.querySelector("#sm-repo").href = repo;
  const cases = Array.isArray(idx.cases) ? idx.cases : [];
  skel.hidden = true;
  body.hidden = false;

  if (cases.length === 0) {
    body.innerHTML = `
<section class="panel subtle">
<h3>No public samples yet</h3>
<p class="muted">When sample cases are published to the repository they appear here, each with its files, sizes and download links.</p>
</section>`;
    return;
  }

  body.innerHTML = cases.map((c) => caseCard(idx, c)).join("");
}

function caseCard(idx, c) {
  const files = Array.isArray(c.files) ? c.files : [];
  const rows = files.map((f) => fileRow(idx, c, f)).join("");
  const bundle = c.bundle && c.bundle.url
    ? `<div class="sm-bundle"><a class="btn ghost small" href="${esc(c.bundle.url)}" target="_blank" rel="noreferrer">${icon("download")} ${esc(c.bundle.name || "Download bundle")}${c.bundle.size ? " (" + esc(fmtBytes(c.bundle.size)) + ")" : ""}</a></div>`
    : "";
  return `
<section class="panel sm-case">
<div class="sm-case-head">
<h3>${esc(c.name || c.dir || "Sample case")}</h3>
${c.number ? `<span class="tag">${esc(c.number)}</span>` : ""}
</div>
${c.description ? `<p class="muted">${esc(c.description)}</p>` : ""}
<table class="data-table dense sm-files">
<thead><tr><th>File</th><th>Size</th><th>Download</th><th>View</th></tr></thead>
<tbody>${rows || '<tr><td colspan="4" class="muted">No files listed.</td></tr>'}</tbody>
</table>
${bundle}
</section>`;
}

function fileRow(idx, c, f) {
  const raw = f.raw || buildUrl(idx, c, f, "raw");
  const viewUrl = f.view || buildUrl(idx, c, f, "blob");
  return `<tr>
<td class="mono">${esc(f.name)}${f.note ? `<span class="sm-note">${esc(f.note)}</span>` : ""}</td>
<td>${f.size ? esc(fmtBytes(f.size)) : ""}</td>
<td><a href="${esc(raw)}" target="_blank" rel="noreferrer" download>${icon("download")} Download</a></td>
<td><a href="${esc(viewUrl)}" target="_blank" rel="noreferrer">View</a></td>
</tr>`;
}

function buildUrl(idx, c, f, kind) {
  const repo = idx.repo || "https://github.com/qays3/NTFS-Suite";
  const branch = idx.branch || "main";
  const dir = idx.samples_dir || "samples";
  const parts = [dir, c.dir, f.name].filter(Boolean).map(encodeURIComponent).join("/");
  return repo + "/" + kind + "/" + branch + "/" + parts;
}

function fmtBytes(n) {
  if (n < 1024) {
    return n + " B";
  }
  const units = ["KB", "MB", "GB", "TB"];
  let i = -1;
  let v = n;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(1) + " " + units[i];
}
