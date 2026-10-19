import { api } from "/js/api.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";

function pivot(term) {
  try {
    sessionStorage.setItem("focus_explore_search", term);
  } catch (e) {
    void e;
  }
  go("/explore");
}

function leaf(path) {
  const parts = String(path || "").replace(/\//g, "\\").split("\\").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path || "");
}

const STATUS_LABEL = {
  resolved: "in this image",
  external: "external / UNC",
  unresolved: "not in this image",
};

export async function mountChain(pane, evidenceId, alive) {
  let data;
  try {
    data = await api.graphChains(evidenceId);
  } catch (err) {
    if (alive && !alive()) {
      return;
    }
    pane.innerHTML = `<section class="panel"><p class="hint">Could not load link chains: ${esc(err.message)}. If the server was just updated, restart it and try again.</p></section>`;
    return;
  }
  if (alive && !alive()) {
    return;
  }

  const stale = data.records_total > 0 && data.reparse_total === 0 && data.hardlink_total === 0;
  const banner = stale
    ? `<div class="reparse-note">This evidence was parsed before link data was captured. Reparse points and hard links read from the $MFT only after v0.7. Remove the $MFT from the Overview and add it again to populate this tab.</div>`
    : "";

  const tiles = [
    ["Reparse points", data.reparse_total],
    ["Hard-linked files", data.hardlink_total],
    ["Risky links", data.links.filter((l) => l.risk).length],
  ];

  pane.innerHTML = `
${banner}
<p class="muted lc-intro">Reparse points (junctions, symbolic links, mount points) and hard links are the two ways NTFS makes one path point at another file or location. Timestomping aside, attackers use them to redirect trusted paths or hide a second name for a file.</p>
<div class="tiles lc-tiles">${tiles
    .map(([label, value]) => `<div class="tile"><span class="tile-value">${Number(value).toLocaleString()}</span><span class="tile-label">${esc(label)}</span></div>`)
    .join("")}</div>

<section class="panel lc-panel">
<div class="chart-head"><h3>Reparse points</h3><span class="chart-hint">Each row redirects a path to a target. Click a name to open it in Explore.</span></div>
<div id="lc-reparse"></div>
</section>

<section class="panel lc-panel">
<div class="chart-head"><h3>Hard-linked files</h3><span class="chart-hint">One MFT record reachable under more than one name. All names share the same data and timestamps.</span></div>
<div id="lc-hard"></div>
</section>`;

  renderReparse(pane.querySelector("#lc-reparse"), data);
  renderHard(pane.querySelector("#lc-hard"), data);
}

function statusChip(status) {
  const label = STATUS_LABEL[status] || status;
  return `<span class="lc-chip lc-${esc(status)}">${esc(label)}</span>`;
}

function renderReparse(host, data) {
  if (!data.links.length) {
    host.innerHTML = `<p class="muted">No reparse points in this image.</p>`;
    return;
  }
  const rows = data.links
    .map((l) => {
      const srcCell = `<button type="button" class="lc-link" data-term="${esc(l.source_name)}" title="${esc(l.source_path)}">${esc(l.source_name || "(unnamed)")}</button>${l.deleted ? ' <span class="lc-chip lc-unresolved">deleted</span>' : ""}<div class="lc-sub">${esc(l.source_path)}</div>`;
      const tgtName = leaf(l.target_raw);
      const tgtCell = l.target_entry !== null && l.target_entry !== undefined
        ? `<button type="button" class="lc-link" data-term="${esc(tgtName)}" title="${esc(l.target_path)}">${esc(l.target_raw)}</button><div class="lc-sub">${esc(l.target_path)}</div>`
        : `<span class="lc-target-raw">${esc(l.target_raw || "(empty)")}</span>`;
      return `<tr>
<td>${srcCell}</td>
<td><span class="lc-tag">${esc(l.tag_name)}</span><div class="lc-sub mono">${esc(l.tag)}</div></td>
<td>${tgtCell}</td>
<td>${statusChip(l.status)}</td>
<td>${l.risk ? '<span class="lc-chip lc-risk">risk</span>' : ""}</td>
</tr>`;
    })
    .join("");
  host.innerHTML = `
<div class="table-wrap">
<table class="data-table lc-table">
<thead><tr><th>Source</th><th>Type</th><th>Target</th><th>Target status</th><th></th></tr></thead>
<tbody>${rows}</tbody>
</table>
</div>
${data.reparse_total > data.links.length ? `<p class="hint">Showing the first ${data.links.length.toLocaleString()} of ${data.reparse_total.toLocaleString()} reparse points.</p>` : ""}`;
  wirePivots(host);
}

function renderHard(host, data) {
  if (!data.hardlinks.length) {
    host.innerHTML = `<p class="muted">No files with more than one hard link in this image.</p>`;
    return;
  }
  const rows = data.hardlinks
    .map((h) => `<tr>
<td><button type="button" class="lc-link" data-term="${esc(h.name)}" title="${esc(h.path)}">${esc(h.name || "(unnamed)")}</button>${h.deleted ? ' <span class="lc-chip lc-unresolved">deleted</span>' : ""}<div class="lc-sub">${esc(h.path)}</div></td>
<td class="mono">${esc(String(h.entry))}</td>
<td><span class="lc-count">${Number(h.count).toLocaleString()} names</span></td>
</tr>`)
    .join("");
  host.innerHTML = `
<div class="table-wrap">
<table class="data-table lc-table">
<thead><tr><th>File</th><th>Record</th><th>Hard links</th></tr></thead>
<tbody>${rows}</tbody>
</table>
</div>
${data.hardlink_total > data.hardlinks.length ? `<p class="hint">Showing the first ${data.hardlinks.length.toLocaleString()} of ${data.hardlink_total.toLocaleString()} hard-linked files.</p>` : ""}
<p class="hint">The $MFT stores a file's hard-link count but not every name. Enumerating all names for a record needs the $Secure / directory index walk that a later version will add.</p>`;
  wirePivots(host);
}

function wirePivots(host) {
  for (const btn of host.querySelectorAll(".lc-link")) {
    btn.addEventListener("click", () => {
      const term = btn.getAttribute("data-term");
      if (term) {
        pivot(term);
      }
    });
  }
}
