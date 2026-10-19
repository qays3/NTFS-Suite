import { api } from "/js/api.js";
import { esc } from "/js/pages/setup.js";

const WELL_KNOWN_SIDS = [
  ["S-1-5-18", "NT AUTHORITY\\SYSTEM", "The operating system account. Owns most Windows and system files."],
  ["S-1-5-19", "NT AUTHORITY\\LOCAL SERVICE", "A low privilege service account."],
  ["S-1-5-20", "NT AUTHORITY\\NETWORK SERVICE", "A service account that talks to the network as the computer."],
  ["S-1-5-80-...", "NT SERVICE\\TrustedInstaller", "Owns protected OS files under Windows, System32 and WinSxS."],
  ["S-1-5-32-544", "BUILTIN\\Administrators", "The local admins group. Common owner of installed programs."],
  ["S-1-5-32-545", "BUILTIN\\Users", "The standard users group."],
  ["S-1-5-11", "NT AUTHORITY\\Authenticated Users", "Any account that signed in."],
  ["S-1-1-0", "Everyone", "All users, including anonymous in some cases."],
  ["S-1-3-0", "CREATOR OWNER", "A placeholder swapped for whoever creates the file."],
  ["S-1-5-21-...-500", "Built-in Administrator", "The first admin account. RID 500."],
  ["S-1-5-21-...-501", "Guest", "The built-in guest account. RID 501."],
  ["S-1-5-21-...-1000+", "Local or domain users", "Real user accounts. The first created user is usually 1001."],
];

export async function mountOwnership(pane, evidenceId, alive) {
  let data;
  try {
    data = await api.graphOwnership(evidenceId);
  } catch (err) {
    if (alive && !alive()) {
      return;
    }
    pane.innerHTML = `<section class="panel"><p class="hint">Could not load ownership: ${esc(err.message)}. If the server was just updated, restart it and try again.</p></section>`;
    return;
  }
  if (alive && !alive()) {
    return;
  }

  const stale = data.total > 0 && data.with_owner === 0 && data.distinct_securities === 0;
  const banner = stale
    ? `<div class="reparse-note">This evidence was parsed before ownership was captured. Owner and security ids read from the $MFT only after v0.7. Remove the $MFT from the Overview and add it again to populate this tab.</div>`
    : "";

  const tiles = [
    ["Records", data.total],
    ["Non-zero owner id", data.with_owner],
    ["Distinct owner ids", data.distinct_owners],
    ["Distinct security ids", data.distinct_securities],
  ];

  pane.innerHTML = `
${banner}
<p class="muted">Every NTFS 3.0 $STANDARD_INFORMATION attribute carries two numbers. The owner id is the disk quota owner, an index into $Quota, and is 0 on volumes with quotas off, which is most of them. The security id indexes into $Secure, which holds the real owner, group and permissions. Until $Secure is parsed, the security id is the useful one for grouping files by who held them and spotting an id that spans places it should not.</p>
<div class="tiles ow-tiles">${tiles
    .map(([label, value]) => `<div class="tile"><span class="tile-value">${Number(value).toLocaleString()}</span><span class="tile-label">${esc(label)}</span></div>`)
    .join("")}</div>

<section class="panel ow-panel">
<div class="chart-head"><h3>Checks</h3></div>
<div class="ow-checks">${data.checks
    .map((c) => `<div class="ow-check ow-${esc(c.level)}"><span class="ow-check-label">${esc(c.label)}</span><span class="ow-check-detail">${esc(c.detail)}</span></div>`)
    .join("")}</div>
</section>

<div class="ow-grid">
<section class="panel ow-panel">
<div class="chart-head"><h3>Files by quota owner id</h3><span class="chart-hint">Usually all 0 unless disk quotas were on</span></div>
<div id="ow-owners"></div>
</section>
<section class="panel ow-panel">
<div class="chart-head"><h3>Files by security id</h3><span class="chart-hint">${data.secure_present ? "resolved to owner names from $Secure" : "add $Secure to resolve to owner names"}</span></div>
<div id="ow-sec"></div>
</section>
</div>

<details class="ow-ref">
<summary>What the ids mean, and the SIDs behind them</summary>
<p class="ow-ref-intro">The numbers above are this volume's own ids into its $Secure file, so a security id here is not the same on another disk. Once $Secure is parsed, each one resolves to a Security Identifier (SID). These are the well known SIDs you will see as file owners.</p>
<div class="table-wrap">
<table class="data-table ow-ref-table">
<thead><tr><th>SID</th><th>Who</th><th>Usually owns</th></tr></thead>
<tbody>${WELL_KNOWN_SIDS.map(([sid, who, owns]) => `<tr><td class="mono">${esc(sid)}</td><td>${esc(who)}</td><td>${esc(owns)}</td></tr>`).join("")}</tbody>
</table>
</div>
<p class="ow-ref-note">A SID ends in a RID (Relative Identifier): 500 is the built-in Administrator, 501 is Guest, and 1000 and up are the accounts created on the machine.</p>
</details>

<p class="hint ow-note">${esc(data.note)}</p>`;

  renderOwners(pane.querySelector("#ow-owners"), data);
  renderSecurities(pane.querySelector("#ow-sec"), data);
}

function idLabel(id) {
  return id === 0 ? "0 (none recorded)" : String(id);
}

function renderOwners(host, data) {
  if (!data.owners.length) {
    host.innerHTML = `<p class="muted">No owner ids recorded.</p>`;
    return;
  }
  const max = Math.max(...data.owners.map((o) => o.count), 1);
  const rows = data.owners
    .map((o) => {
      const pct = Math.round((o.count / max) * 100);
      const examples = o.examples && o.examples.length
        ? `<div class="ow-examples">${o.examples.map((p) => `<span class="ow-example" title="${esc(p)}">${esc(p)}</span>`).join("")}</div>`
        : "";
      return `<div class="ow-row">
<div class="ow-row-head"><span class="ow-id mono">${esc(idLabel(o.id))}</span><span class="ow-row-count">${Number(o.count).toLocaleString()}</span></div>
<div class="ow-bar"><span class="ow-bar-fill" style="width:${pct}%"></span></div>
${examples}
</div>`;
    })
    .join("");
  host.innerHTML = rows;
}

function renderSecurities(host, data) {
  if (!data.securities.length) {
    host.innerHTML = `<p class="muted">No security ids recorded.</p>`;
    return;
  }
  const max = Math.max(...data.securities.map((o) => o.count), 1);
  const rows = data.securities
    .map((o) => {
      const pct = Math.round((o.count / max) * 100);
      const owner = o.name
        ? `<span class="ow-owner" title="${esc(o.sid)}">${esc(o.name)}</span>`
        : "";
      return `<div class="ow-row">
<div class="ow-row-head"><span class="ow-id mono">${esc(idLabel(o.id))}${owner}</span><span class="ow-row-count">${Number(o.count).toLocaleString()}</span></div>
<div class="ow-bar"><span class="ow-bar-fill" style="width:${pct}%"></span></div>
</div>`;
    })
    .join("");
  host.innerHTML = rows;
}
