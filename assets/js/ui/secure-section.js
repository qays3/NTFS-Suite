import { api } from "/js/api.js";

const ATTR_FLAGS = [
  [0x1, "read only"],
  [0x2, "hidden"],
  [0x4, "system"],
  [0x10, "directory"],
  [0x20, "archive"],
  [0x100, "temporary"],
  [0x200, "sparse"],
  [0x400, "reparse point"],
  [0x800, "compressed"],
  [0x1000, "offline"],
  [0x2000, "not indexed"],
  [0x4000, "encrypted"],
];

export function fileAttrText(flags) {
  const f = Number(flags) || 0;
  const names = ATTR_FLAGS.filter(([bit]) => (f & bit) !== 0).map(([, n]) => n);
  return names.length ? names.join(", ") : "none";
}

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Fetch the security descriptor for a record and render an owner/permissions
// section into `container`. `query` is { security_id } or { entry }.
export async function renderSecureSection(container, query) {
  if (!container) {
    return;
  }
  container.innerHTML = '<div class="sec-note">Looking up $Secure…</div>';
  let d;
  try {
    d = await api.secureLookup(query);
  } catch (e) {
    void e;
    container.innerHTML = "";
    return;
  }
  if (!d) {
    container.innerHTML = '<div class="detail-sub">$Secure</div><div class="sec-note">No $Secure is loaded, or this record has no security id. Add a $Secure to resolve the owner and permissions.</div>';
    return;
  }
  const owner = d.owner_name ? `${d.owner_name} (${d.owner_sid})` : d.owner_sid || "unknown";
  const group = d.group_name ? `${d.group_name} (${d.group_sid})` : d.group_sid || "unknown";
  const rows = [
    ["Security id", d.security_id],
    ["Owner", owner],
    ["Group", group],
    ["Permissions", `${d.allow_count} allow, ${d.deny_count} deny (${d.ace_count} entries)`],
  ];
  container.innerHTML = `<div class="detail-sub">$Secure · owner and permissions</div><dl class="detail-list sec-list">${rows
    .map(([k, v]) => `<div class="detail-row"><dt>${esc(k)}</dt><dd>${esc(String(v))}</dd></div>`)
    .join("")}</dl>`;
}
