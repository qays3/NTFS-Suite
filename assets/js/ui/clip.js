import { toast } from "/js/ui/toast.js";

export function rowsToCSV(rows, columns) {
  const head = columns.map((c) => csvField(c.label)).join(",");
  const body = rows
    .map((r) => columns.map((c) => csvField(valueOf(c.get(r)))).join(","))
    .join("\n");
  return body ? head + "\n" + body : head;
}

export function rowsToJSON(rows, columns) {
  const out = rows.map((r) => {
    const o = {};
    for (const c of columns) {
      o[c.key] = c.get(r);
    }
    return o;
  });
  return JSON.stringify(out, null, 2);
}

export async function copyText(text, label) {
  const ok = await write(text);
  toast(ok ? (label || "Copied") : "Copy failed");
  return ok;
}

async function write(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) {
    void e;
  }
  return legacyWrite(text);
}

function legacyWrite(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch (e) {
    void e;
    return false;
  }
}

function valueOf(v) {
  return v === null || v === undefined ? "" : String(v);
}

function csvField(value) {
  const v = valueOf(value);
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}
