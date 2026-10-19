import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { go } from "/js/router.js";
import { icon } from "/js/icons.js";
import { wireBrowse } from "/js/browse.js";

const TARGETS = [
  ["mft", "$MFT", "grid", "Master File Table. Every record and attribute."],
  ["usnjrnl", "$UsnJrnl $J", "list", "The change journal stream."],
  ["secure", "$Secure $SDS", "folder", "Security descriptors: owners and permissions."],
];

export async function renderCollectPanel(container, onChange, close) {
  await refreshCase();
  const hasCase = state.caseOpen && state.caseInfo;
  const caseName = hasCase ? state.caseInfo.name : "";

  container.innerHTML = `
<div class="cl">
<p class="cl-intro">Acquire NTFS artifacts straight off a live Windows volume. Reads the raw disk, so run the app as Administrator.</p>

<div class="cl-field">
<span class="cl-head">Volume</span>
<select id="cl-volume" class="cl-select"><option>Loading volumes\u2026</option></select>
<p class="cl-note" id="cl-vol-note"></p>
</div>

<div class="cl-field">
<div class="cl-head-row"><span class="cl-head">Artifacts</span><button type="button" class="cl-link" id="cl-all">Select all</button></div>
<div class="cl-opts">
${TARGETS.map(
  ([id, name, ic, desc]) =>
    `<label class="cl-opt"><input type="checkbox" class="cl-t" value="${id}" checked><span class="cl-opt-ic">${icon(
      ic
    )}</span><span class="cl-opt-text"><span class="cl-opt-name">${name}</span><span class="cl-opt-desc">${desc}</span></span></label>`
).join("")}
</div>
</div>

<div class="cl-field">
<span class="cl-head">Destination</span>
<div class="seg cl-seg" id="cl-dest">
${hasCase ? `<button type="button" class="seg-btn on" data-dest="current">Current case</button>` : ""}
<button type="button" class="seg-btn ${hasCase ? "" : "on"}" data-dest="case">New case</button>
<button type="button" class="seg-btn" data-dest="folder">Folder</button>
</div>

${
  hasCase
    ? `<div class="cl-dest-body" data-destpanel="current">
<div class="cl-current">${icon("grid")} <span>Collecting into <b>${escText(
        caseName
      )}</b>. Already-added artifacts are replaced.</span></div>
</div>`
    : ""
}

<div class="cl-dest-body" data-destpanel="case" ${hasCase ? "hidden" : ""}>
<label class="cl-lbl">Case name<input id="cl-name" type="text" placeholder="e.g. WORKSTATION-01 live"></label>
<label class="cl-lbl">Case number<input id="cl-number" type="text" placeholder="Optional"></label>
<p class="cl-note">Collected into a new vault, parsed, and opened ready to analyze.</p>
</div>

<div class="cl-dest-body" data-destpanel="folder" hidden>
<label class="cl-lbl">Folder<span class="input-row"><input id="cl-dir" type="text" placeholder="C:\\path\\to\\output"><button type="button" class="btn ghost small" data-browse="cl-dir" data-dirs="1">${icon("folder")} Browse</button></span></label>
<p class="cl-note">Raw streams are written here as files you can add to a case later.</p>
</div>
</div>

<button type="button" class="btn primary cl-go" id="cl-run">${icon("download")} Collect</button>
<p class="cl-err" id="cl-error"></p>
<div class="cl-results" id="cl-results" hidden></div>
</div>`;

  let dest = hasCase ? "current" : "case";

  const seg = container.querySelector("#cl-dest");
  for (const b of seg.querySelectorAll(".seg-btn")) {
    b.addEventListener("click", () => {
      dest = b.getAttribute("data-dest");
      for (const x of seg.querySelectorAll(".seg-btn")) {
        x.classList.toggle("on", x === b);
      }
      for (const p of container.querySelectorAll("[data-destpanel]")) {
        p.hidden = p.getAttribute("data-destpanel") !== dest;
      }
    });
  }

  container.querySelector("#cl-all").addEventListener("click", () => {
    const boxes = [...container.querySelectorAll(".cl-t")];
    const allOn = boxes.every((b) => b.checked);
    boxes.forEach((b) => (b.checked = !allOn));
  });

  wireBrowse(container);
  loadVolumes(container);

  container.querySelector("#cl-run").addEventListener("click", () =>
    runCollect(container, () => dest, false, onChange, close)
  );
}

async function loadVolumes(container) {
  const sel = container.querySelector("#cl-volume");
  const note = container.querySelector("#cl-vol-note");
  try {
    const res = await api.collectVolumes();
    if (!res.supported) {
      sel.innerHTML = `<option value="">Not available on this OS</option>`;
      note.textContent =
        "Live collection only works on Windows. On this machine, add the artifacts as files from the Add evidence page.";
      note.classList.add("warn");
      container.querySelector("#cl-run").disabled = true;
      return;
    }
    if (!res.volumes.length) {
      sel.innerHTML = `<option value="">No NTFS volumes found</option>`;
      note.textContent = "No readable NTFS volumes. Make sure the app runs as Administrator.";
      note.classList.add("warn");
      return;
    }
    sel.innerHTML = res.volumes
      .map(
        (v) =>
          `<option value="${v.letter.replace(":", "")}">${v.letter}  \u00b7  ${v.filesystem}  \u00b7  ${fmtBytes(
            v.total_bytes
          )}</option>`
      )
      .join("");
    note.textContent = "";
    note.classList.remove("warn");
  } catch (e) {
    sel.innerHTML = `<option value="">Could not list volumes</option>`;
    note.textContent = e.message;
    note.classList.add("warn");
  }
}

async function runCollect(container, destFn, replace, onChange, close) {
  const dest = destFn();
  const err = container.querySelector("#cl-error");
  const results = container.querySelector("#cl-results");
  err.textContent = "";

  const volume = container.querySelector("#cl-volume").value;
  if (!volume) {
    err.textContent = "No volume selected.";
    return;
  }
  const targets = [...container.querySelectorAll(".cl-t")]
    .filter((b) => b.checked)
    .map((b) => b.value);
  if (!targets.length) {
    err.textContent = "Pick at least one artifact.";
    return;
  }

  const payload = { volume, targets, replace };
  if (dest === "current") {
    payload.into_current = true;
  } else if (dest === "case") {
    const name = container.querySelector("#cl-name").value.trim();
    if (!name) {
      err.textContent = "Enter a case name.";
      return;
    }
    payload.into_case = {
      name,
      number: container.querySelector("#cl-number").value,
      analyst: "",
      notes: "Collected live from volume " + volume + ":",
    };
  } else {
    const dir = container.querySelector("#cl-dir").value.trim();
    if (!dir) {
      err.textContent = "Choose a destination folder.";
      return;
    }
    payload.out_dir = dir;
  }

  const btn = container.querySelector("#cl-run");
  btn.disabled = true;
  btn.innerHTML = icon("clock") + " Collecting\u2026";
  results.hidden = false;
  results.innerHTML = `<div class="cl-busy">${icon(
    "clock"
  )} Reading the volume. Large $MFT or $J streams can take a minute.</div>`;

  try {
    const res = await api.collectRun(payload);
    renderResults(container, results, res, destFn, onChange, close);
    if (res.case_file) {
      await refreshCase();
      if (onChange) {
        onChange();
      }
    }
  } catch (e) {
    results.innerHTML = `<div class="cl-fail">${icon("cancel")} ${escText(e.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = icon("download") + " Collect";
  }
}

function renderResults(container, box, res, destFn, onChange, close) {
  const rows = res.items
    .map((i) => {
      let status;
      if (i.ok) {
        status = `<span class="cl-ok">${i.parsed ? "collected + parsed" : "collected"}</span>`;
      } else if (i.exists) {
        status = `<span class="cl-dup">already in case</span>`;
      } else {
        status = `<span class="cl-no">failed</span>`;
      }
      const detail = i.ok
        ? fmtBytes(i.bytes)
        : escText(i.error || "error");
      return `<div class="cl-row"><span class="cl-row-name">${escText(
        i.label
      )}</span>${status}<span class="cl-row-detail">${detail}</span></div>`;
    })
    .join("");

  const where = res.case_file
    ? `Case <code>${escText(fileName(res.case_file))}</code>`
    : `Folder <code>${escText(res.out_dir || "")}</code>`;

  const anyDup = res.items.some((i) => i.exists);
  const anyParsed = res.items.some((i) => i.parsed);

  box.innerHTML = `<div class="cl-done">${rows}</div><p class="cl-note">${where}</p>
${anyDup ? `<button type="button" class="btn ghost small cl-replace" id="cl-replace">${icon("cancel")} Replace existing and recollect</button>` : ""}
${anyParsed ? `<button type="button" class="btn small panel-cta" id="cl-goto">${icon("grid")} Open the case</button>` : ""}`;

  if (anyDup) {
    box.querySelector("#cl-replace").addEventListener("click", () =>
      runCollect(container, destFn, true, onChange, close)
    );
  }
  if (anyParsed) {
    box.querySelector("#cl-goto").addEventListener("click", () => {
      if (close) {
        close();
      }
      go("/case");
    });
  }
}

function fileName(p) {
  const parts = String(p).split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function fmtBytes(n) {
  if (!n || n < 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return (u === 0 ? v : v.toFixed(1)) + " " + units[u];
}

function escText(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
