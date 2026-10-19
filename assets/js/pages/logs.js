import { api } from "/js/api.js";
import { refreshCase, state } from "/js/state.js";
import { wireBrowse } from "/js/browse.js";
import { go } from "/js/router.js";
import { esc } from "/js/pages/setup.js";
import { icon } from "/js/icons.js";
import { caseShell } from "/js/pages/case-shell.js";
import { openModal } from "/js/ui/modal.js";

export async function render(view) {
  await refreshCase();
  if (!state.caseOpen) {
    go("/");
    return;
  }
  const content = caseShell(view, "logs");
  content.innerHTML = `
<section class="panel">
<h3>Add</h3>
<p class="muted">Add a $MFT, a $UsnJrnl $J change journal, or a $Secure. One of each type per case. The file is recognised by its contents or its name. Use Browse for the native file dialog, or drop a file below.</p>
<label>Evidence file path<span class="input-row"><input id="ad-path" type="text" placeholder="C:\\path\\to\\$MFT"><button type="button" class="btn ghost small" data-browse="ad-path" data-dirs="0">${icon("folder")} Browse</button><button type="button" class="btn" id="ad-parse">${icon("plus")} Add and parse</button></span></label>
<div class="dropzone" id="ad-drop">
<span id="ad-drop-text">Drop an evidence file here</span>
<div class="upload-track" id="ad-upload" hidden><div class="upload-fill" id="ad-upload-fill"></div></div>
<span class="upload-pct" id="ad-upload-pct" hidden></span>
</div>
<div class="parse-progress" id="ad-progress" hidden>
<div class="progress-head"><span id="ad-phase">Parsing</span><button type="button" class="btn ghost small" id="ad-cancel">Cancel</button></div>
<div class="progress-track"><div class="progress-fill" id="ad-fill"></div></div>
<div class="progress-text" id="ad-ptext"></div>
</div>
<p class="hint" id="ad-error"></p>
</section>
<section class="panel">
<h3>Evidence</h3>
<ul class="evidence-list scroll-purple" id="lg-evidence"></ul>
</section>`;
  wireBrowse(content);
  renderEvidence(content);

  let jobId = null;

  content.querySelector("#ad-parse").addEventListener("click", async () => {
    const path = content.querySelector("#ad-path").value.trim();
    if (!path) {
      return;
    }
    content.querySelector("#ad-error").textContent = "";
    setParseBusy(content, true);
    try {
      const added = await api.addEvidence(path);
      const started = await api.parseEvidence({ evidence_id: added.evidence_id, path, plugin: added.plugin });
      jobId = started.job_id;
      await poll(content, jobId);
    } catch (e) {
      content.querySelector("#ad-error").textContent = e.message || "Could not add the evidence.";
      setParseBusy(content, false);
    }
  });

  content.querySelector("#ad-cancel").addEventListener("click", async () => {
    if (jobId !== null) {
      try {
        await api.jobCancel(jobId);
        content.querySelector("#ad-phase").textContent = "Cancelling";
      } catch (e) {
        void e;
      }
    }
  });

  wireDrop(content);
}

async function poll(content, jobId) {
  const prog = content.querySelector("#ad-progress");
  prog.hidden = false;
  content.querySelector("#ad-fill").style.width = "0%";
  content.querySelector("#ad-ptext").textContent = "Starting";
  for (;;) {
    let v;
    try {
      v = await api.jobStatus(jobId);
    } catch (e) {
      prog.hidden = true;
      setParseBusy(content, false);
      content.querySelector("#ad-error").textContent = "Status failed: " + e.message;
      return;
    }
    if (v.status === "running") {
      const pct = v.total > 0 ? Math.min(100, Math.round((v.processed / v.total) * 100)) : 0;
      content.querySelector("#ad-phase").textContent = v.phase || "Parsing";
      content.querySelector("#ad-fill").style.width = pct + "%";
      content.querySelector("#ad-ptext").textContent =
        v.total > 0 ? v.processed.toLocaleString() + " of about " + v.total.toLocaleString() + " (" + pct + "%)" : v.processed.toLocaleString() + " records";
      await wait(400);
      continue;
    }
    prog.hidden = true;
    setParseBusy(content, false);
    if (v.status === "error") {
      content.querySelector("#ad-error").textContent = "Parse error: " + (v.error || "");
      return;
    }
    if (v.status === "cancelled") {
      content.querySelector("#ad-error").textContent = "Parse cancelled.";
      await refreshCase();
      renderEvidence(content);
      return;
    }
    await refreshCase();
    renderEvidence(content);
    window.dispatchEvent(new Event("case-changed"));
    go("/explore");
    return;
  }
}

function renderEvidence(content) {
  const list = content.querySelector("#lg-evidence");
  list.innerHTML = "";
  if (state.evidence.length === 0) {
    list.innerHTML = '<li class="muted">None yet</li>';
    return;
  }
  for (const e of state.evidence) {
    const li = document.createElement("li");
    li.className = "evidence-item";
    li.innerHTML = `<div class="evidence-main"><span class="evidence-name">${esc(e.name)} (${esc(e.plugin)}, ${esc(e.status)})</span><span class="evidence-path">${esc(e.source_path)}</span></div><button type="button" class="ev-remove" title="Remove this evidence">${icon("cancel")}</button>`;
    li.querySelector(".ev-remove").addEventListener("click", () => confirmRemove(content, e));
    list.appendChild(li);
  }
}

function confirmRemove(content, e) {
  const m = openModal({ title: "Remove evidence", width: "460px" });
  m.body.innerHTML = `
<p>Remove <strong>${esc(e.name)}</strong> and everything parsed from it: its records, timeline events and findings. This cannot be undone.</p>
<div class="modal-foot">
<button type="button" class="btn ghost small" id="ev-cancel">Cancel</button>
<button type="button" class="btn small danger" id="ev-confirm">Remove</button>
</div>
<p class="hint" id="ev-msg"></p>`;
  m.body.querySelector("#ev-cancel").addEventListener("click", () => m.close());
  m.body.querySelector("#ev-confirm").addEventListener("click", async () => {
    const btn = m.body.querySelector("#ev-confirm");
    btn.disabled = true;
    btn.textContent = "Removing";
    try {
      await api.deleteEvidence(e.id);
      await refreshCase();
      m.close();
      renderEvidence(content);
    } catch (err) {
      m.body.querySelector("#ev-msg").textContent = err.message || "Could not remove the evidence.";
      btn.disabled = false;
      btn.textContent = "Remove";
    }
  });
}

function wireDrop(content) {
  const zone = content.querySelector("#ad-drop");
  const stop = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  for (const n of ["dragenter", "dragover"]) {
    zone.addEventListener(n, (e) => {
      stop(e);
      zone.classList.add("drag-over");
    });
  }
  for (const n of ["dragleave", "drop"]) {
    zone.addEventListener(n, (e) => {
      stop(e);
      zone.classList.remove("drag-over");
    });
  }
  zone.addEventListener("drop", async (e) => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (!files || files.length === 0) {
      return;
    }
    const file = files[0];
    content.querySelector("#ad-drop-text").textContent = "Uploading " + file.name;
    const fill = content.querySelector("#ad-upload-fill");
    fill.style.width = "0%";
    fill.classList.add("indet");
    content.querySelector("#ad-upload").hidden = false;
    const pct = content.querySelector("#ad-upload-pct");
    pct.hidden = false;
    pct.textContent = "Starting the upload of " + fmtBytes(file.size);
    try {
      const path = await uploadWithProgress(content, file);
      fill.classList.remove("indet");
      fill.style.width = "100%";
      pct.textContent = "Uploaded " + fmtBytes(file.size) + ", reading it now";
      content.querySelector("#ad-drop-text").textContent = "Uploaded " + file.name;
      setTimeout(() => {
        content.querySelector("#ad-upload").hidden = true;
        pct.hidden = true;
      }, 600);
      content.querySelector("#ad-path").value = path;
      content.querySelector("#ad-parse").click();
    } catch (err) {
      content.querySelector("#ad-upload").hidden = true;
      pct.hidden = true;
      content.querySelector("#ad-drop-text").textContent = "Upload failed: " + err.message;
    }
  });
}

function uploadWithProgress(content, file) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.setRequestHeader("x-filename", file.name);
    xhr.upload.addEventListener("progress", (e) => {
      const fill = content.querySelector("#ad-upload-fill");
      const pct = content.querySelector("#ad-upload-pct");
      if (e.lengthComputable) {
        const p = Math.round((e.loaded / e.total) * 100);
        fill.classList.remove("indet");
        fill.style.width = p + "%";
        if (pct) {
          pct.hidden = false;
          pct.textContent = p + "%  (" + fmtBytes(e.loaded) + " of " + fmtBytes(e.total) + ")";
        }
      } else {
        fill.classList.add("indet");
      }
    });
    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText).path);
        } catch (e) {
          reject(new Error("bad response"));
        }
      } else {
        reject(new Error("status " + xhr.status));
      }
    });
    xhr.addEventListener("error", () => reject(new Error("network error")));
    xhr.send(file);
  });
}

function setParseBusy(content, on) {
  const b = content.querySelector("#ad-parse");
  if (!b) {
    return;
  }
  if (on) {
    b.disabled = true;
    b.classList.add("loading");
    if (!b.dataset.label) {
      b.dataset.label = b.innerHTML;
    }
    b.innerHTML = '<span class="spin"></span> Working';
  } else {
    b.disabled = false;
    b.classList.remove("loading");
    if (b.dataset.label) {
      b.innerHTML = b.dataset.label;
      delete b.dataset.label;
    }
  }
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

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
