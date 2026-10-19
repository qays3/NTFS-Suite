import { go } from "/js/router.js";
import { icon } from "/js/icons.js";
import { state, refreshCase } from "/js/state.js";
import { openPanel } from "/js/ui/side-panel.js";

const STEPS = [
  ["1", "Collect or add the artifacts", "Collect $MFT, $UsnJrnl $J and $Secure straight off a live Windows volume with the Collect button, or add ones you already pulled as files."],
  ["2", "Parse into a case", "Every record, change event and security descriptor is read into one local case vault, at full 100 nanosecond timestamp precision."],
  ["3", "Analyze and correlate", "Timeline, ownership and detections, with each record tagged by the artifacts that mention it so findings corroborate across sources."],
];

const SUPPORTS = [
  ["grid", "$MFT", "Every record and attribute, fixups, full paths, deleted and orphan records, ADS, reparse points, hard links, owner and security ids."],
  ["list", "$UsnJrnl $J", "The change journal: create, delete, rename and data events with their own timestamps, on a dedicated Journal page."],
  ["folder", "$Secure", "Security descriptors resolved to owner and group names and permissions, shown on the Ownership tab and in every record popup."],
  ["clock", "Timeline", "A MACB timeline built from flagged files, plus a Sleuth Kit bodyfile reader that another examiner's output drops into."],
  ["search", "Detection", "Timestomping, anti-forensics and masquerading rules with MITRE mapping, a custom rule builder and offline IOC lists."],
  ["grid", "Correlation", "Each record shows which artifacts mention it, with a correlated tag and jumps between Explore, Findings and the Journal."],
  ["download", "Collect", "Pull $MFT, $UsnJrnl $J and $Secure off a live Windows volume, into a folder or straight into a parsed case, no external imager needed."],
];

const GALLERY = [
  ["Explore", "Browse and filter every $MFT record", "/explore", "grid"],
  ["Graph", "The NTFS map and ownership by id", "/graphs", "grid"],
  ["Time analyze", "A MACB timeline and bodyfile reader", "/time", "clock"],
  ["Journal", "The $UsnJrnl change journal", "/journal", "list"],
  ["Findings", "Ranked detections and rules", "/findings", "search"],
];

const STATS = [
  ["3", "NTFS artifacts parsed"],
  ["25+", "detection rules"],
  ["MITRE", "ATT&CK mapped"],
  ["100%", "local, no upload"],
];

export async function render(view) {
  await refreshCase();
  view.className = "view";
  const hasCase = state.caseOpen && state.caseInfo;
  const caseName = hasCase ? state.caseInfo.name : "";
  view.innerHTML = `
<div class="home">
<section class="home-hero">
<div class="home-badges"><span class="home-badge">v0.8</span><span class="home-badge">runs locally</span><span class="home-badge">single binary</span></div>
<h1 class="home-title"><img class="home-logo" src="/icons/logo.svg" alt="N" width="64" height="64">TFS <span class="home-title-x">Suite</span></h1>
<p class="home-tag">Collect the NTFS artifacts and analyze them.</p>
<p class="home-lead">A local forensic workbench for the NTFS metadata of a Windows volume. It parses the $MFT, the $UsnJrnl $J change journal and $Secure, rebuilds the MACB timeline, resolves ownership, and flags timestomping and anti-forensics, all inside one case vault on your own machine.</p>
<div class="home-cta">
<button type="button" class="btn primary" id="home-cases">${icon("folder")} ${hasCase ? "Go to " + esc(caseName) : "Open or create a case"}</button>
<button type="button" class="btn ghost" id="home-samples">${icon("download")} Try a sample</button>
<button type="button" class="btn ghost" id="home-guide">${icon("list")} Read the guide</button>
</div>
</section>

<section class="home-stats">${STATS.map(([n, l]) => `<div class="home-stat"><span class="home-stat-n">${n}</span><span class="home-stat-l">${l}</span></div>`).join("")}</section>

<section class="home-block">
<h2 class="home-h2">How it works</h2>
<div class="home-steps">${STEPS.map(([n, t, d]) => `<div class="home-step"><span class="home-step-n">${n}</span><div><div class="home-step-t">${t}</div><div class="home-step-d">${d}</div></div></div>`).join("")}</div>
</section>

<section class="home-block">
<h2 class="home-h2">What it supports now</h2>
<div class="home-grid">${SUPPORTS.map(([ic, t, d]) => `<div class="home-card"><span class="home-card-ic">${icon(ic)}</span><div class="home-card-t">${t}</div><div class="home-card-d">${d}</div></div>`).join("")}</div>
</section>

<section class="home-block">
<h2 class="home-h2">Quick actions</h2>
<div class="home-quick">
<button type="button" class="home-q" data-act="new">${icon("plus")}<span>New case</span></button>
<button type="button" class="home-q" data-act="open">${icon("folder")}<span>Open a case</span></button>
<button type="button" class="home-q" data-act="samples">${icon("download")}<span>Samples</span></button>
<button type="button" class="home-q" data-act="guide">${icon("list")}<span>Guide</span></button>
</div>
</section>

<section class="home-block">
<h2 class="home-h2">The pages</h2>
<div class="home-gallery">${GALLERY.map(([t, d, path, ic]) => `<button type="button" class="home-tile" data-go="${path}"><span class="home-tile-ic">${icon(ic)}</span><span class="home-tile-t">${t}</span><span class="home-tile-d">${d}</span></button>`).join("")}</div>
<p class="home-note">${hasCase ? "Your case is open, these open directly." : "The pages open once a case with parsed evidence is set up."}</p>
</section>
</div>`;

  const openCases = () => openPanel("cases", () => {});
  view.querySelector("#home-cases").addEventListener("click", () => {
    if (hasCase) {
      go("/case");
    } else {
      openCases();
    }
  });
  view.querySelector("#home-samples").addEventListener("click", () => go("/samples"));
  view.querySelector("#home-guide").addEventListener("click", () => openPanel("guide"));
  for (const b of view.querySelectorAll(".home-q")) {
    b.addEventListener("click", () => {
      const act = b.getAttribute("data-act");
      if (act === "samples") {
        go("/samples");
      } else if (act === "guide") {
        openPanel("guide");
      } else {
        openCases();
      }
    });
  }
  for (const t of view.querySelectorAll(".home-tile")) {
    t.addEventListener("click", () => {
      if (hasCase) {
        go(t.getAttribute("data-go"));
      } else {
        openCases();
      }
    });
  }
}

function esc(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
