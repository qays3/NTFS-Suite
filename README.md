# NTFS Suite

A single binary forensic tool for Windows NTFS (New Technology File System) artifacts. It parses the $MFT (Master File Table), rebuilds a MACB (Modified, Accessed, Changed, Born) timeline, and flags timestomping and anti forensics inside a case vault. The tool runs a local web app in the browser.

Repository: https://github.com/qays3/NTFS-Suite

## Status

Building in versions. Each version is a full working tool, released before the next starts.

- v0.1 Parser, vault and server: done. $MFT parser core, case vault with schema and audit log, plugin registry with the MFT plugin, local server with the security rules, first run setup and settings, assets served from disk in development and embedded in release.
- v0.2 Explore and time zones: done. Create case, add evidence, parse with live progress and cancel, native file dialog and drag and drop, record table with filters and search, numbered paging, time zone control with every IANA zone, record and timeline CSV and JSON export.
- v0.3 Detection and findings: done. Timestomp, anti forensics and anomaly checks, scoring and per file ranking, MITRE ATT&CK mapping, finding status, group status by reason, folder grouping, cloud sync downgrade, and a Findings page.
- v0.4 Graphs: the statistical chart dashboard was built, then set aside. For an investigation a node and link graph is more useful, so the Graph tab now shows the link graph. The chart aggregation endpoint still exists but is off the tab bar.
- v0.5 Graph: the Graph tab shows an NTFS anatomy, the volume's own metadata files ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, root, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend and its children), each with its MFT entry, its role, and live facts from the parsed evidence (present, deleted or missing, kind, Standard Information time). Zoom, pan and reset controls, and a jump into Explore. A node and link graph endpoint also exists for later execution plugins.
- v0.6 Guide, samples, exports and report: done. The in app Guide (tabbed, offline) covers the case flow, collecting each artifact, detection, every view and a glossary. The Overview tab exports a printable HTML findings report and a JSON report, a Sleuth Kit bodyfile, a timeline CSV, and an IOC list. The Time analyze tab also reads a Sleuth Kit bodyfile back in, from this tool or another examiner, and shows it as the same MACB timeline with the same filters, search and detections. The Samples page lists public sample cases from `assets/samples-index.json` with their files, sizes and GitHub download links. Add real sample files under `samples/` and list them in the index to fill the page.
- Explore and Time analyze both have an After and Before date filter to query a time window; on Explore it filters records in the database by any of their five timestamps, on Time analyze it filters the shown events by day.
- v0.7 Usability, rules and link analysis: done. A command palette opens with Ctrl K or the top bar button and runs any navigation or action from the keyboard. The top bar has a theme toggle that switches dark and light from root.css and saves the choice. Explore and Findings tables copy their current view as CSV or JSON, both have a column chooser and saved views remembered per case, and the popup menu they share lives in one module. Guide, Settings and Open cases moved from pop up modals to a right side panel between the header and footer, with a Go to current case button. Every page now has a long, bookmarkable address, `case/<case name>-<case number>/<page>`, so a view can be shared or reopened directly. Evidence can be deleted, which cascades to its records, events and findings, and only one artifact of each type is allowed at a time. The $MFT parser was extended to read reparse points, hard link counts, owner and security ids, the DOS short name, resident executable content and more, and the vault schema upgrades existing cases in place. The detection set gained an FN<SI direction flag, a masquerading rule for a known file run from an unknown path, name abuse (right to left override, trailing dot or space, double extension), resident executables, MFT slot reuse, hidden and system executables, risky reparse points, and three combination rules. A declarative rule engine lets the analyst write their own rules in a Rules tab, preview them over the current evidence and save them to the case, and an IOC list of names, paths, sizes and hashes can be imported and matched. The Graph page is now tabbed: the NTFS map, a File link chains view of reparse points and hard links, and an Ownership view of owner and security ids.
- v0.8 Recovery and carving: planned.
- v1.0 First complete release: planned.

## Features now

- Parse an $MFT file into records at full 100 nanosecond precision.
- Read $STANDARD_INFORMATION and $FILE_NAME timestamps, detect alternate data streams, rebuild the full path, and mark orphan and deleted records.
- Keep each case in one `.vault` SQLite file with an audit log for chain of custody.
- Explore records in a filtered, paged table with search.
- Control the display time zone, with stored values always kept in UTC.
- Run detection automatically after a parse, and re-run it on demand, then read ranked findings.
- Write and preview your own detection rules, disable built in ones, and import an IOC list, all per case.
- Read the Graph page as three tabs: the NTFS metadata map, reparse point and hard link chains, and ownership by id.
- Delete evidence with everything parsed from it, and keep one artifact of each type per case.
- Open any view by a long, shareable address such as `/case/<case-name>-<case-number>/findings`.

## Detection rules

Findings are ranked by total score per file, because one check alone is never proof.

Single checks run over each record; combination rules fire when several single checks land on the same file, which is the stronger signal. The Rules tab in the app shows this same catalog, lets the analyst disable any built in rule, and lists what each one needs.

### Timestomp and anti-forensics

| Rule | Title | Severity | MITRE | Checks |
| --- | --- | --- | --- | --- |
| MFT-TS-01 | Standard Information created before File Name created | medium→high | T1070.006 | $SI creation earlier than $FN creation by more than a few seconds; install caches and bulk seconds discounted; a zeroed sub second, a time before the volume, a future time or a risky executable raise it to high; gap size ranks it |
| MFT-TS-02 | Standard Information sub seconds all zero | high | T1070.006 | all seven $SI creation sub second digits zero while $FN keeps precision |
| MFT-TS-03 | Standard Information created before the volume | medium | T1070.006 | $SI creation earlier than the volume creation |
| MFT-TS-05 | Standard Information creation zeroed to 1601 | medium | T1070.006 | $SI creation set to the 1601 zero value |
| MFT-TS-06 | Standard Information creation in the future | medium | T1070.006 | $SI creation later than the analysis time |
| MFT-TS-07 | File Name created before Standard Information created | low | T1070.006 | the FN<SI direction; the FN copy is normally set at creation, so this gap means a creation time was changed |
| MFT-AF-01 | Alternate data stream present | low→medium | T1564.004 | a named data stream is attached; heavier for executable content and streams outside Downloads |
| MFT-AF-03 | Orphan record | low | T1070.004 | parent gone or sequence mismatch, so the path cannot be trusted |
| MFT-AF-04 | Known wiper trace | high | T1070 | name matches cipher, BCWipe or SDelete leftovers |

### Masquerading and anomalies

| Rule | Title | Severity | MITRE | Checks |
| --- | --- | --- | --- | --- |
| MFT-AN-01 | Executable in an unusual location | medium | T1036.005 | code in a temporary, recycle or drive root folder |
| MFT-AN-02 | Archive in an unusual location | low | T1036.005 | archive in a temporary or root folder, possible staging |
| MFT-AN-03 | Modified time older than creation time | medium | T1570 | copied in from another volume or the network; creation is the copy time |
| MFT-AN-04 | Creation burst | low | T1036.005 | many files share one creation second |
| MFT-AN-05 | Look alike system name | high | T1036.005 | a name imitating a Windows process, misspelled or not on modern Windows |
| MFT-AN-06 | Known file from an unknown path | high | T1036.005 | a known system file or DLL name running from a path that is not one of its homes |
| MFT-AN-07 | Name abuse | high | T1036.002 | a right to left override, a trailing dot or space, or a double extension |
| MFT-AN-08 | Short name does not match the long name | low | T1036 | the 8.3 short name does not derive from the long name |
| MFT-AN-10 | Executable content resident in the MFT | medium | T1564.004 | a resident data stream starting with the MZ header, code with no file on disk |
| MFT-AN-11 | MFT slot reused | low | T1070.004 | an in use record with a sequence above one, so the slot held earlier deleted files |
| MFT-AN-12 | Hidden and system executable | medium | T1564.001 | an executable with both hidden and system set in a user writable folder |
| MFT-RP-01 | Risky reparse point | medium | T1574 | a junction or symlink in a user writable folder pointing into a system path |

### Combination rules (fire on the same file)

| Rule | Title | Severity | MITRE | Fires when |
| --- | --- | --- | --- | --- |
| MFT-C1 | Timestomped file, high confidence | high | T1070.006 | MFT-TS-01 and MFT-TS-02 |
| MFT-C2 | Masqueraded and hidden binary | high | T1036.005 | MFT-AN-06 and MFT-AN-12 |
| MFT-C3 | Masqueraded and timestomped | high | T1036.005 | MFT-AN-06 and MFT-TS-02 |

### Your own rules and IOC lists

The Rules tab inside Findings has a builder for custom rules. A rule is a title, a severity, an optional MITRE id and reason, and a condition tree of all / any / not groups over leaf tests (field, operator, value) against each record's parsed fields. The engine runs offline with no code execution and bounded regular expressions. Preview a rule over the current evidence before saving it to the case, where it runs alongside the built in rules on every detection.

An IOC list can be imported on the same tab, as JSON or CSV with name, path, size and hash columns. Rule **MFT-IOC-01** then flags any record whose name, path or size matches the list.

Checks that need other artifacts are listed on the Findings page and come with later plugins: record number order, executable content inside a stream parsed as code, Zone.Identifier download source, deeper size anomalies, and broken fixup records.

## False positive control

- Cloud sync folders (OneDrive, Dropbox, Google Drive) are downgraded when the setting is on, which is the default.

## Samples

The Samples page in the app lists public sample cases. It reads `assets/samples-index.json`, which names each case and its files and points at the copies in the `samples/` folder of the repository. The app does not download anything for the user. The links open on GitHub so the user saves the files, then adds them to a case from the Add evidence page.

The index looks like this:

```
{
  "repo": "https://github.com/qays3/NTFS-Suite",
  "branch": "main",
  "samples_dir": "samples",
  "cases": [
    {
      "name": "Timestomped service binary",
      "number": "SAMPLE-001",
      "description": "A single $MFT with a few stomped records for practice.",
      "dir": "timestomp-demo",
      "files": [
        { "name": "$MFT", "size": 10485760, "note": "parse this" }
      ],
      "bundle": { "name": "Download all", "url": "", "size": 0 }
    }
  ]
}
```

Each file link is built from `repo`, `branch`, `samples_dir`, the case `dir` and the file `name`, so the links stay correct as long as the files sit at `samples/<dir>/<name>`. A file may instead carry its own `raw` and `view` URLs, and a case may carry a `bundle` for a release asset. `scripts/check-samples.sh` (needs `jq`) checks that every file named in the index exists under `samples/`.

## Build from source

Needs the Rust toolchain (https://rustup.rs).

```
cargo build --release
cargo test
```

The optimized binary is written to `target/release/ntfssuite` (`ntfssuite.exe` on Windows). In development, `cargo run` serves the front end from the `assets` folder so edits show on reload.

## Project layout

- `src/mft` the NTFS parser: header, fixup, attributes (including the reparse point attribute), data runs, path resolver.
- `src/vault` the case vault: schema, migrations, case, evidence, record (with the extended columns and in-place upgrade), finding, rule and IOC stores, and the audit log.
- `src/detection` the detection engine, scoring, MITRE map, the timestomp, anti forensics, anomaly and NTFS IOC rules, the known-location map for masquerading, the rule catalog, and the declarative rule engine.
- `src/plugins` the plugin trait, registry, and the MFT plugin.
- `src/server` the local server, security guard, asset serving and jobs.
- `src/api` the HTTP handlers for cases, evidence, records, findings, rules, IOC lists, graph (anatomy, link chains, ownership) and export.
- `src/settings` first run setup and settings model.
- `src/util` FILETIME, clock and byte readers.
- `assets` the web app: HTML, CSS and JavaScript modules, and the samples index.
- `samples` the sample case files linked from the Samples page.
- `scripts` helper scripts, including the samples index check.
- `tests` unit tests with a synthetic MFT record builder.

## Tests

`cargo test` runs the parser, vault and detection tests: FILETIME conversion, data run decoding, fixup application, record parsing, path resolution, vault storage, and the detection rules against synthetic records.

## License

To be added.

## Changelog

- v0.7 Link analysis and ownership: the Graph page is tabbed. **NTFS map** is the metadata anatomy from v0.5. **File link chains** lists every reparse point (junction, symbolic link, mount point) with its target resolved against the records in the image and marked in this image, external or not in this image, plus a risk flag when a user writable path points into a system path, and lists the hard-linked files with their link count; any name opens in Explore. **Ownership** groups the volume by the owner id and security id stored in each record, with example paths per owner, coverage and distinct-principal checks, and a note that mapping ids to account names needs the $Secure metafile a later version will parse.
- v0.7 Extended parser and IOC rules: the $MFT parser now reads the reparse point tag and target, the hard link count, the owner and security ids, the USN, the real data size, the DOS 8.3 short name, and whether a resident $DATA stream holds an executable. The vault schema adds these columns and upgrades existing cases in place; re-parse an existing evidence to populate them. New detection rules use the new fields: name abuse (MFT-AN-07), short-name mismatch (MFT-AN-08), resident executable (MFT-AN-10), MFT slot reuse (MFT-AN-11), hidden and system executable (MFT-AN-12), risky reparse point (MFT-RP-01), the FN<SI direction (MFT-TS-07), three combination rules (MFT-C1/C2/C3), and an IOC-list match (MFT-IOC-01).
- v0.7 Side panels and long routing: Guide, Settings and Cases open in a right side panel between the header and the footer instead of a popup, with the Cases panel showing a Go to current case button and the open case highlighted. Every page now has a long bookmarkable path, `/case/<case-name>-<case-number>/overview`, `/explore`, `/graph`, `/time-analyze`, `/findings`, `/evidence`, which reloads to the same view and resolves the case from its slug.
- v0.7 Rules, masquerading, FN<SI and evidence management: the Findings page has a Rules tab that lists every detection rule from one catalog with its plain condition, severity, MITRE technique and finding count, and lets a rule be turned off per case. Analysts write their own rules from a form or as JSON through a declarative engine (boolean conditions over record fields, with a live preview against the case), stored per case and part of scoring; the engine runs offline and evaluates only the condition tree. A new masquerading rule MFT-AN-06 flags a known Windows system file name running from a path that is not one of its homes, from an offline editable map. The SI<FN timestomp rule is now scored with a tolerance, install and bulk clusters discounted, and corroborating indicators raising it to high, and Explore shows a new FN<SI flag. A case now holds one evidence of each artifact type, refusing a duplicate, and each evidence can be removed with everything parsed from it.
- v0.7 Usability: a command palette (Ctrl K or the top bar button) runs any page or action from the keyboard, a top bar theme toggle switches and saves dark or light, and Explore and Findings each copy the current view as CSV or JSON and gain a column chooser and saved views remembered per case.
- v0.6 Samples: a Samples page in the top bar lists public sample cases from `assets/samples-index.json`, each with its files, sizes and GitHub download and view links, built so the links do not break. A `samples/` folder holds the files and `scripts/check-samples.sh` checks the index against it.
- Time filter: Explore and Time analyze have an After and Before date filter to query a window of time. Explore filters records in the database by any of their five timestamps and the window also applies to its CSV and JSON exports; Time analyze filters the shown events by day.
- Bodyfile analyze: the Time analyze tab has a third mode that reads a Sleuth Kit bodyfile, from this tool or another examiner, parses the pipe format into per file lanes, and renders the same MACB timeline with the type filters, path search and the created before File Name, copied in, all equal and future detections. No Sleuth Kit install needed to read a bodyfile.
- Time analyze: a forensic timeline tab where each file is a lane on one shared time axis and its MACB timestamps are nodes linked in order. Add files from the flagged list or from Explore, zoom and pan the time axis in the display zone, and click an event to read it.
- v0.5 Graph: the Graph tab shows an NTFS anatomy of the volume's metadata files with their roles and live facts from the parsed evidence, with zoom, pan and reset controls. A node and link graph of files, folders, streams and findings was built first but set aside as not useful on $MFT data alone; its endpoint remains for later plugins. The earlier statistical chart dashboard moved off the tab bar.
- v0.4 Graphs: a case dashboard of SVG charts reading colors from root.css, with a brushable activity timeline that filters every chart, both creation scatters, the sub second histogram, a day and hour heatmap, extension distribution, and findings by severity and rule. Timestomp noise cut by suppressing Standard Information before File Name in install locations unless the zero sub second tell is also present. Findings grouped by folder with folder level severity counts.
- v0.3 Detection and findings: timestomp, anti forensics and anomaly checks, scoring and per file ranking, MITRE mapping, finding status, cloud sync downgrade, detection after parse and on demand, and a Findings page.
- v0.2 Explore and time zones: case and evidence flow, parse with progress and cancel, record table with filters, search and paging, time zone control, record and timeline export.
- v0.1 Parser, vault and server: $MFT parser core, case vault, plugin registry, local server with the security rules, first run setup, and the web app shell.
