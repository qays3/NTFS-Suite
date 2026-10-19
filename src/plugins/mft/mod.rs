use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use crate::mft::path_resolver::{EntrySummary, PathResolver};
use crate::mft::stream::{detect_record_size_reader, for_each_record};
use crate::plugins::artifact_plugin::{ArtifactPlugin, IngestCtx, IngestStats};
use crate::util::filetime::FileTime;
use crate::vault::error::VaultError;
use crate::vault::record_store::{insert_many, StoredRecord};
use crate::vault::{audit, Vault};

const BATCH: usize = 20_000;
const PROGRESS_EVERY: u64 = 2_000;

pub struct MftPlugin;

struct PartialRecord {
    summary: EntrySummary,
    has_ads: bool,
    si_created: FileTime,
    si_modified: FileTime,
    si_mft_modified: FileTime,
    si_accessed: FileTime,
    fn_created: FileTime,
    si_flags: i64,
    owner_id: i64,
    security_id: i64,
    usn: i64,
    hard_link_count: i64,
    real_size: i64,
    short_name: String,
    reparse_tag: i64,
    reparse_target: String,
    resident_exe: bool,
}

impl ArtifactPlugin for MftPlugin {
    fn id(&self) -> &'static str {
        "mft"
    }

    fn display_name(&self) -> &'static str {
        "MFT"
    }

    fn identify(&self, header: &[u8]) -> bool {
        header.len() >= 4 && (&header[0..4] == b"FILE" || &header[0..4] == b"BAAD")
    }

    fn ingest(
        &self,
        path: &Path,
        vault: &mut Vault,
        evidence_id: i64,
        ctx: &IngestCtx,
    ) -> Result<IngestStats, VaultError> {
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(1 << 20, file);
        let record_size = detect_record_size_reader(&mut reader).unwrap_or(1024);

        let mut partials: Vec<PartialRecord> = Vec::new();
        let mut stats = IngestStats::default();

        ctx.set_phase("reading records");
        let mut seen: u64 = 0;
        let stream_result = for_each_record(&mut reader, record_size, |number, record| {
            seen += 1;
            if seen % PROGRESS_EVERY == 0 {
                ctx.set_processed(seen);
                if ctx.is_cancelled() {
                    return false;
                }
            }
            let summary = PathResolver::summarize(number, record);
            if summary.in_use {
                stats.in_use += 1;
            } else {
                stats.deleted += 1;
            }
            if summary.is_directory {
                stats.directories += 1;
            }
            let has_ads = !record.alternate_streams().is_empty();
            if has_ads {
                stats.with_ads += 1;
            }
            let si = record.standard_information();
            let fnm = record.best_name();
            let rp = record.reparse_point();
            partials.push(PartialRecord {
                summary,
                has_ads,
                si_created: si.map(|s| s.created).unwrap_or(FileTime::new(0)),
                si_modified: si.map(|s| s.modified).unwrap_or(FileTime::new(0)),
                si_mft_modified: si.map(|s| s.mft_modified).unwrap_or(FileTime::new(0)),
                si_accessed: si.map(|s| s.accessed).unwrap_or(FileTime::new(0)),
                fn_created: fnm.map(|f| f.created).unwrap_or(FileTime::new(0)),
                si_flags: si.map(|s| s.flags as i64).unwrap_or(0),
                owner_id: si.map(|s| s.owner_id as i64).unwrap_or(0),
                security_id: si.map(|s| s.security_id as i64).unwrap_or(0),
                usn: si.map(|s| s.usn as i64).unwrap_or(0),
                hard_link_count: record.header.hard_link_count as i64,
                real_size: record.data_size() as i64,
                short_name: record.short_name().unwrap_or_default(),
                reparse_tag: rp.map(|r| r.tag as i64).unwrap_or(0),
                reparse_target: rp.map(|r| r.target.clone()).unwrap_or_default(),
                resident_exe: record.resident_has_mz(),
            });
            true
        })?;
        stats.baad = stream_result.baad;
        stats.errors = stream_result.errors;

        if ctx.is_cancelled() || stream_result.cancelled {
            stats.cancelled = true;
            return Ok(stats);
        }

        ctx.set_phase("resolving paths");
        let mut resolver = PathResolver::new();
        for p in partials.iter() {
            resolver.insert_summary(p.summary.clone());
        }

        ctx.set_phase("writing to vault");
        let mut written: u64 = 0;
        let mut buffer: Vec<StoredRecord> = Vec::with_capacity(BATCH);
        for p in partials.iter() {
            let resolved = resolver.resolve(p.summary.entry);
            let (path_text, orphan) = match resolved {
                Some(r) => {
                    if r.orphan {
                        stats.orphans += 1;
                    }
                    (r.path, r.orphan)
                }
                None => (String::new(), true),
            };
            buffer.push(StoredRecord {
                entry: p.summary.entry as i64,
                sequence: p.summary.sequence as i64,
                in_use: p.summary.in_use,
                is_directory: p.summary.is_directory,
                has_ads: p.has_ads,
                orphan,
                parent_entry: p.summary.parent_entry as i64,
                si_created: p.si_created.to_iso8601_utc(),
                si_modified: p.si_modified.to_iso8601_utc(),
                si_mft_modified: p.si_mft_modified.to_iso8601_utc(),
                si_accessed: p.si_accessed.to_iso8601_utc(),
                fn_created: p.fn_created.to_iso8601_utc(),
                name: p.summary.name.clone(),
                path: path_text,
                si_flags: p.si_flags,
                owner_id: p.owner_id,
                security_id: p.security_id,
                usn: p.usn,
                hard_link_count: p.hard_link_count,
                real_size: p.real_size,
                short_name: p.short_name.clone(),
                reparse_tag: p.reparse_tag,
                reparse_target: p.reparse_target.clone(),
                resident_exe: p.resident_exe,
            });
            stats.records += 1;
            if buffer.len() >= BATCH {
                insert_many(&mut vault.conn, evidence_id, &buffer)?;
                written += buffer.len() as u64;
                ctx.set_processed(written);
                buffer.clear();
                if ctx.is_cancelled() {
                    stats.cancelled = true;
                    return Ok(stats);
                }
            }
        }
        if !buffer.is_empty() {
            insert_many(&mut vault.conn, evidence_id, &buffer)?;
        }

        audit::record(
            &vault.conn,
            "system",
            "evidence_parsed",
            &format!("mft evidence {} records {}", evidence_id, stats.records),
        )?;
        Ok(stats)
    }
}
