use std::path::Path;

use crate::plugins::artifact_plugin::{ArtifactPlugin, IngestCtx, IngestStats};
use crate::usn::{self, MAX_RECORD_LEN, MIN_RECORD_LEN};
use crate::vault::error::VaultError;
use crate::vault::usn_store::{self, UsnEvent};
use crate::vault::Vault;

const BATCH: usize = 20_000;
const PROGRESS_EVERY: u64 = 5_000;

pub struct UsnPlugin;

// A light header check: within the first bytes, find a plausible V2/V3 record.
fn looks_like_usn(header: &[u8]) -> bool {
    let mut off = 0usize;
    while off + 8 <= header.len() && off < 480 {
        let len = u32::from_le_bytes([header[off], header[off + 1], header[off + 2], header[off + 3]]);
        if (MIN_RECORD_LEN..=MAX_RECORD_LEN).contains(&len) && len % 8 == 0 {
            let major = u16::from_le_bytes([header[off + 4], header[off + 5]]);
            if major == 2 || major == 3 {
                return true;
            }
        }
        off += 8;
    }
    false
}

impl ArtifactPlugin for UsnPlugin {
    fn id(&self) -> &'static str {
        "usnjrnl"
    }

    fn display_name(&self) -> &'static str {
        "UsnJrnl"
    }

    fn identify(&self, header: &[u8]) -> bool {
        looks_like_usn(header)
    }

    fn identify_name(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        n.contains("usnjrnl") || n == "$j" || n.ends_with("$j") || n.ends_with("_j") || n.ends_with(":$j")
    }

    fn ingest(
        &self,
        path: &Path,
        vault: &mut Vault,
        evidence_id: i64,
        ctx: &IngestCtx,
    ) -> Result<IngestStats, VaultError> {
        ctx.set_phase("reading journal");
        let data = std::fs::read(path)?;
        ctx.total_estimate
            .store((data.len() as u64 / 96).max(1), std::sync::atomic::Ordering::Relaxed);

        let mut events: Vec<UsnEvent> = Vec::new();
        let mut seen: u64 = 0;
        let mut cancelled = false;
        usn::for_each_record(&data, |r| {
            if ctx.is_cancelled() {
                cancelled = true;
                return false;
            }
            seen += 1;
            if seen % PROGRESS_EVERY == 0 {
                ctx.set_processed(seen);
            }
            events.push(UsnEvent {
                usn: r.usn,
                timestamp: r.timestamp.to_iso8601_utc(),
                entry: r.entry as i64,
                sequence: r.sequence as i64,
                parent_entry: r.parent_entry as i64,
                reason: r.reason as i64,
                summary: usn::reason_summary(r.reason).to_string(),
                source_info: r.source_info as i64,
                security_id: r.security_id,
                file_attributes: r.file_attributes as i64,
                name: r.name.clone(),
            });
            true
        });

        let mut stats = IngestStats::default();
        if cancelled {
            stats.cancelled = true;
            return Ok(stats);
        }

        ctx.set_phase("storing events");
        let total = events.len() as u64;
        let mut written: u64 = 0;
        for chunk in events.chunks(BATCH) {
            if ctx.is_cancelled() {
                stats.cancelled = true;
                return Ok(stats);
            }
            usn_store::insert_many(&mut vault.conn, evidence_id, chunk)?;
            written += chunk.len() as u64;
            ctx.set_processed(written);
        }

        stats.records = total;
        Ok(stats)
    }
}
