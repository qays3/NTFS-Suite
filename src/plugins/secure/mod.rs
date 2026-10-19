use std::path::Path;

use crate::plugins::artifact_plugin::{ArtifactPlugin, IngestCtx, IngestStats};
use crate::secure;
use crate::vault::error::VaultError;
use crate::vault::security_store::{self, SecurityDescriptor};
use crate::vault::Vault;

const BATCH: usize = 5_000;

pub struct SecurePlugin;

// $SDS entries start with a 20-byte header (hash, security id, offset, length)
// then a security descriptor whose first byte is revision 1. The first real
// security id is 0x100 and the first entry offset is 0.
fn looks_like_sds(header: &[u8]) -> bool {
    if header.len() < 24 {
        return false;
    }
    let security_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let offset = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14], header[15],
    ]);
    let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let sd_revision = header[20];
    (0x100..0x10000).contains(&security_id) && offset == 0 && length >= 20 && length < 0x10000 && sd_revision == 1
}

impl ArtifactPlugin for SecurePlugin {
    fn id(&self) -> &'static str {
        "secure"
    }

    fn display_name(&self) -> &'static str {
        "Secure"
    }

    fn identify(&self, header: &[u8]) -> bool {
        looks_like_sds(header)
    }

    fn identify_name(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        n.contains("secure") || n.contains("$sds") || n.ends_with("_sds") || n.ends_with(":$sds")
    }

    fn ingest(
        &self,
        path: &Path,
        vault: &mut Vault,
        evidence_id: i64,
        ctx: &IngestCtx,
    ) -> Result<IngestStats, VaultError> {
        ctx.set_phase("reading security descriptors");
        let data = std::fs::read(path)?;
        ctx.total_estimate
            .store((data.len() as u64 / 128).max(1), std::sync::atomic::Ordering::Relaxed);

        let mut rows: Vec<SecurityDescriptor> = Vec::new();
        let mut cancelled = false;
        secure::for_each_entry(&data, |security_id, d| {
            if ctx.is_cancelled() {
                cancelled = true;
                return;
            }
            rows.push(SecurityDescriptor {
                security_id: security_id as i64,
                owner_sid: d.owner_sid.clone(),
                owner_name: d.owner_name.clone(),
                group_sid: d.group_sid.clone(),
                group_name: d.group_name.clone(),
                control: d.control as i64,
                ace_count: d.ace_count as i64,
                allow_count: d.allow_count as i64,
                deny_count: d.deny_count as i64,
            });
            if rows.len() % 1000 == 0 {
                ctx.set_processed(rows.len() as u64);
            }
        });

        let mut stats = IngestStats::default();
        if cancelled {
            stats.cancelled = true;
            return Ok(stats);
        }

        ctx.set_phase("storing descriptors");
        let mut written: u64 = 0;
        for chunk in rows.chunks(BATCH) {
            if ctx.is_cancelled() {
                stats.cancelled = true;
                return Ok(stats);
            }
            security_store::insert_many(&mut vault.conn, evidence_id, chunk)?;
            written += chunk.len() as u64;
            ctx.set_processed(written);
        }

        stats.records = rows.len() as u64;
        Ok(stats)
    }
}
