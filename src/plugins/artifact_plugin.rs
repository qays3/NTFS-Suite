use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::vault::error::VaultError;
use crate::vault::Vault;

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct IngestStats {
    pub records: u64,
    pub in_use: u64,
    pub deleted: u64,
    pub directories: u64,
    pub with_ads: u64,
    pub orphans: u64,
    pub baad: u64,
    pub errors: u64,
    pub cancelled: bool,
}

pub struct IngestCtx {
    pub cancel: AtomicBool,
    pub processed: AtomicU64,
    pub total_estimate: AtomicU64,
    pub phase: std::sync::Mutex<String>,
}

impl IngestCtx {
    pub fn new(total_estimate: u64) -> IngestCtx {
        IngestCtx {
            cancel: AtomicBool::new(false),
            processed: AtomicU64::new(0),
            total_estimate: AtomicU64::new(total_estimate),
            phase: std::sync::Mutex::new(String::from("starting")),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn set_processed(&self, value: u64) {
        self.processed.store(value, Ordering::Relaxed);
    }

    pub fn set_phase(&self, text: &str) {
        if let Ok(mut p) = self.phase.lock() {
            *p = text.to_string();
        }
    }
}

pub trait ArtifactPlugin {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn identify(&self, header: &[u8]) -> bool;
    // Some artifacts (sparse journals, security streams) have no reliable header
    // magic, so a plugin may also claim a file by its name. Default: no.
    fn identify_name(&self, _name: &str) -> bool {
        false
    }
    fn ingest(
        &self,
        path: &Path,
        vault: &mut Vault,
        evidence_id: i64,
        ctx: &IngestCtx,
    ) -> Result<IngestStats, VaultError>;
}
