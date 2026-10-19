pub mod anomalies;
pub mod anti_forensics;
pub mod engine;
pub mod ownership;
pub mod known_locations;
pub mod mitre;
pub mod ntfs_iocs;
pub mod rule_catalog;
pub mod rule_engine;
pub mod scoring;
pub mod timestomp;

pub use engine::{run, DetectionOptions, DetectionSummary};

use std::collections::{HashMap, HashSet};

use crate::vault::record_store::StoredRecord;

pub const ZEROED_TIME: &str = "1601-01-01T00:00:00.0000000Z";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleHit {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub mitre: &'static str,
    pub reason: String,
}

pub struct Ctx {
    pub volume_created: Option<String>,
    pub now: String,
    pub downgrade_cloud: bool,
    pub tolerance_seconds: i64,
    pub bulk_fn_seconds: HashSet<String>,
    pub ioc_names: HashSet<String>,
    pub ioc_paths: HashSet<String>,
    pub ioc_sizes: HashSet<i64>,
    pub owner_names: HashMap<i64, String>,
    pub secure_present: bool,
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn iso_epoch_seconds(s: &str) -> Option<i64> {
    if s.len() < 19 || is_zeroed(s) {
        return None;
    }
    let p = |a: usize, b: usize| s.get(a..b).and_then(|t| t.parse::<i64>().ok());
    let y = p(0, 4)?;
    let mo = p(5, 7)?;
    let d = p(8, 10)?;
    let h = p(11, 13)?;
    let mi = p(14, 16)?;
    let se = p(17, 19)?;
    Some(days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

pub fn human_gap(seconds: i64) -> String {
    let s = seconds.abs();
    if s >= 31_536_000 {
        format!("{} years", s / 31_536_000)
    } else if s >= 86_400 {
        format!("{} days", s / 86_400)
    } else if s >= 3_600 {
        format!("{} hours", s / 3_600)
    } else if s >= 60 {
        format!("{} minutes", s / 60)
    } else {
        format!("{} seconds", s)
    }
}

pub fn is_zeroed(value: &str) -> bool {
    value == ZEROED_TIME || value.starts_with("1601-01-01T00:00:00")
}

pub fn subseconds(value: &str) -> Option<&str> {
    let dot = value.find('.')?;
    let rest = &value[dot + 1..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    Some(&rest[..end])
}

pub fn all_zero_subseconds(value: &str) -> bool {
    match subseconds(value) {
        Some(s) if !s.is_empty() => s.bytes().all(|b| b == b'0'),
        _ => false,
    }
}

pub fn path_lower(record: &StoredRecord) -> String {
    record.path.to_ascii_lowercase()
}

pub fn extension(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i + 1 < name.len() => name[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn in_cloud_sync(path_lower: &str) -> bool {
    path_lower.contains("onedrive")
        || path_lower.contains("dropbox")
        || path_lower.contains("google drive")
        || path_lower.contains("googledrive")
}
