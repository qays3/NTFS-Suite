use crate::detection::{mitre, Ctx, RuleHit, Severity};
use crate::vault::record_store::StoredRecord;

const SYSTEM_OWNERS: &[&str] = &["SYSTEM", "TrustedInstaller", "Administrators"];

fn is_executable(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys")
}

fn in_system_path(path: &str) -> bool {
    let p = path.to_lowercase().replace('/', "\\");
    p.contains("\\windows\\system32") || p.contains("\\windows\\syswow64") || p.contains("\\program files")
}

// MFT-OWN-01: a system-area executable owned by a non-system account. Needs the
// security id resolved through $Secure, so it only fires when a $Secure is present.
pub fn evaluate(record: &StoredRecord, ctx: &Ctx) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    if !ctx.secure_present || record.is_directory {
        return hits;
    }
    if !is_executable(&record.name) || !in_system_path(&record.path) {
        return hits;
    }
    let owner = match ctx.owner_names.get(&record.security_id) {
        Some(o) if !o.is_empty() => o,
        _ => return hits,
    };
    if SYSTEM_OWNERS.iter().any(|s| owner.eq_ignore_ascii_case(s)) {
        return hits;
    }
    hits.push(RuleHit {
        rule_id: "MFT-OWN-01",
        title: "System binary owned by a non-system account",
        severity: Severity::High,
        mitre: mitre::PERMISSION_MOD,
        reason: format!(
            "{} sits in a protected system folder but is owned by {}, not SYSTEM, TrustedInstaller or Administrators. A user-owned file in a system path can mean a planted or replaced binary.",
            record.name, owner
        ),
    });
    hits
}
