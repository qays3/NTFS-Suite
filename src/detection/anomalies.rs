use crate::detection::{extension, is_zeroed, known_locations, mitre, path_lower, Ctx, RuleHit, Severity};
use crate::vault::record_store::StoredRecord;

const EXECUTABLE: &[&str] = &["exe", "dll", "sys", "pyd", "ps1", "vbs", "bat", "scr", "com", "cmd"];
const ARCHIVE: &[&str] = &["rar", "zip", "7z", "cab", "iso"];
const MASQUERADE_NAMES: &[&str] = &[
    "svch0st.exe",
    "scvhost.exe",
    "svchosts.exe",
    "lsass .exe",
    "lsasss.exe",
    "csrsss.exe",
    "taskhost.exe",
];

pub fn evaluate(record: &StoredRecord, _ctx: &Ctx) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    if record.is_directory {
        return hits;
    }
    let lower = path_lower(record);
    let name_lower = record.name.to_ascii_lowercase();
    let ext = extension(&name_lower);

    if !is_zeroed(&record.si_modified)
        && !is_zeroed(&record.si_created)
        && record.si_modified < record.si_created
    {
        hits.push(RuleHit {
            rule_id: "MFT-AN-03",
            title: "Modified time older than creation time",
            severity: Severity::Medium,
            mitre: mitre::LATERAL_TOOL_TRANSFER,
            reason: format!(
                "Content modified {} is older than creation {}. The file was copied in from another volume or over the network, so the creation time is the copy time.",
                record.si_modified, record.si_created
            ),
        });
    }

    let suspicious_dir = in_suspicious_dir(&lower);
    if EXECUTABLE.contains(&ext.as_str()) && suspicious_dir {
        hits.push(RuleHit {
            rule_id: "MFT-AN-01",
            title: "Executable in an unusual location",
            severity: Severity::Medium,
            mitre: mitre::MASQUERADING,
            reason: format!(
                "An executable or script sits at {}. Code does not normally run from temporary, recycle or drive root folders.",
                record.path
            ),
        });
    }

    if ARCHIVE.contains(&ext.as_str()) && suspicious_dir {
        hits.push(RuleHit {
            rule_id: "MFT-AN-02",
            title: "Archive in an unusual location",
            severity: Severity::Low,
            mitre: mitre::MASQUERADING,
            reason: format!(
                "An archive sits at {}. Archives in temporary or root folders can be staging for collection or exfiltration.",
                record.path
            ),
        });
    }

    if MASQUERADE_NAMES.contains(&name_lower.as_str()) {
        hits.push(RuleHit {
            rule_id: "MFT-AN-05",
            title: "Look alike system name",
            severity: Severity::High,
            mitre: mitre::MASQUERADING,
            reason: format!(
                "The name {} imitates a Windows system process. The real name is spelled differently or does not exist on modern Windows.",
                name_lower
            ),
        });
    }

    if let Some(reason) = known_locations::masquerade_reason(&name_lower, &lower) {
        hits.push(RuleHit {
            rule_id: "MFT-AN-06",
            title: "Known file from an unknown path",
            severity: Severity::High,
            mitre: mitre::MASQUERADING,
            reason,
        });
    }

    hits
}

fn in_suspicious_dir(lower: &str) -> bool {
    lower.contains("\\temp\\")
        || lower.contains("\\$recycle.bin\\")
        || lower.contains("\\windows\\temp\\")
        || is_drive_root(lower)
}

fn is_drive_root(lower: &str) -> bool {
    lower.starts_with('\\') && lower.matches('\\').count() == 1 && lower.contains('.')
}
