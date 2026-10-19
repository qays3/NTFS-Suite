use crate::detection::{extension, mitre, path_lower, Ctx, RuleHit, Severity};
use crate::vault::record_store::StoredRecord;

pub fn evaluate(record: &StoredRecord, _ctx: &Ctx) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    let lower = path_lower(record);
    let name_lower = record.name.to_ascii_lowercase();

    if record.has_ads {
        let in_downloads = lower.contains("\\downloads\\");
        let severity = if in_downloads {
            Severity::Low
        } else {
            Severity::Medium
        };
        hits.push(RuleHit {
            rule_id: "MFT-AF-01",
            title: "Alternate data stream present",
            severity,
            mitre: mitre::NTFS_FILE_ATTRIBUTES,
            reason: format!(
                "The record carries an alternate data stream. Streams hide data behind a normal file name. Path {}.",
                record.path
            ),
        });
    }

    if record.orphan {
        hits.push(RuleHit {
            rule_id: "MFT-AF-03",
            title: "Orphan record",
            severity: Severity::Low,
            mitre: mitre::FILE_DELETION,
            reason: String::from(
                "The parent folder record is gone or its sequence does not match, so the full path cannot be trusted. Orphans often follow deletion and record reuse.",
            ),
        });
    }

    if let Some(reason) = wiper_trace(&lower, &name_lower, &extension(&name_lower)) {
        hits.push(RuleHit {
            rule_id: "MFT-AF-04",
            title: "Known wiper trace",
            severity: Severity::High,
            mitre: mitre::INDICATOR_REMOVAL,
            reason,
        });
    }

    hits
}

fn wiper_trace(lower: &str, name_lower: &str, ext: &str) -> Option<String> {
    if lower.contains("efstmpwp") {
        return Some(String::from(
            "The path holds the EFSTMPWP folder left by cipher.exe /w while wiping free space.",
        ));
    }
    if name_lower.starts_with("fil") && ext == "tmp" && name_lower.len() <= 12 {
        return Some(format!(
            "The name {} matches the fil*.tmp pattern cipher.exe /w writes while overwriting free space.",
            name_lower
        ));
    }
    if name_lower == "~bcwipe.tmp"
        || name_lower == "bcw-dir-nodes"
        || name_lower == "swp_insbcb.tmp"
        || name_lower.starts_with("logfilewiper")
    {
        return Some(format!(
            "The name {} is a BCWipe secure deletion artifact.",
            name_lower
        ));
    }
    if is_repeated_letter(name_lower) {
        return Some(format!(
            "The name {} is one repeated letter, the pattern SDelete leaves while renaming a file before deletion.",
            name_lower
        ));
    }
    None
}

fn is_repeated_letter(name_lower: &str) -> bool {
    let compact: String = name_lower.chars().filter(|c| *c != '.').collect();
    if compact.len() < 3 {
        return false;
    }
    let mut chars = compact.chars();
    let first = match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => c,
        _ => return false,
    };
    compact.chars().all(|c| c == first)
}
