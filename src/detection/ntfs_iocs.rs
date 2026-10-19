use crate::detection::{extension, mitre, path_lower, Ctx, RuleHit, Severity};
use crate::vault::record_store::StoredRecord;

const EXE_EXT: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "pif", "msi",
];
const DOC_EXT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif",
];

const FLAG_HIDDEN: i64 = 0x2;
const FLAG_SYSTEM: i64 = 0x4;
const TAG_MOUNT_POINT: i64 = 0xA000_0003;
const TAG_SYMLINK: i64 = 0xA000_000C;

fn user_writable(lower: &str) -> bool {
    lower.contains("\\users\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\programdata\\")
        || lower.contains("\\public\\")
        || lower.contains("\\downloads\\")
}

fn system_path(lower: &str) -> bool {
    lower.contains("\\windows\\") || lower.contains("\\program files")
}

pub fn evaluate(record: &StoredRecord, ctx: &Ctx) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    let name = &record.name;
    let name_lower = name.to_ascii_lowercase();
    let lower = path_lower(record);
    let ext = extension(&name_lower);

    if ctx.ioc_names.contains(&name_lower) || ctx.ioc_paths.contains(&lower) {
        hits.push(RuleHit {
            rule_id: "MFT-IOC-01",
            title: "Matches the imported IOC list",
            severity: Severity::Medium,
            mitre: mitre::MASQUERADE_NAME,
            reason: format!(
                "The name or path {} equals an entry in the IOC list imported for this case.",
                record.path
            ),
        });
    } else if record.real_size > 0 && ctx.ioc_sizes.contains(&record.real_size) {
        hits.push(RuleHit {
            rule_id: "MFT-IOC-01",
            title: "Size matches an IOC entry",
            severity: Severity::Low,
            mitre: mitre::MASQUERADE_NAME,
            reason: format!(
                "The real size {} matches an IOC list entry. A size match alone is only a prompt to check the hash, not proof.",
                record.real_size
            ),
        });
    }

    if name.contains('\u{202E}') || name.contains('\u{202D}') || name.contains('\u{2066}') {
        hits.push(RuleHit {
            rule_id: "MFT-AN-07",
            title: "Right to left override in the name",
            severity: Severity::High,
            mitre: mitre::MASQUERADING,
            reason: format!(
                "The name {} carries a right to left override character, which hides the real extension by flipping the text that follows it.",
                name
            ),
        });
    }

    if !record.is_directory && (name.ends_with(' ') || name.ends_with('.')) {
        hits.push(RuleHit {
            rule_id: "MFT-AN-07",
            title: "Trailing dot or space in the name",
            severity: Severity::Medium,
            mitre: mitre::MASQUERADE_NAME,
            reason: format!(
                "The name {} ends with a dot or a space, a trick that makes a file look like a different type.",
                name
            ),
        });
    }

    {
        let parts: Vec<&str> = name_lower.rsplitn(3, '.').collect();
        if parts.len() == 3 && EXE_EXT.contains(&parts[0]) && DOC_EXT.contains(&parts[1]) {
            hits.push(RuleHit {
                rule_id: "MFT-AN-07",
                title: "Double extension",
                severity: Severity::Medium,
                mitre: mitre::MASQUERADING,
                reason: format!(
                    "The name {} reads like a document but really ends in an executable extension.",
                    name
                ),
            });
        }
    }

    if !record.short_name.is_empty() && eight_three_mismatch(&record.name, &record.short_name) {
        hits.push(RuleHit {
            rule_id: "MFT-AN-08",
            title: "Short name does not match the long name",
            severity: Severity::Low,
            mitre: mitre::MASQUERADE_NAME,
            reason: format!(
                "The 8.3 short name {} does not derive from the long name {}, so the short name is left over from an earlier name on the same record.",
                record.short_name, record.name
            ),
        });
    }

    if record.resident_exe {
        hits.push(RuleHit {
            rule_id: "MFT-AN-10",
            title: "Executable content resident in the MFT",
            severity: Severity::Medium,
            mitre: mitre::NTFS_FILE_ATTRIBUTES,
            reason: String::from(
                "A data stream held inside the MFT record starts with the MZ header of a Windows executable. Code hidden in resident data needs no file on disk.",
            ),
        });
    }

    if record.in_use && record.sequence > 1 {
        hits.push(RuleHit {
            rule_id: "MFT-AN-11",
            title: "MFT slot reused",
            severity: Severity::Low,
            mitre: mitre::FILE_DELETION,
            reason: format!(
                "This in use record has sequence number {}, so the slot held one or more earlier files that were deleted and the slot reused.",
                record.sequence
            ),
        });
    }

    if !record.is_directory
        && EXE_EXT.contains(&ext.as_str())
        && record.si_flags & FLAG_HIDDEN != 0
        && record.si_flags & FLAG_SYSTEM != 0
        && user_writable(&lower)
    {
        hits.push(RuleHit {
            rule_id: "MFT-AN-12",
            title: "Hidden and system executable",
            severity: Severity::Medium,
            mitre: mitre::HIDDEN_FILE,
            reason: format!(
                "The executable {} has both the hidden and system attributes set in a user writable folder, which legitimate software rarely does.",
                record.path
            ),
        });
    }

    if record.reparse_tag == TAG_MOUNT_POINT || record.reparse_tag == TAG_SYMLINK {
        let target_lower = record.reparse_target.to_ascii_lowercase();
        let risky = user_writable(&lower) && system_path(&target_lower);
        if risky {
            hits.push(RuleHit {
                rule_id: "MFT-RP-01",
                title: "Risky reparse point",
                severity: Severity::Medium,
                mitre: mitre::HIJACK_EXECUTION,
                reason: format!(
                    "A link in a user writable folder points into a system path ({}). A planted junction or symlink can redirect a trusted path to attacker content.",
                    record.reparse_target
                ),
            });
        }
    }

    hits
}

fn eight_three_mismatch(long: &str, short: &str) -> bool {
    let short_u = short.to_ascii_uppercase();
    if let Some(tilde) = short_u.find('~') {
        let base = &short_u[..tilde];
        if base.is_empty() {
            return false;
        }
        let long_alnum: String = long
            .to_ascii_uppercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        return !long_alnum.starts_with(base);
    }
    false
}
