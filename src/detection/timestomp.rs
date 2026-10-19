use crate::detection::{
    all_zero_subseconds, extension, human_gap, is_zeroed, iso_epoch_seconds, mitre, path_lower, Ctx,
    RuleHit, Severity,
};
use crate::vault::record_store::StoredRecord;

fn is_install_location(lower: &str) -> bool {
    lower.contains("\\windows\\winsxs\\")
        || lower.contains("\\windows\\servicing\\")
        || lower.contains("\\windows\\installer\\")
        || lower.contains("\\windows\\softwaredistribution\\")
        || lower.contains("\\program files\\")
        || lower.contains("\\program files (x86)\\")
        || lower.contains("\\programdata\\microsoft\\windows defender\\")
        || lower.contains("\\$recycle.bin\\")
}

fn risky_exec(name_lower: &str, lower: &str) -> bool {
    let ext = extension(name_lower);
    matches!(ext.as_str(), "exe" | "dll" | "ps1" | "bat")
        && (lower.contains("\\temp\\")
            || lower.contains("\\appdata\\")
            || lower.contains("\\public\\")
            || lower.contains("\\programdata\\"))
}

pub fn evaluate(record: &StoredRecord, ctx: &Ctx) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    let si = &record.si_created;
    let fnc = &record.fn_created;
    let si_zero = is_zeroed(si);
    let fn_zero = is_zeroed(fnc);
    let lower = path_lower(record);
    let install = is_install_location(&lower);
    let si_zero_sub = !si_zero && !fn_zero && all_zero_subseconds(si) && !all_zero_subseconds(fnc);

    let name_lower = record.name.to_ascii_lowercase();
    if let (Some(si_e), Some(fn_e)) = (iso_epoch_seconds(si), iso_epoch_seconds(fnc)) {
        let tol = ctx.tolerance_seconds;
        if fn_e - si_e > tol {
            let fn_sec = &fnc[..19.min(fnc.len())];
            let bulk = ctx.bulk_fn_seconds.contains(fn_sec);
            let suppressed = (install || bulk) && !si_zero_sub;
            if !suppressed {
                let gap = fn_e - si_e;
                let volume_before = ctx
                    .volume_created
                    .as_deref()
                    .map(|v| si.as_str() < v)
                    .unwrap_or(false);
                let future = si.as_str() > ctx.now.as_str();
                let risky = risky_exec(&name_lower, &lower);
                let corroborated = si_zero_sub || volume_before || future || risky;
                hits.push(RuleHit {
                    rule_id: "MFT-TS-01",
                    title: "Standard Information created before File Name created",
                    severity: if corroborated { Severity::High } else { Severity::Medium },
                    mitre: mitre::TIMESTOMP,
                    reason: format!(
                        "Standard Information creation {} is {} earlier than File Name creation {}. A tool changed the visible creation time but could not change the File Name copy.",
                        si, human_gap(gap), fnc
                    ),
                });
            }
        } else if si_e - fn_e > tol && !install {
            hits.push(RuleHit {
                rule_id: "MFT-TS-07",
                title: "File Name created before Standard Information created",
                severity: Severity::Low,
                mitre: mitre::TIMESTOMP,
                reason: format!(
                    "File Name creation {} is {} earlier than Standard Information creation {}, the FN<SI direction. The File Name copy is normally set at creation, so this gap means a creation time was changed.",
                    fnc, human_gap(si_e - fn_e), si
                ),
            });
        }
    }

    if !si_zero && !fn_zero && all_zero_subseconds(si) && !all_zero_subseconds(fnc) {
        hits.push(RuleHit {
            rule_id: "MFT-TS-02",
            title: "Standard Information sub seconds all zero",
            severity: Severity::High,
            mitre: mitre::TIMESTOMP,
            reason: format!(
                "Standard Information creation {} has all seven sub second digits zero while File Name creation {} keeps full precision. Timestomping tools write whole seconds.",
                si, fnc
            ),
        });
    }

    if let Some(volume) = ctx.volume_created.as_deref() {
        if !si_zero && si.as_str() < volume {
            hits.push(RuleHit {
                rule_id: "MFT-TS-03",
                title: "Standard Information created before the volume",
                severity: Severity::Medium,
                mitre: mitre::TIMESTOMP,
                reason: format!(
                    "Standard Information creation {} is earlier than the volume creation {}. A file cannot predate the file system it lives on.",
                    si, volume
                ),
            });
        }
    }

    if record.in_use && si_zero {
        hits.push(RuleHit {
            rule_id: "MFT-TS-05",
            title: "Standard Information creation zeroed to 1601",
            severity: Severity::Medium,
            mitre: mitre::TIMESTOMP,
            reason: String::from(
                "Standard Information creation is set to 1601-01-01, the zero value. Wipers such as Eraser leave this trace.",
            ),
        });
    }

    if !si_zero && si.as_str() > ctx.now.as_str() {
        hits.push(RuleHit {
            rule_id: "MFT-TS-06",
            title: "Standard Information creation in the future",
            severity: Severity::Medium,
            mitre: mitre::TIMESTOMP,
            reason: format!(
                "Standard Information creation {} is later than the analysis time {}. The time was set forward.",
                si, ctx.now
            ),
        });
    }

    hits
}
