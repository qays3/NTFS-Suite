use std::collections::HashMap;

use rusqlite::Connection;

use crate::detection::rule_engine::{self, Rule};
use crate::detection::scoring::{apply_cloud_downgrade, base_score};
use crate::detection::{anomalies, anti_forensics, in_cloud_sync, is_zeroed, mitre, ntfs_iocs, timestomp, Ctx, Severity};
use crate::util::clock::now_iso8601;
use crate::vault::error::VaultError;
use crate::vault::finding_store::{self, NewFinding};
use crate::vault::record_store::{self, RecordFilter};
use crate::vault::rule_store;

fn parse_severity(value: &str) -> Severity {
    match value {
        "high" => Severity::High,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

const MAX_FINDINGS: usize = 100_000;

pub struct DetectionOptions {
    pub downgrade_cloud: bool,
    pub burst_threshold: u32,
}

impl Default for DetectionOptions {
    fn default() -> Self {
        DetectionOptions {
            downgrade_cloud: true,
            burst_threshold: 200,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DetectionSummary {
    pub findings: usize,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub flagged_files: i64,
    pub truncated: bool,
}

struct Burst {
    count: u32,
    entry: i64,
    path: String,
    name: String,
}

pub fn run(
    conn: &mut Connection,
    evidence_id: i64,
    options: &DetectionOptions,
) -> Result<DetectionSummary, VaultError> {
    let volume_created = record_store::page(conn, evidence_id, 0, 1)
        .ok()
        .and_then(|rows| rows.into_iter().find(|r| r.entry == 0).map(|r| r.si_created))
        .filter(|v| !is_zeroed(v));

    let mut fn_counts: HashMap<String, u32> = HashMap::new();
    record_store::for_each_filtered(conn, evidence_id, &RecordFilter::default(), |r| {
        if !is_zeroed(&r.fn_created) && r.fn_created.len() >= 19 {
            *fn_counts.entry(r.fn_created[..19].to_string()).or_insert(0) += 1;
        }
    })?;
    let bulk_fn_seconds: std::collections::HashSet<String> = fn_counts
        .into_iter()
        .filter(|(_, c)| *c >= 50)
        .map(|(k, _)| k)
        .collect();

    let ioc = crate::vault::ioc_store::lookup(conn).unwrap_or_else(|_| crate::vault::ioc_store::IocLookup {
        names: std::collections::HashSet::new(),
        paths: std::collections::HashSet::new(),
        sizes: std::collections::HashSet::new(),
    });

    let descriptors = crate::vault::security_store::all(conn).unwrap_or_default();
    let secure_present = !descriptors.is_empty();
    let owner_names: std::collections::HashMap<i64, String> = descriptors
        .into_iter()
        .map(|d| {
            let label = if d.owner_name.is_empty() { d.owner_sid } else { d.owner_name };
            (d.security_id, label)
        })
        .collect();

    let ctx = Ctx {
        volume_created,
        now: now_iso8601(),
        downgrade_cloud: options.downgrade_cloud,
        tolerance_seconds: 3,
        bulk_fn_seconds,
        ioc_names: ioc.names,
        ioc_paths: ioc.paths,
        ioc_sizes: ioc.sizes,
        owner_names,
        secure_present,
    };

    let enabled = rule_store::enabled_map(conn).unwrap_or_default();
    let custom: Vec<Rule> = rule_store::list_custom(conn)
        .unwrap_or_default()
        .into_iter()
        .filter(|r| *enabled.get(&r.id).unwrap_or(&true))
        .collect();

    let mut findings: Vec<NewFinding> = Vec::new();
    let mut bursts: HashMap<String, Burst> = HashMap::new();
    let mut truncated = false;

    record_store::for_each_filtered(conn, evidence_id, &RecordFilter::default(), |record| {
        if findings.len() < MAX_FINDINGS {
            let cloud = ctx.downgrade_cloud && in_cloud_sync(&record.path.to_ascii_lowercase());
            let mut hits = timestomp::evaluate(record, &ctx);
            hits.extend(anti_forensics::evaluate(record, &ctx));
            hits.extend(anomalies::evaluate(record, &ctx));
            hits.extend(ntfs_iocs::evaluate(record, &ctx));
            hits.extend(crate::detection::ownership::evaluate(record, &ctx));
            for hit in hits {
                if !*enabled.get(hit.rule_id).unwrap_or(&true) {
                    continue;
                }
                let mut score = base_score(hit.severity);
                if cloud {
                    score = apply_cloud_downgrade(score);
                }
                findings.push(NewFinding {
                    rule_id: hit.rule_id.to_string(),
                    title: hit.title.to_string(),
                    severity: hit.severity.as_str().to_string(),
                    score,
                    mitre: hit.mitre.to_string(),
                    entry: record.entry,
                    path: record.path.clone(),
                    name: record.name.clone(),
                    reason: hit.reason,
                });
            }
            for rule in &custom {
                if findings.len() >= MAX_FINDINGS {
                    break;
                }
                if rule_engine::eval(&rule.condition, record) {
                    let sev = parse_severity(&rule.severity);
                    let mut score = base_score(sev);
                    if cloud {
                        score = apply_cloud_downgrade(score);
                    }
                    let reason = if rule.reason.is_empty() {
                        format!("Matched the custom rule {}.", rule.id)
                    } else {
                        rule.reason.clone()
                    };
                    findings.push(NewFinding {
                        rule_id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: sev.as_str().to_string(),
                        score,
                        mitre: rule.mitre.clone(),
                        entry: record.entry,
                        path: record.path.clone(),
                        name: record.name.clone(),
                        reason,
                    });
                }
            }
        } else {
            truncated = true;
        }

        if !is_zeroed(&record.si_created) && record.si_created.len() >= 19 {
            let bucket = record.si_created[..19].to_string();
            let entry = bursts.entry(bucket).or_insert(Burst {
                count: 0,
                entry: record.entry,
                path: record.path.clone(),
                name: record.name.clone(),
            });
            entry.count += 1;
            if record.entry < entry.entry {
                entry.entry = record.entry;
                entry.path = record.path.clone();
                entry.name = record.name.clone();
            }
        }
    })?;

    for (bucket, burst) in bursts.iter() {
        if burst.count >= options.burst_threshold && findings.len() < MAX_FINDINGS {
            findings.push(NewFinding {
                rule_id: String::from("MFT-AN-04"),
                title: String::from("Creation burst"),
                severity: Severity::Low.as_str().to_string(),
                score: base_score(Severity::Low),
                mitre: mitre::MASQUERADING.to_string(),
                entry: burst.entry,
                path: burst.path.clone(),
                name: burst.name.clone(),
                reason: format!(
                    "{} files share the creation second {}. A large burst can mark an install, an unpack or staged files.",
                    burst.count, bucket
                ),
            });
        }
    }

    let combos: &[(&str, &str, &str, &[&str])] = &[
        ("MFT-C1", "Timestomped file, high confidence", mitre::TIMESTOMP, &["MFT-TS-01", "MFT-TS-02"]),
        ("MFT-C2", "Masqueraded and hidden binary", mitre::MASQUERADING, &["MFT-AN-06", "MFT-AN-12"]),
        ("MFT-C3", "Masqueraded and timestomped", mitre::MASQUERADING, &["MFT-AN-06", "MFT-TS-02"]),
    ];
    let mut by_entry: HashMap<i64, (std::collections::HashSet<String>, String, String)> = HashMap::new();
    for f in &findings {
        let bucket = by_entry
            .entry(f.entry)
            .or_insert_with(|| (std::collections::HashSet::new(), f.path.clone(), f.name.clone()));
        bucket.0.insert(f.rule_id.clone());
    }
    let mut combo_findings: Vec<NewFinding> = Vec::new();
    for (entry, (rules, path, name)) in by_entry.iter() {
        for (id, title, mt, required) in combos {
            if required.iter().all(|r| rules.contains(*r)) {
                combo_findings.push(NewFinding {
                    rule_id: id.to_string(),
                    title: title.to_string(),
                    severity: Severity::High.as_str().to_string(),
                    score: base_score(Severity::High),
                    mitre: mt.to_string(),
                    entry: *entry,
                    path: path.clone(),
                    name: name.clone(),
                    reason: format!(
                        "This file matched several checks at once ({}), which together are strong evidence rather than one weak signal.",
                        required.join(" plus ")
                    ),
                });
            }
        }
    }
    for cf in combo_findings {
        if findings.len() < MAX_FINDINGS {
            findings.push(cf);
        }
    }

    finding_store::clear(conn, evidence_id)?;
    let created = now_iso8601();
    finding_store::insert_many(conn, evidence_id, &created, &findings)?;
    let stats = finding_store::stats(conn, evidence_id)?;

    Ok(DetectionSummary {
        findings: findings.len(),
        high: stats.high,
        medium: stats.medium,
        low: stats.low,
        flagged_files: stats.flagged_files,
        truncated,
    })
}
