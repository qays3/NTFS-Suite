use ntfs_suite::detection::{self, DetectionOptions};
use ntfs_suite::vault::finding_store::{self, FindingFilter};
use ntfs_suite::vault::record_store::{self, StoredRecord};
use ntfs_suite::vault::Vault;

fn record(entry: i64, name: &str, path: &str, si_created: &str, si_modified: &str, fn_created: &str) -> StoredRecord {
    StoredRecord {
        entry,
        sequence: 1,
        in_use: true,
        is_directory: false,
        has_ads: false,
        orphan: false,
        parent_entry: 5,
        si_created: si_created.to_string(),
        si_modified: si_modified.to_string(),
        si_mft_modified: si_modified.to_string(),
        si_accessed: si_modified.to_string(),
        fn_created: fn_created.to_string(),
        name: name.to_string(),
        path: path.to_string(),
        ..Default::default()
    }
}

fn rules_for(conn: &rusqlite::Connection, entry: i64) -> Vec<String> {
    let filter = FindingFilter::default();
    finding_store::list(conn, 1, &filter, 0, 1000)
        .unwrap()
        .into_iter()
        .filter(|f| f.entry == entry)
        .map(|f| f.rule_id)
        .collect()
}

#[test]
fn flags_si_only_timestomp() {
    let mut vault = Vault::open_in_memory().unwrap();
    let rows = vec![
        record(0, "$MFT", "\\$MFT", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z"),
        record(80, "clean.txt", "\\Users\\a\\clean.txt", "2026-01-01T10:00:00.1234567Z", "2026-01-01T11:00:00.1234567Z", "2026-01-01T10:00:00.1234567Z"),
        record(81, "evil.exe", "\\Users\\a\\evil.exe", "2020-01-01T00:00:00.0000000Z", "2020-01-01T00:00:00.0000000Z", "2026-01-01T10:00:00.1234567Z"),
    ];
    record_store::insert_many(&mut vault.conn, 1, &rows).unwrap();

    let summary = detection::run(&mut vault.conn, 1, &DetectionOptions::default()).unwrap();
    assert!(summary.findings >= 2);

    let evil = rules_for(&vault.conn, 81);
    assert!(evil.iter().any(|r| r == "MFT-TS-01"), "expected SI<FN, got {:?}", evil);
    assert!(evil.iter().any(|r| r == "MFT-TS-02"), "expected zero subsecond, got {:?}", evil);

    let clean = rules_for(&vault.conn, 80);
    assert!(clean.is_empty(), "clean file should not be flagged, got {:?}", clean);
}

#[test]
fn flags_copied_in_file() {
    let mut vault = Vault::open_in_memory().unwrap();
    let rows = vec![
        record(0, "$MFT", "\\$MFT", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z"),
        record(90, "copied.doc", "\\Users\\a\\copied.doc", "2026-05-01T09:00:00.5000000Z", "2024-01-01T08:00:00.5000000Z", "2026-05-01T09:00:00.5000000Z"),
    ];
    record_store::insert_many(&mut vault.conn, 1, &rows).unwrap();
    detection::run(&mut vault.conn, 1, &DetectionOptions::default()).unwrap();
    let hits = rules_for(&vault.conn, 90);
    assert!(hits.iter().any(|r| r == "MFT-AN-03"), "expected copied in, got {:?}", hits);
}

#[test]
fn cloud_sync_downgraded() {
    let mut vault = Vault::open_in_memory().unwrap();
    let rows = vec![
        record(0, "$MFT", "\\$MFT", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z"),
        record(70, "evil.exe", "\\Users\\a\\OneDrive\\evil.exe", "2020-01-01T00:00:00.0000000Z", "2020-01-01T00:00:00.0000000Z", "2026-01-01T10:00:00.1234567Z"),
        record(71, "evil.exe", "\\Users\\a\\Desktop\\evil.exe", "2020-01-01T00:00:00.0000000Z", "2020-01-01T00:00:00.0000000Z", "2026-01-01T10:00:00.1234567Z"),
    ];
    record_store::insert_many(&mut vault.conn, 1, &rows).unwrap();
    detection::run(&mut vault.conn, 1, &DetectionOptions { downgrade_cloud: true, burst_threshold: 200 }).unwrap();

    let filter = FindingFilter::default();
    let all = finding_store::list(&vault.conn, 1, &filter, 0, 1000).unwrap();
    let cloud_score: i64 = all.iter().filter(|f| f.entry == 70 && f.rule_id == "MFT-TS-01").map(|f| f.score).sum();
    let normal_score: i64 = all.iter().filter(|f| f.entry == 71 && f.rule_id == "MFT-TS-01").map(|f| f.score).sum();
    assert!(cloud_score < normal_score, "cloud {} should be below normal {}", cloud_score, normal_score);
}

#[test]
fn flags_system_binary_owned_by_user() {
    use ntfs_suite::vault::security_store::{self, SecurityDescriptor};

    let mut vault = Vault::open_in_memory().unwrap();
    let mut planted = record(
        90,
        "svchost.exe",
        "\\Windows\\System32\\svchost.exe",
        "2026-01-01T10:00:00.1234567Z",
        "2026-01-01T10:00:00.1234567Z",
        "2026-01-01T10:00:00.1234567Z",
    );
    planted.security_id = 300;
    let mut legit = record(
        91,
        "kernel32.dll",
        "\\Windows\\System32\\kernel32.dll",
        "2026-01-01T10:00:00.1234567Z",
        "2026-01-01T10:00:00.1234567Z",
        "2026-01-01T10:00:00.1234567Z",
    );
    legit.security_id = 301;
    let mft = record(0, "$MFT", "\\$MFT", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z", "2019-01-01T00:00:00.1234500Z");
    record_store::insert_many(&mut vault.conn, 1, &[mft, planted, legit]).unwrap();

    let descs = vec![
        SecurityDescriptor { security_id: 300, owner_name: "Account (RID 1001)".to_string(), ..Default::default() },
        SecurityDescriptor { security_id: 301, owner_name: "SYSTEM".to_string(), ..Default::default() },
    ];
    security_store::insert_many(&mut vault.conn, 1, &descs).unwrap();

    detection::run(&mut vault.conn, 1, &DetectionOptions::default()).unwrap();

    assert!(rules_for(&vault.conn, 90).contains(&"MFT-OWN-01".to_string()));
    assert!(!rules_for(&vault.conn, 91).contains(&"MFT-OWN-01".to_string()));
}
